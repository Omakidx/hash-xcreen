//! QUIC backend: streams, datagrams and priorities per protocol §3.

use std::{sync::Arc, sync::atomic::Ordering, time::Duration};

use bytes::Bytes;
use hx_proto::{
    channel::{
        ChannelId, CloseCode, MAX_CONTROL_MESSAGE, MAX_CURSOR_MESSAGE, MAX_INPUT_MESSAGE,
        MAX_TRANSFER_HEADER, RESET_STALE_FRAME, STOP_TRANSFER_REJECTED, priority,
    },
    datagram::{Datagram, decode_datagram},
    media::{MEDIA_HEADER_LEN, MediaHeader},
    message::{self, parse_frame_len},
    pb::{ControlMessage, CursorEvent, InputEvent, TransferHeader},
    version::Features,
};
use quinn::{ConnectionError, RecvStream, SendStream, VarInt, congestion::BbrConfig};
use tokio::sync::mpsc::error::TrySendError;

use crate::{
    ack::AckOutcome,
    conn::{Backend, Connection, Inner, Role, VideoFrame, VideoJob},
    error::{CloseInfo, Error, Result, transport},
    transfer::{IncomingBody, IncomingTransfer, SenderBody, TransferKind, TransferSender},
};

/// How long a freshly accepted unidirectional stream may take to send its channel byte.
const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Receive window of a server connection before authorization (protocol §1).
const PREAUTH_RECEIVE_WINDOW: u32 = 256 * 1024;
/// Steady-state connection receive window cap (both sides).
const STEADY_RECEIVE_WINDOW: u32 = 64 * 1024 * 1024;
/// Unidirectional streams a client may open after authorization (input + transfers).
const AUTHORIZED_CLIENT_UNI_STREAMS: u32 = 64;

/// QUIC transport parameters for one side (protocol §1).
///
/// A server starts **restricted**: one bidirectional stream (control), no unidirectional
/// streams, a small connection receive window and datagram buffer, so a peer that never
/// authenticates cannot make it buffer anything significant. `lift_restrictions` raises the
/// limits once the application authorizes the connection.
pub(crate) fn transport_config(role: Role) -> Result<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    // Streams the *peer* may open towards us.
    match role {
        Role::Server => {
            t.max_concurrent_bidi_streams(1u32.into());
            t.max_concurrent_uni_streams(0u32.into());
            t.receive_window(PREAUTH_RECEIVE_WINDOW.into());
            // Only 14-byte mouse datagrams are ever expected.
            t.datagram_receive_buffer_size(Some(16 * 1024));
        }
        Role::Client => {
            // Server opens: cursor stream, one stream per video frame, transfers.
            t.max_concurrent_bidi_streams(0u32.into());
            t.max_concurrent_uni_streams(1024u32.into());
            // A malicious server (before any pinning) cannot make the client buffer more.
            t.receive_window(STEADY_RECEIVE_WINDOW.into());
            t.stream_receive_window((8u32 * 1024 * 1024).into());
            t.datagram_receive_buffer_size(Some(256 * 1024));
        }
    }
    t.keep_alive_interval(Some(Duration::from_secs(5)));
    t.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .map_err(|e| Error::Config(format!("{e}")))?,
    ));
    t.congestion_controller_factory(Arc::new(BbrConfig::default()));
    Ok(t)
}

pub(crate) struct QuicBackend {
    pub conn: quinn::Connection,
    control: tokio::sync::Mutex<SendStream>,
    /// Client: the input stream (opened on first use, which waits for authorization).
    /// Server: the cursor stream.
    uni: tokio::sync::Mutex<Option<SendStream>>,
    /// Client endpoints must outlive their connection.
    endpoint: Option<quinn::Endpoint>,
}

/// The certificate chain the peer presented. An identity of an unexpected type is an error,
/// never a silent `None` (which would read as "no client certificate").
pub(crate) fn peer_certs(
    conn: &quinn::Connection,
) -> Result<Option<Vec<rustls::pki_types::CertificateDer<'static>>>> {
    match conn.peer_identity() {
        None => Ok(None),
        Some(id) => id
            .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
            .map(|b| Some(*b))
            .map_err(|_| Error::Tls("peer identity has an unexpected type".into())),
    }
}

// ---------------------------------------------------------------- stream I/O helpers

fn quic_code(code: CloseCode) -> VarInt {
    VarInt::from_u32(code.code())
}

pub(crate) async fn write_message(s: &mut SendStream, body: &Bytes) -> Result<()> {
    s.write_all(&(body.len() as u32).to_le_bytes())
        .await
        .map_err(transport)?;
    s.write_all(body).await.map_err(transport)
}

/// Read one length-prefixed frame. `Ok(None)` is a clean end of stream between frames.
pub(crate) async fn read_message(rs: &mut RecvStream, max: usize) -> Result<Option<Vec<u8>>> {
    let mut first = [0u8; 1];
    if rs.read(&mut first).await.map_err(transport)?.is_none() {
        return Ok(None);
    }
    let mut prefix = [first[0], 0, 0, 0];
    read_exact(rs, &mut prefix[1..]).await?;
    let len = parse_frame_len(prefix, max)?;
    let mut body = vec![0u8; len];
    read_exact(rs, &mut body).await?;
    Ok(Some(body))
}

async fn read_exact(rs: &mut RecvStream, buf: &mut [u8]) -> Result<()> {
    rs.read_exact(buf).await.map_err(|e| match e {
        quinn::ReadExactError::FinishedEarly(_) => {
            Error::Violation("stream ended inside a frame".into())
        }
        quinn::ReadExactError::ReadError(e) => transport(e),
    })
}

pub(crate) fn close_info_from_error(e: &ConnectionError) -> CloseInfo {
    match e {
        ConnectionError::ApplicationClosed(ac) => CloseInfo {
            code: CloseCode::from_code(ac.error_code.into_inner()),
            reason: String::from_utf8_lossy(&ac.reason)
                .chars()
                .take(120)
                .collect(),
            by_peer: true,
        },
        ConnectionError::LocallyClosed => CloseInfo {
            code: CloseCode::NoError,
            reason: "closed locally".into(),
            by_peer: false,
        },
        ConnectionError::TimedOut => CloseInfo {
            code: CloseCode::InternalError,
            reason: "idle timeout".into(),
            by_peer: true,
        },
        other => CloseInfo {
            code: CloseCode::InternalError,
            reason: other.to_string(),
            by_peer: true,
        },
    }
}

// ---------------------------------------------------------------- backend

impl QuicBackend {
    pub(crate) fn new(
        conn: quinn::Connection,
        control: SendStream,
        uni: Option<SendStream>,
        endpoint: Option<quinn::Endpoint>,
    ) -> Self {
        Self {
            conn,
            control: tokio::sync::Mutex::new(control),
            uni: tokio::sync::Mutex::new(uni),
            endpoint,
        }
    }

    pub(crate) fn rtt(&self) -> Duration {
        self.conn.rtt()
    }

    pub(crate) fn close(&self, code: CloseCode, reason: &str) {
        self.conn.close(quic_code(code), reason.as_bytes());
    }

    pub(crate) async fn flush_close(&self) {
        if let Some(ep) = &self.endpoint {
            let _ = tokio::time::timeout(Duration::from_secs(1), ep.wait_idle()).await;
        }
    }

    /// Raise the limits that were kept minimal until the application authorized the peer.
    pub(crate) fn lift_restrictions(&self) {
        self.conn
            .set_max_concurrent_uni_streams(AUTHORIZED_CLIENT_UNI_STREAMS.into());
        self.conn.set_receive_window(STEADY_RECEIVE_WINDOW.into());
    }

    pub(crate) async fn send_reliable(&self, ch: ChannelId, body: Bytes) -> Result<()> {
        if ch == ChannelId::Control {
            let mut s = self.control.lock().await;
            return write_message(&mut s, &body).await;
        }
        if !matches!(ch, ChannelId::Input | ChannelId::Cursor) {
            return Err(Error::Violation("not a message channel".into()));
        }
        let mut guard = self.uni.lock().await;
        if guard.is_none() {
            // The peer only grants unidirectional streams once it has authorized us, so
            // this waits for that.
            let mut s = self.conn.open_uni().await.map_err(transport)?;
            let _ = s.set_priority(if ch == ChannelId::Input {
                priority::INPUT
            } else {
                priority::CURSOR
            });
            s.write_all(&[ch as u8]).await.map_err(transport)?;
            *guard = Some(s);
        }
        match guard.as_mut() {
            Some(s) => write_message(s, &body).await,
            None => Err(Error::ChannelClosed),
        }
    }

    pub(crate) fn send_datagram(&self, dg: Bytes) -> Result<()> {
        let max = self
            .conn
            .max_datagram_size()
            .ok_or_else(|| Error::Transport("peer disabled datagrams".into()))?;
        if dg.len() > max {
            return Err(Error::DatagramTooLarge { len: dg.len(), max });
        }
        self.conn.send_datagram(dg).map_err(transport)
    }

    /// Open the frame's stream (waiting for stream credit applies backpressure), then write it
    /// on a task so the caller is not held up; completion of the stream is the ack.
    pub(crate) async fn send_video(&self, inner: Arc<Inner>, job: VideoJob) -> Result<()> {
        let mut s = self.conn.open_uni().await.map_err(transport)?;
        let _ = s.set_priority(priority::VIDEO);
        tokio::spawn(async move {
            let outcome = {
                let write = write_frame(&mut s, &job);
                tokio::select! {
                    biased;
                    () = job.cancel.cancelled() => None,
                    r = write => Some(r),
                }
            };
            let outcome = match outcome {
                None => {
                    let _ = s.reset(RESET_STALE_FRAME.into());
                    AckOutcome::Cancelled
                }
                Some(Ok(None)) => AckOutcome::Delivered,
                Some(Ok(Some(code))) => AckOutcome::Rejected(code),
                Some(Err(_)) => AckOutcome::ConnectionLost,
            };
            job.finish(&inner, outcome);
        });
        Ok(())
    }

    pub(crate) async fn open_transfer(
        &self,
        kind: TransferKind,
        header: TransferHeader,
    ) -> Result<TransferSender> {
        let mut s = self.conn.open_uni().await.map_err(transport)?;
        let _ = s.set_priority(priority::TRANSFER);
        s.write_all(&[kind.channel() as u8])
            .await
            .map_err(transport)?;
        write_message(&mut s, &message::encode(&header)?).await?;
        Ok(TransferSender::new(SenderBody::Quic(s), header.size))
    }
}

/// Write channel byte, header and payload, finish, and wait for the peer to have all of it.
/// `Ok(None)` is delivery, `Ok(Some(code))` the peer stopped the stream.
async fn write_frame(s: &mut SendStream, job: &VideoJob) -> Result<Option<u64>> {
    let mut head = [0u8; 1 + MEDIA_HEADER_LEN];
    head[0] = ChannelId::Video as u8;
    head[1..].copy_from_slice(&job.head);
    match s.write_all(&head).await {
        Ok(()) => {}
        Err(quinn::WriteError::Stopped(code)) => return Ok(Some(code.into_inner())),
        Err(e) => return Err(transport(e)),
    }
    match s.write_all(&job.payload).await {
        Ok(()) => {}
        Err(quinn::WriteError::Stopped(code)) => return Ok(Some(code.into_inner())),
        Err(e) => return Err(transport(e)),
    }
    s.finish().map_err(transport)?;
    Ok(s.stopped()
        .await
        .map_err(transport)?
        .map(VarInt::into_inner))
}

// ---------------------------------------------------------------- reader tasks

/// Start the reader tasks of an established QUIC connection.
pub(crate) fn spawn_tasks(inner: &Arc<Inner>, control_recv: RecvStream) {
    let Backend::Quic(q) = &inner.backend else {
        return;
    };
    let conn = q.conn.clone();

    let i = inner.clone();
    tokio::spawn(async move {
        let e = conn.closed().await;
        i.record_close(close_info_from_error(&e));
    });

    let i = inner.clone();
    tokio::spawn(async move {
        if let Err(e) = control_reader(&i, control_recv).await {
            reader_failed(&i, "control", e);
        }
    });

    let i = inner.clone();
    tokio::spawn(async move { uni_acceptor(i).await });

    let i = inner.clone();
    tokio::spawn(async move { datagram_reader(i).await });
}

/// A reader hit an error: protocol problems close the connection, transport errors are
/// reported by the connection-closed watcher.
fn reader_failed(inner: &Inner, what: &str, e: Error) {
    match e {
        Error::Protocol(_) | Error::Violation(_) => inner.fail(&format!("{what}: {e}")),
        other => tracing::debug!(channel = what, error = %other, "reader ended"),
    }
}

async fn control_reader(inner: &Arc<Inner>, mut rs: RecvStream) -> Result<()> {
    while let Some(buf) = read_message(&mut rs, MAX_CONTROL_MESSAGE).await? {
        let m: ControlMessage = message::decode(&buf)?;
        inner.deliver_control(m).await?;
    }
    Ok(())
}

async fn uni_acceptor(inner: Arc<Inner>) {
    let Backend::Quic(q) = &inner.backend else {
        return;
    };
    while let Ok(rs) = q.conn.accept_uni().await {
        let i = inner.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_uni(&i, rs).await {
                reader_failed(&i, "stream", e);
            }
        });
    }
}

async fn handle_uni(inner: &Arc<Inner>, mut rs: RecvStream) -> Result<()> {
    let mut b = [0u8; 1];
    tokio::time::timeout(STREAM_OPEN_TIMEOUT, read_exact(&mut rs, &mut b))
        .await
        .map_err(|_| Error::Violation("stream did not start with a channel byte".into()))??;
    let ch = ChannelId::from_u8(b[0])?;
    if inner.role == Role::Server && !inner.is_authorized() {
        // Unreachable with the pre-authorization stream limit of 0; enforced anyway.
        return Err(Error::Violation(
            "unidirectional stream before authorization".into(),
        ));
    }
    match (inner.role, ch) {
        (Role::Server, ChannelId::Input) => {
            if inner.claimed_input.swap(true, Ordering::SeqCst) {
                return Err(Error::Violation("second input stream".into()));
            }
            while let Some(buf) = read_message(&mut rs, MAX_INPUT_MESSAGE).await? {
                let e: InputEvent = message::decode(&buf)?;
                inner.deliver_input(e).await?;
            }
            Ok(())
        }
        (Role::Client, ChannelId::Cursor) => {
            if inner.claimed_cursor.swap(true, Ordering::SeqCst) {
                return Err(Error::Violation("second cursor stream".into()));
            }
            while let Some(buf) = read_message(&mut rs, MAX_CURSOR_MESSAGE).await? {
                let e: CursorEvent = message::decode(&buf)?;
                inner.deliver_cursor(e).await?;
            }
            Ok(())
        }
        (Role::Client, ChannelId::Video) => read_video(inner, rs).await,
        (_, ChannelId::Clipboard | ChannelId::File) => {
            let (kind, feature, name) = match ch {
                ChannelId::Clipboard => (TransferKind::Clipboard, Features::CLIPBOARD, "clipboard"),
                _ => (TransferKind::File, Features::FILE_TRANSFER, "file transfer"),
            };
            inner
                .require_feature(feature, name)
                .map_err(|e| Error::Violation(e.to_string()))?;
            let Some(buf) = read_message(&mut rs, MAX_TRANSFER_HEADER).await? else {
                return Err(Error::Violation("transfer without header".into()));
            };
            let header: TransferHeader = message::decode(&buf)?;
            if kind == TransferKind::Clipboard {
                header.validate_clipboard()?;
            }
            let t = IncomingTransfer::new(kind, header, IncomingBody::Quic(rs));
            // A full queue means the application is not keeping up: refuse this transfer.
            if let Err(e) = inner.router.transfers.try_send(t) {
                let (TrySendError::Full(t) | TrySendError::Closed(t)) = e;
                if let IncomingBody::Quic(mut rs) = t.body {
                    let _ = rs.stop(STOP_TRANSFER_REJECTED.into());
                }
            }
            Ok(())
        }
        _ => Err(Error::Violation(format!(
            "channel {ch:?} is not allowed on a stream to this role"
        ))),
    }
}

async fn read_video(inner: &Arc<Inner>, mut rs: RecvStream) -> Result<()> {
    let mut head = [0u8; MEDIA_HEADER_LEN];
    match rs.read_exact(&mut head).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::ReadError(quinn::ReadError::Reset(_))) => {
            inner
                .counters
                .frames_reset_by_peer
                .fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        Err(quinn::ReadExactError::ReadError(e)) => return Err(transport(e)),
        Err(quinn::ReadExactError::FinishedEarly(_)) => {
            return Err(Error::Violation(
                "video stream shorter than its header".into(),
            ));
        }
    }
    let header = MediaHeader::decode(&head)?;
    let want = header.payload_len as usize;
    // Bounded by the validated `payload_len` (<= 16 MiB); one byte more detects an overlong body.
    let payload = match rs.read_to_end(want + 1).await {
        Ok(p) => p,
        Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(_))) => {
            inner
                .counters
                .frames_reset_by_peer
                .fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        Err(quinn::ReadToEndError::Read(e)) => return Err(transport(e)),
        Err(quinn::ReadToEndError::TooLong) => {
            return Err(Error::Violation(
                "video body longer than payload_len".into(),
            ));
        }
    };
    if payload.len() != want {
        return Err(Error::Violation(
            "video body shorter than payload_len".into(),
        ));
    }
    inner
        .deliver_video(VideoFrame {
            header,
            payload: Bytes::from(payload),
        })
        .await
}

async fn datagram_reader(inner: Arc<Inner>) {
    let Backend::Quic(q) = &inner.backend else {
        return;
    };
    while let Ok(d) = q.conn.read_datagram().await {
        handle_datagram(&inner, &d);
    }
}

pub(crate) fn handle_datagram(inner: &Inner, d: &[u8]) {
    match (inner.role, decode_datagram(d)) {
        (Role::Server, Ok(Datagram::MouseMove(m))) => inner.deliver_mouse(m),
        (Role::Client, Ok(Datagram::Audio(a))) if inner.features().contains(Features::AUDIO) => {
            inner.deliver_audio(a);
        }
        _ => {
            inner
                .counters
                .datagrams_dropped
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------- establishing

/// Finish a QUIC connection after a successful hello exchange: open the long-lived outbound
/// stream, build the [`Connection`] and start the readers.
pub(crate) async fn establish(
    conn: quinn::Connection,
    control_send: SendStream,
    control_recv: RecvStream,
    endpoint: Option<quinn::Endpoint>,
    parts: crate::conn::Parts,
) -> Result<Connection> {
    let _ = control_send.set_priority(priority::CONTROL);
    // Both sides open their long-lived unidirectional stream (the client's input stream, the
    // server's cursor stream) lazily on first use. Nothing here waits on the peer's stream
    // credit, so a peer that grants none cannot stall `accept`.
    let uni = None;
    let backend = Backend::Quic(QuicBackend::new(conn, control_send, uni, endpoint));
    let inner = Inner::new(parts, backend);
    spawn_tasks(&inner, control_recv);
    Ok(Connection::from_inner(inner))
}
