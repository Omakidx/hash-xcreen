//! The typed async API of the gateway end of the session link.
//!
//! * [`LinkClient::connect`] dials the three lanes and returns a [`LinkClient`] (commands, cheap
//!   to clone) and a [`LinkEvents`] (the single stream of everything the session sends).
//! * Commands never block on the session: they are queued in the bounded priority queues of
//!   section 17 and written by one task. A queue that fills because the session does not read
//!   ends the link as a *fault* (not as a client error).
//! * [`LinkEvents::next`] yields frames, cursor, statistics, events and transfers; the last
//!   event is always [`LinkEvent::Closed`] with the classification.

use super::config::LinkConfig;
use super::connect::connect;
use super::shared::{BulkOut, Shared, lock};
use super::tasks::{abort_incoming, encode};
use super::types::{
    ConnectError, Counters, FailureClass, LinkClosed, LinkEvent, SendError, SessionInfo,
    TransferError,
};
use bytes::Bytes;
use hx_ipc::link::frames::{encode_transfer_abort, encode_transfer_end, encode_transfer_open};
use hx_ipc::link::{MAX_TRANSFER_CHUNK, Role, pb};
use hx_proto::channel::RESET_TRANSFER_ERROR;
use hx_proto::datagram::MouseMove;
use hx_proto::order::serial_gt;
use hx_proto::pb::{ClientStats, InputEvent, TransferHeader};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

/// Ends the link when the last handle is dropped.
struct Guard(Arc<Shared>);

impl Drop for Guard {
    fn drop(&mut self) {
        self.0
            .fail(FailureClass::Closed, "every handle to the link was dropped");
    }
}

/// The command side of a link. Cloning is cheap; the link closes when every clone and the
/// [`LinkEvents`] are gone.
#[derive(Clone)]
pub struct LinkClient {
    sh: Arc<Shared>,
    _guard: Arc<Guard>,
}

/// The event side of a link: one consumer.
pub struct LinkEvents {
    sh: Arc<Shared>,
    _guard: Arc<Guard>,
}

impl std::fmt::Debug for LinkClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkClient")
            .field("closed", &self.sh.is_closed())
            .finish_non_exhaustive()
    }
}

impl LinkClient {
    /// Dials the desktop at `host_socket_path` (the host side of the proxy device,
    /// `/run/hx/link/<desktop>.sock`): `ctl` first, waits for `info`, then `media` and `bulk`.
    ///
    /// Everything is bounded: each `connect` by `connect_timeout`, preamble plus `info` by
    /// `handshake_timeout` (5 s), the extra lanes by `extra_lanes_timeout` (5 s). The error says
    /// why in a [`FailureClass`]: `Unavailable` (refused, reset after accept, silent) is the
    /// normal "desktop not up" answer, `Outdated` means the in-container binary is old.
    pub async fn connect(
        host_socket_path: impl AsRef<Path>,
        cfg: LinkConfig,
    ) -> Result<(LinkClient, LinkEvents), ConnectError> {
        let c = connect(host_socket_path.as_ref(), cfg).await?;
        let guard = Arc::new(Guard(c.shared.clone()));
        Ok((
            LinkClient {
                sh: c.shared.clone(),
                _guard: guard.clone(),
            },
            LinkEvents {
                sh: c.shared,
                _guard: guard,
            },
        ))
    }

    /// What the session reported in `info` (codecs are the negotiated intersection).
    pub fn info(&self) -> &SessionInfo {
        &self.sh.info
    }

    /// The negotiated link minor version (the lower of the two).
    pub fn negotiated_minor(&self) -> u8 {
        self.sh.minor
    }

    /// True once the link has ended.
    pub fn is_closed(&self) -> bool {
        self.sh.is_closed()
    }

    /// Why the link ended, once it has.
    pub fn closed_reason(&self) -> Option<LinkClosed> {
        self.sh.closed_reason()
    }

    /// What was ignored, dropped or refused so far.
    pub fn counters(&self) -> Counters {
        *lock(&self.sh.counters)
    }

    /// Smoothed-free last round-trip of the `ping`/`pong` exchange in microseconds (0: none yet).
    pub fn ping_rtt_us(&self) -> u32 {
        lock(&self.sh.pings).rtt_us
    }

    /// Bytes of video currently queued for the consumer (never above the video pool).
    pub fn queued_video_bytes(&self) -> u64 {
        self.sh.inbox.queued_frame_bytes()
    }

    /// Closes the link now (`FailureClass::Closed`).
    pub fn close(&self) {
        self.sh.fail(FailureClass::Closed, "closed by the owner");
    }

    fn ensure_open(&self) -> Result<(), SendError> {
        if self.sh.is_closed() {
            Err(SendError::Closed)
        } else {
            Ok(())
        }
    }

    fn queue_p1(&self, m: pb::gateway_to_session::Message) -> Result<(), SendError> {
        self.ensure_open()?;
        let f = encode(m).map_err(SendError::Invalid)?;
        if self.sh.out.push_p1(f) {
            Ok(())
        } else {
            self.sh.fail(
                FailureClass::Fault,
                "ctl queue full: the session is not reading",
            );
            Err(SendError::Closed)
        }
    }

    /// Begins streaming for a client: `epoch` identifies it (section 18). Frames of any other
    /// epoch are dropped from now on, frames still queued for the previous client are
    /// discarded, and everything is dropped until the session's `KEY | RESYNC` frame. The
    /// gateway has already applied the device's bandwidth cap and policies.
    pub fn start(&self, epoch: u32, config: pb::StreamConfig) -> Result<(), SendError> {
        self.ensure_open()?;
        // Validate first (the encoder applies the section 14.1 ranges) so a bad config changes
        // no state.
        let f = encode(pb::gateway_to_session::Message::Start(pb::Start {
            epoch,
            config: Some(config),
        }))
        .map_err(SendError::Invalid)?;
        self.sh.epoch.store(epoch, Relaxed);
        self.sh.epoch_set.store(true, Relaxed);
        lock(&self.sh.video).gate_armed = true;
        let _stale = self.sh.inbox.drain_frames();
        if self.sh.out.push_p1(f) {
            Ok(())
        } else {
            self.sh.fail(
                FailureClass::Fault,
                "ctl queue full: the session is not reading",
            );
            Err(SendError::Closed)
        }
    }

    /// The last client left (or was displaced): stop capturing. Frames are dropped until the
    /// next [`start`](Self::start).
    pub fn stop(&self, epoch: u32) -> Result<(), SendError> {
        self.sh.epoch_set.store(false, Relaxed);
        let _stale = self.sh.inbox.drain_frames();
        self.queue_p1(pb::gateway_to_session::Message::Stop(pb::Stop { epoch }))
    }

    /// New settings while streaming (client window resize, bitrate cap, frame rate, policies).
    /// Zero fields keep their value; the two policy booleans are applied as given.
    pub fn reconfigure(&self, config: pb::StreamConfig) -> Result<(), SendError> {
        self.sh
            .clipboard_allowed
            .store(config.clipboard_enabled, Relaxed);
        self.sh
            .files_allowed
            .store(config.file_transfer_enabled, Relaxed);
        self.queue_p1(pb::gateway_to_session::Message::Reconfigure(
            pb::Reconfigure {
                config: Some(config),
            },
        ))
    }

    /// Asks for a fresh full image (protocol `RequestKeyframe`, or after dropping frames).
    /// At most 2 per second reach the session; a refused one is retried within a second.
    pub fn request_idr(&self, last_decoded_frame: u32) -> Result<(), SendError> {
        self.ensure_open()?;
        lock(&self.sh.video).last_delivered = last_decoded_frame;
        self.sh.arm_resync();
        Ok(())
    }

    /// One validated key, button, scroll or `release_all` event, in client order (priority P0).
    pub fn input(&self, event: InputEvent) -> Result<(), SendError> {
        self.ensure_open()?;
        let f =
            encode(pb::gateway_to_session::Message::Input(event)).map_err(SendError::Invalid)?;
        if self.sh.out.push_p0(f) {
            Ok(())
        } else {
            // The client is within its rate limit, so the session is the one not reading.
            self.sh.fail(
                FailureClass::Fault,
                "input queue full: the session is not reading",
            );
            Err(SendError::Closed)
        }
    }

    /// Pointer motion: latest wins, absolute and relative merged, at most one message per
    /// millisecond (priority P0, after the queued input events).
    pub fn mouse(&self, motion: MouseMove) -> Result<(), SendError> {
        self.ensure_open()?;
        self.sh.out.push_mouse(motion);
        Ok(())
    }

    /// The outcome per frame (section 15.3), as soon as known. A `CANCELLED`, `REJECTED` or
    /// `DROPPED` result breaks the decode chain: the link client then discards non-key frames
    /// until the next `KEY | RESYNC` and asks for an IDR itself (at most 2 per second).
    pub fn frame_feedback(&self, results: &[pb::FrameResult]) -> Result<(), SendError> {
        self.ensure_open()?;
        let mut broken = false;
        for chunk in results.chunks(hx_ipc::link::validate::MAX_FEEDBACK_RESULTS) {
            for r in chunk {
                match pb::FrameOutcome::try_from(r.outcome) {
                    Ok(pb::FrameOutcome::Delivered) => {
                        let mut v = lock(&self.sh.video);
                        if serial_gt(r.frame_number, v.last_delivered) {
                            v.last_delivered = r.frame_number;
                        }
                    }
                    Ok(_) => broken = true,
                    Err(_) => {}
                }
            }
            self.queue_p1(pb::gateway_to_session::Message::FrameFeedback(
                pb::FrameFeedback {
                    results: chunk.to_vec(),
                },
            ))?;
        }
        if broken {
            self.sh.arm_resync();
        }
        Ok(())
    }

    /// The gateway's view of the path to the client (about 4 per second while streaming).
    pub fn transport_stats(&self, rtt_us: u32, delivery_rate_kbps: u32) -> Result<(), SendError> {
        self.ensure_open()?;
        let f = encode(pb::gateway_to_session::Message::TransportStats(
            pb::TransportStats {
                rtt_us,
                delivery_rate_kbps,
            },
        ))
        .map_err(SendError::Invalid)?;
        self.sh.out.push_p2(f);
        Ok(())
    }

    /// Forwarded client decode statistics (about 1 per second).
    pub fn client_stats(&self, stats: ClientStats) -> Result<(), SendError> {
        self.ensure_open()?;
        let f = encode(pb::gateway_to_session::Message::ClientStats(stats))
            .map_err(SendError::Invalid)?;
        self.sh.out.push_p2(f);
        Ok(())
    }

    /// Orderly end: `code` is a protocol.md section 8 close code; `message` is log text.
    pub fn goodbye(&self, code: u32, message: &str) -> Result<(), SendError> {
        self.ensure_open()?;
        let f = encode(pb::gateway_to_session::Message::Goodbye(pb::Goodbye {
            code,
            message: hx_ipc::text::sanitize_text(message, 256),
        }))
        .map_err(SendError::Invalid)?;
        self.sh.out.push_p2(f);
        Ok(())
    }

    /// Switches clipboard and file transfers on or off for session-initiated transfers and for
    /// [`begin_transfer`](Self::begin_transfer) (the device's policy; also sent to the session
    /// in `StreamConfig`).
    pub fn set_policy(&self, clipboard: bool, files: bool) {
        self.sh.clipboard_allowed.store(clipboard, Relaxed);
        self.sh.files_allowed.store(files, Relaxed);
    }

    /// Refuses or abandons an incoming transfer (`code` `0x101` rejected or `0x100` error).
    pub fn abort_transfer(&self, id: u32, code: u32) {
        abort_incoming(&self.sh, id, code);
    }

    /// Starts sending a clipboard or file transfer to the session. The header is validated like
    /// a client-supplied one and against `max_file_bytes`. At most 4 transfers are in flight; a
    /// new clipboard transfer aborts the previous one.
    pub async fn begin_transfer(
        &self,
        channel: pb::TransferChannel,
        header: TransferHeader,
    ) -> Result<TransferSender, TransferError> {
        if self.sh.is_closed() {
            return Err(TransferError::Closed);
        }
        let clipboard = match channel {
            pb::TransferChannel::Clipboard => true,
            pb::TransferChannel::File => false,
            pb::TransferChannel::Unspecified => {
                return Err(TransferError::Invalid("channel".into()));
            }
        };
        let allowed = if clipboard {
            self.sh.clipboard_allowed.load(Relaxed)
        } else {
            self.sh.files_allowed.load(Relaxed)
        };
        if !allowed {
            return Err(TransferError::Disabled);
        }
        let size = header.size;
        let (id, replaced) = {
            let mut x = lock(&self.sh.xfer);
            let mut replaced = None;
            if clipboard {
                replaced = x.outgoing.iter().find(|(_, c)| **c).map(|(id, _)| *id);
                if let Some(old) = replaced {
                    x.outgoing.remove(&old);
                    x.out_aborted.insert(old);
                }
            }
            if x.outgoing.len() >= 4 {
                return Err(TransferError::TooMany);
            }
            let id = loop {
                let id = x.next_id;
                x.next_id = x.next_id.wrapping_add(2) | 1;
                if id != 0 && !x.outgoing.contains_key(&id) {
                    break id;
                }
            };
            x.outgoing.insert(id, clipboard);
            (id, replaced)
        };
        let open = pb::TransferOpen {
            id,
            channel: channel as i32,
            header: Some(header),
        };
        let frame = match encode_transfer_open(Role::Gateway, &open, self.sh.cfg.max_file_bytes) {
            Ok(f) => f,
            Err(e) => {
                lock(&self.sh.xfer).outgoing.remove(&id);
                return Err(TransferError::Invalid(e.to_string()));
            }
        };
        if let Some(old) = replaced
            && let Ok(a) = encode_transfer_abort(old, RESET_TRANSFER_ERROR)
        {
            let _ = self.sh.bulk_tx.send(BulkOut::Frame(a)).await;
        }
        if self.sh.bulk_tx.send(BulkOut::Frame(frame)).await.is_err() {
            return Err(TransferError::Closed);
        }
        Ok(TransferSender {
            sh: self.sh.clone(),
            id,
            size,
            sent: 0,
            done: false,
        })
    }
}

/// The gateway's side of a transfer to the session. Dropping it before [`finish`](Self::finish)
/// aborts the transfer.
pub struct TransferSender {
    sh: Arc<Shared>,
    id: u32,
    size: u64,
    sent: u64,
    done: bool,
}

impl TransferSender {
    /// The transfer id (odd).
    pub fn id(&self) -> u32 {
        self.id
    }

    fn check(&self) -> Result<(), TransferError> {
        if self.sh.is_closed() {
            return Err(TransferError::Closed);
        }
        let x = lock(&self.sh.xfer);
        if !x.outgoing.contains_key(&self.id) || x.out_aborted.contains(&self.id) {
            return Err(TransferError::Aborted);
        }
        Ok(())
    }

    /// Sends body bytes (split into frames of at most 64 KiB). Waits while the `bulk` writer's
    /// queue is full; nothing else is affected.
    pub async fn write(&mut self, data: Bytes) -> Result<(), TransferError> {
        self.check()?;
        let len = data.len() as u64;
        if self.sent + len > self.size {
            self.abort_inner(RESET_TRANSFER_ERROR);
            return Err(TransferError::SizeMismatch);
        }
        let mut at = 0;
        while at < data.len() {
            self.check()?;
            let end = (at + MAX_TRANSFER_CHUNK).min(data.len());
            self.sh
                .bulk_tx
                .send(BulkOut::Data {
                    id: self.id,
                    data: data.slice(at..end),
                })
                .await
                .map_err(|_| TransferError::Closed)?;
            at = end;
        }
        self.sent += len;
        Ok(())
    }

    /// Ends the transfer. Fewer bytes than the header announced abort it with `TRANSFER_ERROR`.
    pub async fn finish(mut self) -> Result<(), TransferError> {
        self.check()?;
        if self.sent != self.size {
            self.abort_inner(RESET_TRANSFER_ERROR);
            return Err(TransferError::SizeMismatch);
        }
        let end =
            encode_transfer_end(self.id).map_err(|e| TransferError::Invalid(e.to_string()))?;
        self.done = true;
        lock(&self.sh.xfer).outgoing.remove(&self.id);
        self.sh
            .bulk_tx
            .send(BulkOut::Frame(end))
            .await
            .map_err(|_| TransferError::Closed)
    }

    /// Aborts the transfer with a protocol.md section 8 transfer code.
    pub fn abort(mut self, code: u32) {
        self.abort_inner(code);
    }

    fn abort_inner(&mut self, code: u32) {
        if self.done {
            return;
        }
        self.done = true;
        {
            let mut x = lock(&self.sh.xfer);
            x.outgoing.remove(&self.id);
            x.out_aborted.remove(&self.id);
        }
        if let Ok(a) = encode_transfer_abort(self.id, code) {
            let _ = self.sh.bulk_tx.try_send(BulkOut::Frame(a));
        }
    }
}

impl Drop for TransferSender {
    fn drop(&mut self) {
        self.abort_inner(RESET_TRANSFER_ERROR);
    }
}

impl LinkEvents {
    /// The next event. After the link ends this returns [`LinkEvent::Closed`] (events still
    /// queued, such as a session goodbye, come first; queued video and transfer data do not).
    pub async fn next(&mut self) -> LinkEvent {
        loop {
            let notified = self.sh.inbox.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(closed) = self.sh.closed_reason() {
                if let Some(ev) = self.sh.inbox.pop_event_only() {
                    return ev;
                }
                return LinkEvent::Closed(closed);
            }
            if let Some(ev) = self.sh.inbox.pop() {
                return ev;
            }
            notified.await;
        }
    }

    /// The link's counters (same as [`LinkClient::counters`]).
    pub fn counters(&self) -> Counters {
        *lock(&self.sh.counters)
    }
}
