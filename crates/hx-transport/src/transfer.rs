//! Clipboard and file transfers: one unidirectional stream per transfer (QUIC) or tagged
//! chunk messages (WebSocket), behind one pair of types.

use bytes::Bytes;
use hx_proto::{
    channel::{ChannelId, MAX_TRANSFER_CHUNK, RESET_TRANSFER_ERROR, STOP_TRANSFER_REJECTED},
    pb::TransferHeader,
};

use crate::{
    error::{Error, Result, transport},
    ws::{WsChunk, WsTransferSender},
};

/// Which transfer channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferKind {
    /// Clipboard content (channel `0x07`).
    Clipboard,
    /// A file (channel `0x08`).
    File,
}

impl TransferKind {
    pub(crate) fn channel(self) -> ChannelId {
        match self {
            Self::Clipboard => ChannelId::Clipboard,
            Self::File => ChannelId::File,
        }
    }
}

pub(crate) enum IncomingBody {
    Quic(quinn::RecvStream),
    Ws(WsReceiver),
}

/// Receiving half of a WebSocket transfer. Queued bytes are counted against a per-transfer
/// and a per-connection budget until the application reads (or drops) them.
pub(crate) struct WsReceiver {
    pub rx: tokio::sync::mpsc::Receiver<WsChunk>,
    pub queued: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    pub conn_queued: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl WsReceiver {
    fn release(&self, len: usize) {
        use std::sync::atomic::Ordering::SeqCst;
        self.queued.fetch_sub(len, SeqCst);
        self.conn_queued.fetch_sub(len, SeqCst);
    }
}

impl Drop for WsReceiver {
    fn drop(&mut self) {
        self.rx.close();
        while let Ok(chunk) = self.rx.try_recv() {
            if let WsChunk::Data(b) = chunk {
                self.release(b.len());
            }
        }
    }
}

/// A transfer started by the peer. Read it with [`next_chunk`](Self::next_chunk) or
/// [`read_to_end`](Self::read_to_end); the byte count is checked against `header.size`.
pub struct IncomingTransfer {
    /// Which channel it arrived on.
    pub kind: TransferKind,
    /// The validated header.
    pub header: TransferHeader,
    pub(crate) body: IncomingBody,
    pub(crate) remaining: u64,
}

impl std::fmt::Debug for IncomingTransfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncomingTransfer")
            .field("kind", &self.kind)
            .field("header", &self.header)
            .finish()
    }
}

impl IncomingTransfer {
    pub(crate) fn new(kind: TransferKind, header: TransferHeader, body: IncomingBody) -> Self {
        let remaining = header.size;
        Self {
            kind,
            header,
            body,
            remaining,
        }
    }

    /// Next piece of the body, or `None` after exactly `header.size` bytes. A body that is
    /// longer or shorter than announced is [`Error::TransferSize`] and aborts the transfer.
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>> {
        match &mut self.body {
            IncomingBody::Quic(rs) => match rs
                .read_chunk(MAX_TRANSFER_CHUNK, true)
                .await
                .map_err(transport)?
            {
                Some(chunk) => {
                    if chunk.bytes.len() as u64 > self.remaining {
                        let _ = rs.stop(RESET_TRANSFER_ERROR.into());
                        return Err(Error::TransferSize);
                    }
                    self.remaining -= chunk.bytes.len() as u64;
                    Ok(Some(chunk.bytes))
                }
                None if self.remaining == 0 => Ok(None),
                None => Err(Error::TransferSize),
            },
            IncomingBody::Ws(w) => match w.rx.recv().await {
                Some(WsChunk::Data(b)) => {
                    w.release(b.len());
                    if b.len() as u64 > self.remaining {
                        return Err(Error::TransferSize);
                    }
                    self.remaining -= b.len() as u64;
                    Ok(Some(b))
                }
                Some(WsChunk::End) if self.remaining == 0 => Ok(None),
                Some(WsChunk::End) => Err(Error::TransferSize),
                Some(WsChunk::Aborted) | None => Err(Error::ChannelClosed),
            },
        }
    }

    /// Read the whole body, refusing anything above `limit` bytes before reading it.
    pub async fn read_to_end(mut self, limit: u64) -> Result<Bytes> {
        if self.header.size > limit {
            self.reject();
            return Err(Error::TransferSize);
        }
        let mut out = Vec::with_capacity(self.header.size.min(1 << 20) as usize);
        while let Some(c) = self.next_chunk().await? {
            out.extend_from_slice(&c);
        }
        Ok(Bytes::from(out))
    }

    /// Refuse the transfer: the sender sees its stream stopped.
    pub fn reject(self) {
        if let IncomingBody::Quic(mut rs) = self.body {
            let _ = rs.stop(STOP_TRANSFER_REJECTED.into());
        }
        // WebSocket: dropping the receiver makes the connection abort the transfer on the
        // next chunk.
    }
}

pub(crate) enum SenderBody {
    Quic(quinn::SendStream),
    Ws(WsTransferSender),
}

/// Sending half of a transfer opened with `Connection::open_transfer`.
pub struct TransferSender {
    pub(crate) body: SenderBody,
    pub(crate) remaining: u64,
}

impl TransferSender {
    pub(crate) fn new(body: SenderBody, size: u64) -> Self {
        Self {
            body,
            remaining: size,
        }
    }

    /// Append body bytes. Writing more than `header.size` is [`Error::TransferSize`].
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        if data.len() as u64 > self.remaining {
            return Err(Error::TransferSize);
        }
        match &mut self.body {
            SenderBody::Quic(s) => s.write_all(data).await.map_err(transport)?,
            SenderBody::Ws(w) => {
                for part in data.chunks(MAX_TRANSFER_CHUNK) {
                    w.send_data(Bytes::copy_from_slice(part)).await?;
                }
            }
        }
        self.remaining -= data.len() as u64;
        Ok(())
    }

    /// Finish the transfer. Fewer bytes than `header.size` were written: the transfer is
    /// aborted and [`Error::TransferSize`] returned. On QUIC this waits until the receiver
    /// has the whole body and fails if it rejected it.
    pub async fn finish(mut self) -> Result<()> {
        if self.remaining != 0 {
            self.abort();
            return Err(Error::TransferSize);
        }
        match &mut self.body {
            SenderBody::Quic(s) => {
                s.finish().map_err(transport)?;
                match s.stopped().await.map_err(transport)? {
                    None => Ok(()),
                    Some(code) => Err(Error::Violation(format!(
                        "receiver stopped the transfer (code {code})"
                    ))),
                }
            }
            SenderBody::Ws(w) => w.send_end().await,
        }
    }

    /// Abort the transfer.
    pub fn abort(self) {
        match self.body {
            SenderBody::Quic(mut s) => {
                let _ = s.reset(RESET_TRANSFER_ERROR.into());
            }
            SenderBody::Ws(w) => w.abort(),
        }
    }
}
