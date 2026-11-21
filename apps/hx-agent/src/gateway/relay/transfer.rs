//! Clipboard and file transfers between one client and the session (protocol 5.5, 5.6; ipc.md 16).
//!
//! Each transfer is a client stream on one side and a transfer on the `bulk` lane on the other;
//! the relay copies the body in chunks of at most 64 KiB and never holds more than one chunk per
//! transfer (inbound) or what the link client's own credit allows (outbound).
//!
//! * **Policy.** Clipboard and files are each allowed only if the feature was negotiated and the
//!   client's latest `ViewConfig` allows it (files follow the negotiated feature; clipboard also
//!   needs `clipboard_enabled`). A refused transfer is stopped with `TRANSFER_REJECTED`.
//! * **Limits.** A file header above the effective limit (the lower of the negotiated and the
//!   link's `max_file_bytes`) is refused before a body byte is read. A clipboard is at most
//!   64 MiB. At most 4 transfers per direction run at once; clipboard transfers from the session
//!   are limited to 4 per second.
//! * **Names are hints.** The file name is only forwarded (it already passed the protocol's name
//!   rules on the way in); nothing here uses it as a path.
//! * **Bounds.** Session to client: the pump pushes into a bounded inbox ([`Inbox`], 128 entries,
//!   256 with the small control entries) without waiting; chunks hold the link client's unread
//!   credit until they are written, so a stalled client pauses `bulk` and nothing else. A
//!   transfer that overflows the inbox is aborted. Every write to the client and every wait for
//!   a chunk is bounded by 30 s.
//! * **Takeover.** `abort` (a generation counter) aborts every running transfer in both
//!   directions.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hx_ipc::link::pb;
use hx_proto::channel::{MAX_CLIPBOARD_SIZE, RESET_TRANSFER_ERROR, STOP_TRANSFER_REJECTED};
use hx_proto::version::Features;
use hx_transport::{Connection, IncomingTransfer, TransferKind, TransferSender};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, watch};

use super::util::{TokenBucket, lock};
use crate::link::{LinkClient, TransferEvent};

/// Transfers per direction.
const MAX_CONCURRENT: usize = 4;
/// A wait for the next chunk, or one write, that takes this long ends the transfer.
const IDLE: Duration = Duration::from_secs(30);
/// Opening a client stream.
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);
/// Entries of the session-to-client inbox (data and opens); control entries get headroom.
const INBOX_SOFT: usize = 128;
const INBOX_HARD: usize = 256;

/// What the transfer tasks of one client share.
#[derive(Clone)]
pub(super) struct TransferCtx {
    pub conn: Connection,
    pub link: LinkClient,
    pub clipboard_ok: Arc<AtomicBool>,
    pub files_ok: Arc<AtomicBool>,
    /// The effective file limit: the lower of the negotiated one and the link's.
    pub max_file_bytes: u64,
    pub features: Features,
    /// Bumped on a takeover: every transfer, both directions, is aborted.
    pub abort: watch::Receiver<u64>,
    /// Bumped when the client's policy turns the clipboard off: its transfers are aborted.
    pub abort_clip: watch::Receiver<u64>,
    /// Bumped when the policy turns files off.
    pub abort_file: watch::Receiver<u64>,
}

impl TransferCtx {
    fn allowed(&self, kind: TransferKind) -> bool {
        match kind {
            TransferKind::Clipboard => {
                self.features.contains(Features::CLIPBOARD) && self.clipboard_ok.load(Relaxed)
            }
            TransferKind::File => {
                self.features.contains(Features::FILE_TRANSFER) && self.files_ok.load(Relaxed)
            }
        }
    }
}

/// Session-to-client transfer events waiting for the outbound task.
#[derive(Default)]
pub(super) struct Inbox {
    q: Mutex<VecDeque<TransferEvent>>,
    notify: Notify,
}

impl Inbox {
    /// Queues `ev` without waiting; a transfer that does not fit is aborted toward the session.
    pub(super) fn push(&self, link: &LinkClient, ev: TransferEvent) {
        let overflow = {
            let mut q = lock(&self.q);
            let cap = match ev {
                TransferEvent::Open { .. } | TransferEvent::Data(_) => INBOX_SOFT,
                _ => INBOX_HARD,
            };
            if q.len() >= cap {
                Some(ev)
            } else {
                q.push_back(ev);
                None
            }
        };
        match overflow {
            None => self.notify.notify_one(),
            Some(TransferEvent::Open { id, .. }) => link.abort_transfer(id, STOP_TRANSFER_REJECTED),
            Some(TransferEvent::Data(chunk)) => link.abort_transfer(chunk.id, RESET_TRANSFER_ERROR),
            Some(_) => {}
        }
    }

    fn pop(&self) -> Option<TransferEvent> {
        lock(&self.q).pop_front()
    }

    /// Drops everything queued (chunks release their credit as they drop) and aborts the
    /// transfers it belonged to toward the session.
    pub(super) fn clear(&self, link: &LinkClient) {
        let drained: Vec<TransferEvent> = lock(&self.q).drain(..).collect();
        let mut ids = std::collections::HashSet::new();
        for ev in drained {
            match ev {
                TransferEvent::Open { id, .. } => {
                    ids.insert(id);
                }
                TransferEvent::Data(chunk) => {
                    ids.insert(chunk.id);
                }
                _ => {}
            }
        }
        for id in ids {
            link.abort_transfer(id, RESET_TRANSFER_ERROR);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        lock(&self.q).len()
    }
}

/// Accepts the client's transfers and bridges each to the session.
pub(super) async fn inbound(cx: TransferCtx, mut shutdown: watch::Receiver<bool>) {
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let mut rate = TokenBucket::new(50, 50);
    loop {
        let t = tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            r = cx.conn.accept_transfer() => match r {
                Ok(t) => t,
                Err(_) => return,
            },
        };
        let channel = match t.kind {
            TransferKind::Clipboard => pb::TransferChannel::Clipboard,
            TransferKind::File => pb::TransferChannel::File,
        };
        let size_ok = match t.kind {
            TransferKind::Clipboard => t.header.size > 0 && t.header.size <= MAX_CLIPBOARD_SIZE,
            TransferKind::File => t.header.validate_file(cx.max_file_bytes).is_ok(),
        };
        if !cx.allowed(t.kind) || !size_ok || !rate.allow(Instant::now()) {
            t.reject();
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            t.reject();
            continue;
        };
        tokio::spawn(run_inbound(
            cx.clone(),
            t,
            channel,
            permit,
            shutdown.clone(),
        ));
    }
}

enum Step {
    Chunk(Result<Option<bytes::Bytes>, ()>),
    Stop,
}

async fn run_inbound(
    cx: TransferCtx,
    mut t: IncomingTransfer,
    channel: pb::TransferChannel,
    _permit: OwnedSemaphorePermit,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut abort = cx.abort.clone();
    let mut kind_abort = match channel {
        pb::TransferChannel::File => cx.abort_file.clone(),
        _ => cx.abort_clip.clone(),
    };
    let mut sender = match cx.link.begin_transfer(channel, t.header.clone()).await {
        Ok(s) => s,
        Err(_) => {
            t.reject();
            return;
        }
    };
    loop {
        let step = tokio::select! {
            biased;
            _ = shutdown.changed() => Step::Stop,
            _ = abort.changed() => Step::Stop,
            _ = kind_abort.changed() => Step::Stop,
            r = tokio::time::timeout(IDLE, t.next_chunk()) => {
                Step::Chunk(r.map_err(|_| ()).and_then(|r| r.map_err(|_| ())))
            }
        };
        match step {
            Step::Stop | Step::Chunk(Err(())) => {
                sender.abort(RESET_TRANSFER_ERROR);
                t.reject();
                return;
            }
            Step::Chunk(Ok(Some(chunk))) => {
                match tokio::time::timeout(IDLE, sender.write(chunk)).await {
                    Ok(Ok(())) => {}
                    _ => {
                        sender.abort(RESET_TRANSFER_ERROR);
                        t.reject();
                        return;
                    }
                }
            }
            Step::Chunk(Ok(None)) => {
                // The body is complete and its size matched the header.
                let _ = tokio::time::timeout(IDLE, sender.finish()).await;
                return;
            }
        }
    }
}

/// How often the session may start transfers: clipboard 4 a second, files 16 per 10 s.
struct Rates {
    clip: TokenBucket,
    file: TokenBucket,
}

struct Out {
    sender: TransferSender,
    kind: TransferKind,
}

/// Bridges the session's transfers to the client.
pub(super) async fn outbound(
    cx: TransferCtx,
    inbox: Arc<Inbox>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut abort = cx.abort.clone();
    let mut abort_clip = cx.abort_clip.clone();
    let mut abort_file = cx.abort_file.clone();
    let mut active: HashMap<u32, Out> = HashMap::new();
    let mut rates = Rates {
        clip: TokenBucket::new(4, 4),
        // 16 files a copy (ipc.md 16), about one copy every 10 s.
        file: TokenBucket::with_rate(1.6, 16),
    };
    loop {
        while let Some(ev) = inbox.pop() {
            enum Sig {
                Shutdown,
                Abort,
                Kind(TransferKind),
                Done,
            }
            let sig = tokio::select! {
                biased;
                _ = shutdown.changed() => Sig::Shutdown,
                _ = abort.changed() => Sig::Abort,
                _ = abort_clip.changed() => Sig::Kind(TransferKind::Clipboard),
                _ = abort_file.changed() => Sig::Kind(TransferKind::File),
                () = handle(&cx, &mut active, &mut rates, ev) => Sig::Done,
            };
            match sig {
                Sig::Shutdown => {
                    abort_all(&cx, &mut active);
                    return;
                }
                Sig::Abort => abort_all(&cx, &mut active),
                Sig::Kind(k) => abort_kind(&cx, &mut active, k),
                Sig::Done => {}
            }
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                abort_all(&cx, &mut active);
                return;
            }
            _ = abort.changed() => {
                abort_all(&cx, &mut active);
                inbox.clear(&cx.link);
            }
            _ = abort_clip.changed() => abort_kind(&cx, &mut active, TransferKind::Clipboard),
            _ = abort_file.changed() => abort_kind(&cx, &mut active, TransferKind::File),
            () = inbox.notify.notified() => {}
        }
    }
}

/// The policy for `kind` was switched off: its running transfers (session to client) end.
fn abort_kind(cx: &TransferCtx, active: &mut HashMap<u32, Out>, kind: TransferKind) {
    let ids: Vec<u32> = active
        .iter()
        .filter(|(_, o)| o.kind == kind)
        .map(|(id, _)| *id)
        .collect();
    for id in ids {
        if let Some(o) = active.remove(&id) {
            o.sender.abort();
            cx.link.abort_transfer(id, RESET_TRANSFER_ERROR);
        }
    }
}

fn abort_all(cx: &TransferCtx, active: &mut HashMap<u32, Out>) {
    for (id, o) in active.drain() {
        o.sender.abort();
        cx.link.abort_transfer(id, RESET_TRANSFER_ERROR);
    }
}

async fn handle(
    cx: &TransferCtx,
    active: &mut HashMap<u32, Out>,
    rates: &mut Rates,
    ev: TransferEvent,
) {
    match ev {
        TransferEvent::Open {
            id,
            channel,
            header,
        } => {
            let kind = match channel {
                pb::TransferChannel::Clipboard => TransferKind::Clipboard,
                pb::TransferChannel::File => TransferKind::File,
                pb::TransferChannel::Unspecified => {
                    cx.link.abort_transfer(id, STOP_TRANSFER_REJECTED);
                    return;
                }
            };
            let refuse = !cx.allowed(kind)
                || active.len() >= MAX_CONCURRENT
                || active.contains_key(&id)
                || (kind == TransferKind::Clipboard && !rates.clip.allow(Instant::now()))
                || (kind == TransferKind::File
                    && (header.size > cx.max_file_bytes || !rates.file.allow(Instant::now())));
            if refuse {
                cx.link.abort_transfer(id, STOP_TRANSFER_REJECTED);
                return;
            }
            // A new clipboard replaces the previous one: the link client reports the old one as
            // `Aborted`, which closes its client stream.
            match tokio::time::timeout(OPEN_TIMEOUT, cx.conn.open_transfer(kind, header)).await {
                Ok(Ok(sender)) => {
                    active.insert(id, Out { sender, kind });
                }
                _ => cx.link.abort_transfer(id, STOP_TRANSFER_REJECTED),
            }
        }
        TransferEvent::Data(chunk) => {
            let Some(o) = active.get_mut(&chunk.id) else {
                // Not (or no longer) ours: the chunk's credit is released when it drops.
                return;
            };
            let ok = matches!(
                tokio::time::timeout(IDLE, o.sender.write(&chunk.data)).await,
                Ok(Ok(()))
            );
            if !ok && let Some(o) = active.remove(&chunk.id) {
                o.sender.abort();
                cx.link.abort_transfer(chunk.id, RESET_TRANSFER_ERROR);
            }
        }
        TransferEvent::End { id } => {
            if let Some(o) = active.remove(&id) {
                // Finishing waits for the client to have read the body: not in this task.
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(IDLE, o.sender.finish()).await;
                });
            }
        }
        TransferEvent::Aborted { id, .. } => {
            if let Some(o) = active.remove(&id) {
                o.sender.abort();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // The transfer paths are exercised end to end in `tests/relay_e2e.rs`; the inbox bound needs
    // a link client, which needs a session, so it is covered there too (a hostile session that
    // floods transfer events).
    use super::*;

    #[test]
    fn inbox_starts_empty() {
        assert_eq!(Inbox::default().len(), 0);
    }
}
