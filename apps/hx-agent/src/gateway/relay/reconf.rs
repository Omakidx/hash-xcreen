//! `ViewConfig` to `reconfigure`, coalesced.
//!
//! A client may send a `ViewConfig` as often as it likes (each replaces the previous one), but
//! every `reconfigure` costs the session a message of its `ctl` budget and a command for its
//! engine. The relay therefore forwards at most 10 a second: changes that arrive within 100 ms
//! of the last one are merged (latest wins, a zero numeric field keeps the earlier value, as in
//! the protocol) and sent together when the interval is over. The last change is never lost.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hx_ipc::link::pb;

use super::util::lock;
use crate::link::LinkClient;

/// The shortest time between two `reconfigure` messages.
pub(super) const MIN_GAP: Duration = Duration::from_millis(100);

/// `newer` on top of `older`: a non-zero numeric field replaces the old value (zero keeps it), a
/// size needs both sides, the booleans are taken as given.
pub(super) fn merge(older: pb::StreamConfig, newer: pb::StreamConfig) -> pb::StreamConfig {
    let pick = |o: u32, n: u32| if n != 0 { n } else { o };
    let size = newer.width != 0 && newer.height != 0;
    pb::StreamConfig {
        codec: if newer.codec != 0 {
            newer.codec
        } else {
            older.codec
        },
        max_fps: pick(older.max_fps, newer.max_fps),
        bitrate_cap_kbps: pick(older.bitrate_cap_kbps, newer.bitrate_cap_kbps),
        width: if size { newer.width } else { older.width },
        height: if size { newer.height } else { older.height },
        scale_percent: pick(older.scale_percent, newer.scale_percent),
        audio_enabled: newer.audio_enabled,
        clipboard_enabled: newer.clipboard_enabled,
        file_transfer_enabled: newer.file_transfer_enabled,
    }
}

/// What to do with a change that arrives at `now`.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Plan {
    /// Send it now.
    Now,
    /// A flush is already waiting: only merge.
    Merge,
    /// Arm a flush in this long.
    After(Duration),
}

pub(super) fn plan(last: Option<Instant>, armed: bool, now: Instant) -> Plan {
    if armed {
        return Plan::Merge;
    }
    match last {
        Some(t) if now.saturating_duration_since(t) < MIN_GAP => {
            Plan::After(MIN_GAP - now.saturating_duration_since(t))
        }
        _ => Plan::Now,
    }
}

#[derive(Default)]
struct State {
    pending: Option<pb::StreamConfig>,
    last: Option<Instant>,
    armed: bool,
}

/// The coalescer of one client.
pub(super) struct Reconf {
    link: LinkClient,
    state: Mutex<State>,
    closed: AtomicBool,
    /// `reconfigure` messages sent.
    pub(super) sent: AtomicU64,
}

impl Reconf {
    pub(super) fn new(link: LinkClient) -> Arc<Self> {
        Arc::new(Self {
            link,
            state: Mutex::new(State::default()),
            closed: AtomicBool::new(false),
            sent: AtomicU64::new(0),
        })
    }

    /// Stops sending (the client was detached).
    pub(super) fn close(&self) {
        self.closed.store(true, Relaxed);
        lock(&self.state).pending = None;
    }

    pub(super) fn push(self: &Arc<Self>, cfg: pb::StreamConfig) {
        if self.closed.load(Relaxed) {
            return;
        }
        let now = Instant::now();
        let action = {
            let mut s = lock(&self.state);
            s.pending = Some(match s.pending.take() {
                Some(old) => merge(old, cfg),
                None => cfg,
            });
            let p = plan(s.last, s.armed, now);
            if let Plan::After(_) = p {
                s.armed = true;
            }
            p
        };
        match action {
            Plan::Now => self.flush(),
            Plan::Merge => {}
            Plan::After(wait) => {
                let me = self.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(wait).await;
                    me.flush();
                });
            }
        }
    }

    fn flush(&self) {
        let cfg = {
            let mut s = lock(&self.state);
            s.armed = false;
            s.last = Some(Instant::now());
            s.pending.take()
        };
        if let Some(cfg) = cfg
            && !self.closed.load(Relaxed)
        {
            self.sent.fetch_add(1, Relaxed);
            if let Err(e) = self.link.reconfigure(cfg) {
                tracing::debug!(error = %e, "reconfigure was not queued");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_most_one_every_100_ms_and_the_last_change_is_kept() {
        let t0 = Instant::now();
        assert_eq!(plan(None, false, t0), Plan::Now);
        let ms = |n| t0 + Duration::from_millis(n);
        assert_eq!(
            plan(Some(t0), false, ms(30)),
            Plan::After(Duration::from_millis(70))
        );
        assert_eq!(plan(Some(t0), true, ms(40)), Plan::Merge);
        assert_eq!(plan(Some(t0), false, ms(100)), Plan::Now);
    }

    #[test]
    fn merging_keeps_earlier_values_for_zero_fields() {
        let a = pb::StreamConfig {
            max_fps: 30,
            width: 800,
            height: 600,
            clipboard_enabled: true,
            ..Default::default()
        };
        let b = pb::StreamConfig {
            bitrate_cap_kbps: 2_000,
            ..Default::default()
        };
        let m = merge(a, b);
        assert_eq!((m.max_fps, m.bitrate_cap_kbps, m.width), (30, 2_000, 800));
        assert!(!m.clipboard_enabled, "booleans as given by the newer one");
    }
}
