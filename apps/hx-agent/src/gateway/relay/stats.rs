//! Statistics: what the gateway tells the session about the path (`transport_stats`, about 4 per
//! second) and what it tells the client about the server (`ServerStats`, protocol 5.8, at most
//! 1 per second).
//!
//! `ServerStats` carries **numbers only**, built from the session's `SessionStats` (clamped to
//! the protocol's ranges, saturating) and the gateway's own transport numbers. Nothing the
//! session produced as text can reach it. It is sent only if the feature was negotiated and the
//! client's latest `ViewConfig` asked for it (`stats_enabled`); while it is off nothing is built.

use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hx_ipc::link::pb;
use hx_proto::channel::CloseCode;
use hx_proto::pb::{ControlMessage, control_message::Message as Ctl};
use hx_proto::version::Features;
use hx_transport::Connection;
use tokio::sync::watch;

use super::util::lock;
use super::video::VideoShared;
use crate::link::LinkClient;

const TICK: Duration = Duration::from_millis(250);
/// `ServerStats` at most this often (protocol 5.8: one per second).
const SERVER_STATS_EVERY: Duration = Duration::from_millis(950);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// The session's latest statistics and the client's switch.
#[derive(Default)]
pub(super) struct StatsShared {
    session: Mutex<Option<pb::SessionStats>>,
    /// The client's latest `ViewConfig.stats_enabled`.
    pub(super) on: AtomicBool,
}

impl StatsShared {
    pub(super) fn set_session(&self, s: pb::SessionStats) {
        *lock(&self.session) = Some(s);
    }

    fn take(&self) -> Option<pb::SessionStats> {
        lock(&self.session).take()
    }
}

fn sat(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// `ServerStats` from the session's interval statistics and the gateway's numbers. Every field is
/// within the protocol's range whatever the session said.
pub(super) fn build_server_stats(
    s: &pb::SessionStats,
    rtt_us: u32,
    dropped_frames: u32,
) -> hx_proto::pb::ServerStats {
    let interval_ms = s
        .interval_ms
        .clamp(1, hx_proto::channel::MAX_STATS_INTERVAL_MS);
    hx_proto::pb::ServerStats {
        interval_ms,
        frames: s.frames,
        keyframes: s.keyframes,
        dropped_frames,
        // bytes * 8 bits / interval_ms = kbit/s.
        bitrate_kbps: sat(s.bytes.saturating_mul(8) / u64::from(interval_ms)),
        target_bitrate_kbps: s.target_bitrate_kbps,
        fps_ceiling: s.fps_ceiling.min(240),
        encode_p95_us: s.encode_p95_us,
        total_p95_us: s.total_p95_us,
        queue_depth_max: s.queue_depth_max,
        rtt_us,
    }
}

/// The statistics task of one client.
pub(super) async fn run(
    conn: Connection,
    link: LinkClient,
    video: Arc<VideoShared>,
    stats: Arc<StatsShared>,
    features: Features,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_bytes = 0u64;
    let mut last_at = Instant::now();
    let mut last_server_stats: Option<Instant> = None;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            _ = tick.tick() => {}
        }
        let now = Instant::now();
        let rtt_us = conn
            .stats()
            .rtt
            .map_or(0, |d| sat(u64::try_from(d.as_micros()).unwrap_or(u64::MAX)));
        let bytes = video.delivered_bytes.load(Relaxed);
        let ms = u64::try_from(now.saturating_duration_since(last_at).as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let kbps = sat(bytes.saturating_sub(last_bytes).saturating_mul(8) / ms);
        last_bytes = bytes;
        last_at = now;
        if link.transport_stats(rtt_us, kbps).is_err() {
            return;
        }
        if !features.contains(Features::SERVER_STATS) || !stats.on.load(Relaxed) {
            // Nothing is built while the overlay is off.
            stats.take();
            continue;
        }
        if last_server_stats.is_some_and(|t| now.saturating_duration_since(t) < SERVER_STATS_EVERY)
        {
            continue;
        }
        let Some(session) = stats.take() else {
            continue;
        };
        let dropped = video.dropped.swap(0, Relaxed);
        let m = ControlMessage::new(Ctl::ServerStats(build_server_stats(
            &session, rtt_us, dropped,
        )));
        last_server_stats = Some(now);
        match tokio::time::timeout(WRITE_TIMEOUT, conn.send_control(&m)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return,
            Err(_) => {
                let c = conn.clone();
                tokio::spawn(async move { c.close(CloseCode::Busy, "not reading").await });
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_stats_are_numeric_and_clamped_whatever_the_session_says() {
        let s = pb::SessionStats {
            interval_ms: 0,
            frames: 60,
            keyframes: 2,
            bytes: u64::MAX,
            fps_ceiling: 100_000,
            target_bitrate_kbps: 4_000,
            encode_p95_us: 1_500,
            total_p95_us: 9_000,
            queue_depth_max: 3,
            ..Default::default()
        };
        let o = build_server_stats(&s, 12_000, 4);
        assert_eq!(o.interval_ms, 1, "zero is raised into the protocol's range");
        assert_eq!(o.fps_ceiling, 240);
        assert_eq!(o.bitrate_kbps, u32::MAX, "saturates");
        assert_eq!((o.frames, o.keyframes, o.dropped_frames), (60, 2, 4));
        assert_eq!(o.rtt_us, 12_000);
        let s = pb::SessionStats {
            interval_ms: 1_000,
            bytes: 500_000,
            ..Default::default()
        };
        assert_eq!(build_server_stats(&s, 0, 0).bitrate_kbps, 4_000);
        let s = pb::SessionStats {
            interval_ms: 9_000_000,
            ..Default::default()
        };
        assert_eq!(build_server_stats(&s, 0, 0).interval_ms, 60_000);
    }
}
