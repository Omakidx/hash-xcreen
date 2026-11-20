use super::sim::{Content, Profile, run};
use super::*;

fn ms(n: u64) -> u64 {
    n * MS
}

fn delivered(frame: u32, bytes: usize, elapsed_ms: u64) -> FrameAck {
    FrameAck {
        frame_number: frame,
        bytes,
        elapsed: Duration::from_millis(elapsed_ms),
        outcome: AckOutcome::Delivered,
    }
}

fn ctl() -> CongestionController {
    CongestionController::new(CongestionConfig::default(), 0)
}

#[test]
fn starts_below_the_top_of_the_ladder() {
    let c = ctl();
    assert_eq!(c.kbps(), 4000);
    assert_eq!(c.fps(), 60);
    let init = c.initial_actions();
    assert_eq!(init.bitrate_kbps, Some(4000));
    assert_eq!(init.max_fps, Some(60));
}

#[test]
fn cap_shapes_the_ladder() {
    let c = CongestionController::new(
        CongestionConfig {
            cap: BandwidthCap::Mbps5,
            ..CongestionConfig::default()
        },
        0,
    );
    assert_eq!(c.ladder, vec![500, 1000, 1500, 2000, 3000, 4000, 5000]);
    let mut c = ctl();
    assert_eq!(*c.ladder.last().unwrap(), 20_000);
    // Lowering the cap clamps the rate immediately; Auto never exceeds 20 Mbit/s.
    c.level = c.ladder.len() - 1;
    let a = c.set_cap(BandwidthCap::Mbps10, 0);
    assert_eq!(a.bitrate_kbps, Some(10_000));
    assert_eq!(c.kbps(), 10_000);
    let a = c.set_cap(BandwidthCap::Mbps50, 0);
    assert!(a.is_empty());
    assert_eq!(BandwidthCap::from_mbps(25), Some(BandwidthCap::Mbps25));
    assert_eq!(BandwidthCap::from_mbps(7), None);
}

#[test]
fn fps_falls_with_the_rate() {
    assert_eq!(fps_for(500), 16);
    assert_eq!(fps_for(100), MIN_FPS);
    assert_eq!(fps_for(20_000), MAX_FPS);
    assert!(fps_for(1000) < fps_for(2000));
}

/// Feed `n` frames sent every 16 ms with a constant ack delay; returns the time after them.
fn feed(c: &mut CongestionController, mut t: u64, n: u32, first: u32, delay_ms: u64) -> u64 {
    for i in 0..n {
        c.on_frame_sent(ms(t), first + i, 1000);
        let a = c.on_frame_ack(ms(t + delay_ms), delivered(first + i, 1000, delay_ms));
        assert!(a.is_empty());
        t += 16;
    }
    t
}

#[test]
fn rising_ack_latency_steps_the_rate_down() {
    let mut c = ctl();
    let t = feed(&mut c, 1000, 20, 0, 20); // baseline 20 ms
    assert!(c.poll(ms(t)).is_empty());
    // Frames now take 120 ms: 100 ms of queueing, past the step-down threshold.
    let t = feed(&mut c, t, 10, 100, 120);
    let a = c.poll(ms(t + 200));
    assert_eq!(a.bitrate_kbps, Some(3000));
    assert!(a.cancel.is_empty() && !a.resync);
    assert_eq!(c.stats().step_downs, 1);
}

#[test]
fn jitter_raises_the_thresholds() {
    let mut calm = ctl();
    let mut jittery = ctl();
    for (c, spread) in [(&mut calm, 0u64), (&mut jittery, 60u64)] {
        let mut t = 1000;
        for i in 0..60u32 {
            let delay = 20 + if i % 2 == 0 { spread } else { 0 };
            c.on_frame_sent(ms(t), i, 1000);
            c.on_frame_ack(ms(t + delay), delivered(i, 1000, delay));
            t += 16;
        }
    }
    let (calm_down, calm_stale, _) = calm.thresholds();
    let (jit_down, jit_stale, _) = jittery.thresholds();
    assert_eq!(calm_down, 30 * MS);
    assert!(jit_down > 60 * MS && jit_down <= 120 * MS, "{jit_down}");
    assert!(jit_stale > calm_stale);
    // A 50 ms excess is congestion on the calm link and noise on the jittery one.
    for c in [&mut calm, &mut jittery] {
        let mut t = 1960;
        for i in 100..110u32 {
            c.on_frame_sent(ms(t), i, 1000);
            c.on_frame_ack(ms(t + 70), delivered(i, 1000, 70));
            t += 16;
        }
    }
    assert!(calm.poll(ms(2200)).bitrate_kbps.is_some());
    assert!(jittery.poll(ms(2200)).is_empty());
}

#[test]
fn stale_frames_are_cancelled_and_resynced() {
    let mut c = ctl();
    let t = feed(&mut c, 1000, 20, 0, 20);
    // Three frames go out and nothing is acked for far longer than the stale threshold.
    for i in 0..3u32 {
        c.on_frame_sent(ms(t + u64::from(i) * 16), 500 + i, 20_000);
    }
    assert!(c.poll(ms(t + 60)).is_empty(), "60 ms late is not stale yet");
    let a = c.poll(ms(t + 400));
    assert_eq!(a.cancel, vec![500, 501, 502]);
    assert!(a.resync);
    assert_eq!(a.bitrate_kbps, Some(2000), "two levels down");
    assert!(c.resync_pending());
    // Late acks for the cancelled frames are ignored.
    assert!(
        c.on_frame_ack(
            ms(t + 410),
            FrameAck {
                frame_number: 500,
                bytes: 20_000,
                elapsed: Duration::from_millis(410),
                outcome: AckOutcome::Cancelled,
            }
        )
        .is_empty()
    );
    // Frames encoded before the fresh IDR are not sent; the IDR carries RESYNC.
    assert_eq!(c.on_frame_ready(false), FrameDisposition::Drop);
    assert_eq!(
        c.on_frame_ready(true),
        FrameDisposition::Send { resync: true }
    );
    assert_eq!(
        c.on_frame_ready(false),
        FrameDisposition::Send { resync: false }
    );
    assert!(!c.resync_pending());
}

#[test]
fn transport_cancel_and_connection_loss() {
    let mut c = ctl();
    let t = feed(&mut c, 1000, 20, 0, 20);
    c.on_frame_sent(ms(t), 900, 1000);
    let a = c.on_frame_ack(
        ms(t + 300),
        FrameAck {
            frame_number: 900,
            bytes: 1000,
            elapsed: Duration::from_millis(300),
            outcome: AckOutcome::Rejected,
        },
    );
    assert!(a.resync);
    assert_eq!(a.bitrate_kbps, Some(3000));
    // Connection lost: back to the starting rate, resync armed, nothing in flight.
    c.on_frame_sent(ms(t + 301), 901, 1000);
    let a = c.on_frame_ack(
        ms(t + 302),
        FrameAck {
            frame_number: 901,
            bytes: 1000,
            elapsed: Duration::ZERO,
            outcome: AckOutcome::ConnectionLost,
        },
    );
    assert!(a.resync);
    assert_eq!(c.stats().in_flight, 0);
    assert!(c.kbps() <= INITIAL_KBPS);
    // Duplicate and unknown acks are harmless.
    assert!(c.on_frame_ack(ms(t + 303), delivered(901, 1, 1)).is_empty());
    assert!(
        c.on_frame_ack(ms(t + 303), delivered(4242, 1, 1))
            .is_empty()
    );
    let a = c.reset(ms(t + 400));
    assert!(a.resync);
    assert_eq!(a.bitrate_kbps, Some(4000));
}

#[test]
fn light_traffic_does_not_probe_upwards() {
    let mut c = ctl();
    let mut t = 1000;
    for no in 0..80 {
        c.on_frame_sent(ms(t), no, 1500);
        c.on_frame_ack(ms(t + 20), delivered(no, 1500, 20));
        t += 100;
        assert!(c.poll(ms(t)).bitrate_kbps.is_none());
    }
    assert_eq!(c.kbps(), 4000);
}

#[test]
fn idle_polling_is_slow_and_restores_the_start_rate() {
    let mut c = ctl();
    assert_eq!(c.next_poll(), Duration::from_millis(100));
    c.on_frame_sent(0, 1, 1000);
    assert_eq!(c.next_poll(), Duration::from_millis(5));
    c.on_frame_ack(ms(10), delivered(1, 1000, 10));
    c.level = 1;
    assert!(c.poll(ms(1000)).is_empty());
    let a = c.poll(ms(3000));
    assert_eq!(a.bitrate_kbps, Some(4000));
}

// ---- simulated links (S2-like profiles) ----

fn steady(name: &'static str, kbps: u32, rtt_ms: u64, jitter_ms: u64, loss: f64) -> Profile {
    Profile {
        name,
        bw: vec![(0, kbps)],
        rtt_ms,
        jitter_ms,
        loss,
    }
}

#[test]
fn sim_lan_reaches_the_top_quickly() {
    let p = steady("lan", 1_000_000, 2, 0, 0.0);
    let r = run(&p, BandwidthCap::Auto, Content::Busy, 12, 8);
    eprintln!("{}: {r:?}", p.name);
    assert_eq!(r.final_kbps, 20_000);
    assert!(
        r.kbps_per_s[..8].contains(&20_000),
        "ramp: {:?}",
        r.kbps_per_s
    );
    assert_eq!(r.cancels, 0, "no stale events on a clean fast link");
    assert!(r.max_backlog_ms < 50.0);
}

#[test]
fn sim_rtt150_loss_converges_without_queue_runaway() {
    // S2: 150 ms RTT, 10 Mbit/s, 1% loss. Uncontrolled it queued for 1.4 s; the spike's
    // controller settled near 3.5 Mbit/s. (p95 queue includes the retransmission round
    // trips, which are loss recovery, not queueing.)
    let p = steady("rtt150-loss", 10_000, 150, 5, 0.01);
    let r = run(&p, BandwidthCap::Auto, Content::Busy, 40, 15);
    eprintln!("{}: {r:?}", p.name);
    assert!(
        r.mean_sent_kbps > 3000.0 && r.mean_sent_kbps <= 10_500.0,
        "{r:?}"
    );
    assert!(r.max_backlog_ms < 600.0, "{r:?}");
    assert!(r.p95_queue_ms < 400.0, "{r:?}");
    assert!(r.mean_fps >= 24.0, "{r:?}");
}

#[test]
fn sim_jittery_mobile_link_is_not_throttled_to_nothing() {
    // S2 `mobile`: 40 ms plus 30 ms jitter, 0.5% loss, 20 Mbit/s. A fixed 40 ms threshold
    // sat at 0.3 to 0.6 Mbit/s.
    let p = steady("mobile", 20_000, 40, 30, 0.005);
    let r = run(&p, BandwidthCap::Auto, Content::Busy, 40, 15);
    eprintln!("{}: {r:?}", p.name);
    assert!(r.mean_target_kbps >= 5000.0, "{r:?}");
    assert!(r.max_backlog_ms < 400.0, "{r:?}");
    assert!(r.p95_queue_ms < 250.0, "{r:?}");
}

#[test]
fn sim_slow_link_settles_at_its_capacity() {
    let p = steady("dsl", 3000, 30, 2, 0.0);
    let r = run(&p, BandwidthCap::Auto, Content::Busy, 30, 10);
    eprintln!("{}: {r:?}", p.name);
    assert!(
        r.mean_sent_kbps > 1500.0 && r.mean_sent_kbps < 3300.0,
        "{r:?}"
    );
    assert!(r.max_backlog_ms < 400.0, "{r:?}");
    assert!(r.p95_queue_ms < 200.0, "{r:?}");
}

#[test]
fn sim_bandwidth_collapse_cancels_then_recovers_fast() {
    // 40 Mbit/s, collapses to 1.5 Mbit/s for 10 s, then returns.
    let p = Profile {
        name: "collapse",
        bw: vec![(0, 40_000), (10_000, 1500), (20_000, 40_000)],
        rtt_ms: 40,
        jitter_ms: 4,
        loss: 0.0,
    };
    let r = run(&p, BandwidthCap::Auto, Content::Busy, 40, 13);
    eprintln!("{}: {r:?}", p.name);
    assert!(
        r.cancels >= 1,
        "collapse must trigger the stale policy: {r:?}"
    );
    assert!(r.resyncs >= 1);
    assert!(r.max_backlog_ms < 1500.0, "queue bounded: {r:?}");
    // While constrained the rate is at or below the link; afterwards it is back near the top.
    let k = &r.kbps_per_s;
    assert!(k[14..19].iter().all(|v| *v <= 2000), "{k:?}");
    assert!(
        k[26] >= 10_000,
        "fast ramp-up within 6 s of recovery: {k:?}"
    );
    assert_eq!(*k.last().unwrap(), 20_000, "{k:?}");
}

#[test]
fn sim_bandwidth_cap_is_a_ceiling() {
    let p = steady("lan", 1_000_000, 2, 0, 0.0);
    for (cap, max) in [
        (BandwidthCap::Mbps5, 5000),
        (BandwidthCap::Mbps10, 10_000),
        (BandwidthCap::Mbps25, 25_000),
    ] {
        let r = run(&p, cap, Content::Busy, 15, 10);
        assert_eq!(r.max_kbps, max, "{cap:?}: {r:?}");
        assert_eq!(r.final_kbps, max);
    }
}

#[test]
fn sim_typing_traffic_stays_calm() {
    let p = steady("lan", 1_000_000, 2, 0, 0.0);
    let r = run(&p, BandwidthCap::Auto, Content::Light, 20, 5);
    assert_eq!(r.cancels, 0);
    assert_eq!(r.step_downs, 0);
    assert_eq!(r.max_kbps, 4000, "typing never probes: {r:?}");
}
