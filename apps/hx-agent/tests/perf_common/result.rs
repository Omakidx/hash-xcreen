//! What a run reports, the pure functions that judge it, and the JSON the macro run writes.
//!
//! Everything here is plain data and arithmetic, so the thresholds are unit-tested without a
//! network namespace, an X server or a gateway.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use super::net::{Control, Profile};

/// Nearest-rank percentile of `v` (not sorted), `p` in 0..=100. `None` for an empty slice.
pub fn percentile(v: &[f64], p: f64) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let rank = ((p / 100.0) * s.len() as f64).ceil().max(1.0) as usize;
    Some(s[rank.min(s.len()) - 1])
}

/// Latency of the marked input events of one phase, in milliseconds (input sent to the decoded
/// picture that shows it).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Latency {
    pub events: u32,
    pub seen: u32,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub max: f64,
}

impl Latency {
    pub fn from_samples(events: u32, samples: &[f64]) -> Latency {
        Latency {
            events,
            seen: samples.len() as u32,
            p50: percentile(samples, 50.0).unwrap_or(f64::NAN),
            p95: percentile(samples, 95.0).unwrap_or(f64::NAN),
            p99: percentile(samples, 99.0).unwrap_or(f64::NAN),
            max: percentile(samples, 100.0).unwrap_or(f64::NAN),
        }
    }
}

/// One measured window (typing, scrolling, idle).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Phase {
    pub name: String,
    pub secs: f64,
    pub frames: u64,
    pub key_frames: u64,
    /// Encoded video bytes the client received.
    pub video_bytes: u64,
    /// The longest silence between two frames while the phase was active, in ms.
    pub max_gap_ms: f64,
    pub decode_failures: u64,
    /// Non-key frames that did not follow their predecessor (the client then asks for a key frame).
    pub frame_gaps: u64,
    /// Bytes through the client's network interface (all protocol overhead included).
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    /// CPU of hx-session and hx-gatewayd over the window, in cores (filled by the orchestrator).
    pub session_cores: f64,
    pub gateway_cores: f64,
    pub latency: Option<Latency>,
}

impl Phase {
    pub fn cores(&self) -> f64 {
        self.session_cores + self.gateway_cores
    }
    pub fn net_kbit_s(&self) -> f64 {
        (self.net_rx_bytes + self.net_tx_bytes) as f64 * 8.0 / 1000.0 / self.secs.max(1e-9)
    }
    pub fn video_kbit_s(&self) -> f64 {
        self.video_bytes as f64 * 8.0 / 1000.0 / self.secs.max(1e-9)
    }
    pub fn net_bytes_s(&self) -> f64 {
        (self.net_rx_bytes + self.net_tx_bytes) as f64 / self.secs.max(1e-9)
    }
}

/// What the client side saw.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClientReport {
    pub pair_ms: f64,
    pub login_ms: f64,
    pub first_frame_ms: f64,
    pub stream: String,
    pub typing: Phase,
    pub scroll: Phase,
    pub idle: Phase,
    /// The decoded picture against the picture the server drew: share of pixels on the wrong
    /// side of the black/white threshold, and the contrast the decoder produced.
    pub mismatch_pct: f64,
    pub contrast: f64,
    pub final_matches: bool,
    pub disconnect_clean: bool,
    pub reconnect_ms: f64,
    pub reconnect_decoded: bool,
    /// Transport round trip measured by the connection itself after login (ms).
    pub transport_rtt_ms: f64,
    /// The server's once-a-second statistics as the client received them (diagnostics).
    pub server_stats: Vec<String>,
    /// The first frames of the stream as the client received them (diagnostics).
    pub first_frames: Vec<String>,
    /// For each frame gap: milliseconds until a key frame repaired the picture.
    pub gap_recovery_ms: Vec<f64>,
    /// Every key frame after the first, with whether it carries an IDR slice.
    pub key_frames: Vec<String>,
    pub errors: Vec<String>,
}

/// One profile's complete run.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RunResult {
    pub profile: String,
    pub rtt_ms: u32,
    pub control: Control,
    pub client: ClientReport,
    pub resolution: String,
    pub release_build: bool,
    pub loadavg_1m: f64,
    pub cpus: u32,
    /// Set when the host was busy during the run (load average above the CPU count / 2): the
    /// numbers are an upper bound and the strict latency gate is not applied.
    pub noisy: bool,
}

/// Thresholds. The LAN profile carries the Gate 1 numbers; the others are sanity bounds that say
/// "it works, it recovers, it does not stall", relative to the profile's round trip.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// p95 of the input-to-decoded-picture latency, ms.
    pub latency_p95_ms: f64,
    /// Cores of hx-session + hx-gatewayd while typing or scrolling (Gate 1: 1.5).
    pub active_cores: f64,
    /// Cores while idle (Gate 1: about 0).
    pub idle_cores: f64,
    /// Bytes per second through the interface while idle (Gate 1: about 0).
    pub idle_bytes_s: f64,
    /// Longest frame gap during typing or scrolling, ms.
    pub max_gap_ms: f64,
    /// Time to the first decoded frame after login, ms.
    pub first_frame_ms: f64,
}

pub const GATE1_LATENCY_P95_MS: f64 = 40.0;
pub const GATE1_ACTIVE_CORES: f64 = 1.5;
pub const GATE1_IDLE_CORES: f64 = 0.05;
pub const GATE1_IDLE_BYTES_S: f64 = 2048.0;

/// The limits for `p`. `strict` applies the Gate 1 latency to LAN; without it (a loaded
/// development host) the LAN latency bound is 4x, and the result says so.
pub fn limits(p: &Profile, strict: bool) -> Limits {
    limits_for(p, strict, true)
}

/// The Gate 1 CPU numbers are for release builds. A debug build runs the Rust parts of the
/// pipeline 2 to 3 times slower, so its CPU limits are doubled (it is a functional run, not a
/// measurement).
pub fn limits_for(p: &Profile, strict: bool, release: bool) -> Limits {
    let cpu = if release { 1.0 } else { 2.0 };
    let rtt = f64::from(p.rtt_ms);
    let lan = p.name == "lan";
    let latency = match p.name {
        "lan" if strict => GATE1_LATENCY_P95_MS,
        "lan" => GATE1_LATENCY_P95_MS * 4.0,
        // Network plus the pipeline plus one retransmission round or two; a bound that catches
        // a stall, not a number to tune.
        "broadband" => rtt + 120.0,
        _ => rtt * 4.0 + 600.0,
    };
    Limits {
        latency_p95_ms: latency,
        active_cores: GATE1_ACTIVE_CORES * cpu,
        idle_cores: GATE1_IDLE_CORES * cpu,
        idle_bytes_s: GATE1_IDLE_BYTES_S,
        max_gap_ms: if lan { 1000.0 } else { 2500.0 },
        first_frame_ms: if lan { 15_000.0 } else { 20_000.0 },
    }
}

/// Every violated bound, as a sentence. Empty: the run passes.
pub fn evaluate(r: &RunResult, p: &Profile, strict: bool) -> Vec<String> {
    let lim = limits_for(p, strict, r.release_build);
    let c = &r.client;
    let mut f = Vec::new();
    f.extend(
        r.control
            .notes
            .iter()
            .filter(|n| n.starts_with("FAIL"))
            .cloned(),
    );
    f.extend(c.errors.iter().map(|e| format!("client error: {e}")));
    if c.first_frame_ms <= 0.0 || c.first_frame_ms > lim.first_frame_ms {
        f.push(format!(
            "first frame after {:.0} ms (limit {:.0})",
            c.first_frame_ms, lim.first_frame_ms
        ));
    }
    for ph in [&c.typing, &c.scroll] {
        match &ph.latency {
            None => f.push(format!("{}: no latency measured", ph.name)),
            Some(l) => {
                if l.seen < l.events {
                    f.push(format!(
                        "{}: {} of {} input events never showed up on screen",
                        ph.name,
                        l.events - l.seen,
                        l.events
                    ));
                }
                // NaN (no sample at all) fails too.
                if l.p95.is_nan() || l.p95 > lim.latency_p95_ms {
                    f.push(format!(
                        "{}: p95 latency {:.1} ms exceeds {:.0} ms",
                        ph.name, l.p95, lim.latency_p95_ms
                    ));
                }
            }
        }
        if ph.cores() > lim.active_cores {
            f.push(format!(
                "{}: {:.2} cores exceeds {:.2}",
                ph.name,
                ph.cores(),
                lim.active_cores
            ));
        }
        if ph.max_gap_ms > lim.max_gap_ms {
            f.push(format!(
                "{}: the video stalled for {:.0} ms (limit {:.0})",
                ph.name, ph.max_gap_ms, lim.max_gap_ms
            ));
        }
        if ph.frames == 0 {
            f.push(format!("{}: no frames", ph.name));
        }
        if p.rate_mbit > 0 && ph.net_kbit_s() > f64::from(p.rate_mbit) * 1000.0 {
            f.push(format!(
                "{}: {:.0} kbit/s through a {} Mbit/s link",
                ph.name,
                ph.net_kbit_s(),
                p.rate_mbit
            ));
        }
    }
    if c.idle.cores() > lim.idle_cores {
        f.push(format!(
            "idle: {:.3} cores exceeds {:.3}",
            c.idle.cores(),
            lim.idle_cores
        ));
    }
    if c.idle.net_bytes_s() > lim.idle_bytes_s {
        f.push(format!(
            "idle: {:.0} bytes/s exceeds {:.0}",
            c.idle.net_bytes_s(),
            lim.idle_bytes_s
        ));
    }
    if !c.final_matches {
        f.push(format!(
            "the decoded picture does not match the desktop ({:.2}% of pixels wrong, contrast {:.0})",
            c.mismatch_pct, c.contrast
        ));
    }
    if !c.disconnect_clean {
        f.push("the disconnect was not clean".into());
    }
    if !c.reconnect_decoded {
        f.push("no decodable frame after reconnecting".into());
    }
    f
}

/// Black/white comparison of a decoded luma plane against the server's mask (255 white, 0 black).
/// Returns (share of mismatching pixels in percent, contrast = mean luma of white pixels minus
/// mean luma of black pixels). The threshold is the midpoint of the two means, so the decoder's
/// colour range does not matter.
pub fn compare(luma: &[u8], mask: &[u8]) -> Option<(f64, f64)> {
    if luma.len() != mask.len() || luma.is_empty() {
        return None;
    }
    let (mut sw, mut nw, mut sb, mut nb) = (0u64, 0u64, 0u64, 0u64);
    for (&l, &m) in luma.iter().zip(mask) {
        if m > 127 {
            sw += u64::from(l);
            nw += 1;
        } else {
            sb += u64::from(l);
            nb += 1;
        }
    }
    if nw == 0 || nb == 0 {
        return None;
    }
    let (yw, yb) = (sw as f64 / nw as f64, sb as f64 / nb as f64);
    let thr = (yw + yb) / 2.0;
    let bad = luma
        .iter()
        .zip(mask)
        .filter(|&(&l, &m)| (f64::from(l) > thr) != (m > 127))
        .count();
    Some((bad as f64 * 100.0 / luma.len() as f64, yw - yb))
}

/// The aggregate of a repeated LAN run: what `perf/check.py` compares to the baseline.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Macro {
    pub runs: u32,
    pub resolution: String,
    pub release_build: bool,
    pub noisy: bool,
    pub loadavg_1m: f64,
    pub cpus: u32,
    pub metrics: std::collections::BTreeMap<String, f64>,
    pub per_run: Vec<RunResult>,
}

fn median(v: &[f64]) -> f64 {
    percentile(v, 50.0).unwrap_or(f64::NAN)
}

/// Aggregates LAN runs. Latency and CPU metrics are the **median across runs** of each run's
/// p95 / cores (one noisy run does not move them), `*_worst` the worst run.
pub fn aggregate(runs: Vec<RunResult>) -> Macro {
    let pick = |f: &dyn Fn(&RunResult) -> f64| -> Vec<f64> { runs.iter().map(f).collect() };
    let mut m = std::collections::BTreeMap::new();
    let lat = |r: &RunResult, ph: &Phase| {
        ph.latency.as_ref().map_or(f64::NAN, |l| {
            let _ = r;
            l.p95
        })
    };
    let typing_p95 = pick(&|r| lat(r, &r.client.typing));
    let scroll_p95 = pick(&|r| lat(r, &r.client.scroll));
    let typing_p50 = pick(&|r| r.client.typing.latency.as_ref().map_or(f64::NAN, |l| l.p50));
    let scroll_p50 = pick(&|r| r.client.scroll.latency.as_ref().map_or(f64::NAN, |l| l.p50));
    let worst = |v: &[f64]| v.iter().copied().fold(f64::MIN, f64::max);
    m.insert("typing_latency_p95_ms".into(), median(&typing_p95));
    m.insert("typing_latency_p95_ms_worst".into(), worst(&typing_p95));
    m.insert("typing_latency_p50_ms".into(), median(&typing_p50));
    m.insert("scroll_latency_p95_ms".into(), median(&scroll_p95));
    m.insert("scroll_latency_p95_ms_worst".into(), worst(&scroll_p95));
    m.insert("scroll_latency_p50_ms".into(), median(&scroll_p50));
    let tc = pick(&|r| r.client.typing.cores());
    let sc = pick(&|r| r.client.scroll.cores());
    let ic = pick(&|r| r.client.idle.cores());
    m.insert("typing_cores".into(), median(&tc));
    m.insert("typing_cores_worst".into(), worst(&tc));
    m.insert("scroll_cores".into(), median(&sc));
    m.insert("scroll_cores_worst".into(), worst(&sc));
    m.insert("idle_cores".into(), median(&ic));
    m.insert("idle_cores_worst".into(), worst(&ic));
    let ib = pick(&|r| r.client.idle.net_bytes_s());
    m.insert("idle_bytes_per_s".into(), median(&ib));
    m.insert("idle_bytes_per_s_worst".into(), worst(&ib));
    m.insert(
        "typing_kbit_s".into(),
        median(&pick(&|r| r.client.typing.net_kbit_s())),
    );
    m.insert(
        "scroll_kbit_s".into(),
        median(&pick(&|r| r.client.scroll.net_kbit_s())),
    );
    m.insert(
        "first_frame_ms".into(),
        median(&pick(&|r| r.client.first_frame_ms)),
    );
    m.insert("pair_ms".into(), median(&pick(&|r| r.client.pair_ms)));
    m.insert("login_ms".into(), median(&pick(&|r| r.client.login_ms)));
    m.insert(
        "mismatch_pct_worst".into(),
        worst(&pick(&|r| r.client.mismatch_pct)),
    );
    let first = runs.first();
    Macro {
        runs: runs.len() as u32,
        resolution: first.map(|r| r.resolution.clone()).unwrap_or_default(),
        release_build: first.is_some_and(|r| r.release_build),
        noisy: runs.iter().any(|r| r.noisy),
        loadavg_1m: first.map_or(0.0, |r| r.loadavg_1m),
        cpus: first.map_or(0, |r| r.cpus),
        metrics: m,
        per_run: runs,
    }
}

#[cfg(test)]
mod tests {
    use super::super::net::{BROADBAND, LAN, LOSSY, MOBILE};
    use super::*;

    #[test]
    fn percentile_is_nearest_rank() {
        let v: Vec<f64> = (1..=100).map(f64::from).collect();
        assert_eq!(percentile(&v, 95.0), Some(95.0));
        assert_eq!(percentile(&v, 50.0), Some(50.0));
        assert_eq!(percentile(&v, 100.0), Some(100.0));
        assert_eq!(percentile(&[7.0], 95.0), Some(7.0));
        assert_eq!(percentile(&[], 95.0), None);
    }

    fn good() -> RunResult {
        let lat = |p95| {
            Some(Latency {
                events: 60,
                seen: 60,
                p50: 10.0,
                p95,
                p99: p95,
                max: p95,
            })
        };
        let ph = |name: &str, p95, cores| Phase {
            name: name.into(),
            secs: 5.0,
            frames: 100,
            max_gap_ms: 150.0,
            session_cores: cores,
            gateway_cores: 0.1,
            latency: lat(p95),
            ..Phase::default()
        };
        RunResult {
            profile: "lan".into(),
            rtt_ms: 1,
            release_build: true,
            client: ClientReport {
                first_frame_ms: 800.0,
                typing: ph("typing", 20.0, 0.4),
                scroll: ph("scroll", 25.0, 0.6),
                idle: Phase {
                    name: "idle".into(),
                    secs: 10.0,
                    net_rx_bytes: 200,
                    net_tx_bytes: 200,
                    session_cores: 0.01,
                    ..Phase::default()
                },
                final_matches: true,
                disconnect_clean: true,
                reconnect_decoded: true,
                ..ClientReport::default()
            },
            ..RunResult::default()
        }
    }

    #[test]
    fn a_good_lan_run_passes_the_gate() {
        assert_eq!(evaluate(&good(), &LAN, true), Vec::<String>::new());
    }

    #[test]
    fn the_gate_1_numbers_fail_a_lan_run_that_misses_them() {
        let mut r = good();
        r.client.typing.latency.as_mut().unwrap().p95 = 41.0;
        assert!(
            evaluate(&r, &LAN, true)
                .iter()
                .any(|s| s.contains("typing: p95"))
        );
        // On a loaded development host the bound is 4x: 41 ms passes, 161 ms does not.
        assert!(evaluate(&r, &LAN, false).is_empty());
        r.client.typing.latency.as_mut().unwrap().p95 = 161.0;
        assert!(!evaluate(&r, &LAN, false).is_empty());

        let mut r = good();
        r.client.scroll.session_cores = 1.45;
        assert!(
            evaluate(&r, &LAN, true)
                .iter()
                .any(|s| s.contains("scroll") && s.contains("cores"))
        );

        let mut r = good();
        r.client.idle.session_cores = 0.2;
        assert!(
            evaluate(&r, &LAN, true)
                .iter()
                .any(|s| s.starts_with("idle"))
        );
        let mut r = good();
        r.client.idle.net_rx_bytes = 100_000;
        assert!(
            evaluate(&r, &LAN, true)
                .iter()
                .any(|s| s.contains("bytes/s"))
        );
    }

    #[test]
    fn a_debug_build_gets_twice_the_cpu_but_the_same_latency_gate() {
        let mut r = good();
        r.release_build = false;
        r.client.scroll.session_cores = 1.6;
        assert!(
            evaluate(&r, &LAN, true).is_empty(),
            "{:?}",
            evaluate(&r, &LAN, true)
        );
        r.client.scroll.session_cores = 3.0;
        assert!(!evaluate(&r, &LAN, true).is_empty());
        r.client.scroll.session_cores = 0.4;
        r.client.typing.latency.as_mut().unwrap().p95 = 41.0;
        assert!(!evaluate(&r, &LAN, true).is_empty());
    }

    #[test]
    fn missing_events_a_stall_and_a_wrong_picture_fail_every_profile() {
        for p in [LAN, BROADBAND, LOSSY, MOBILE] {
            let mut r = good();
            r.client.typing.latency.as_mut().unwrap().seen = 58;
            assert!(
                evaluate(&r, &p, true)
                    .iter()
                    .any(|s| s.contains("never showed"))
            );
            let mut r = good();
            r.client.scroll.max_gap_ms = 9000.0;
            assert!(evaluate(&r, &p, true).iter().any(|s| s.contains("stalled")));
            let mut r = good();
            r.client.final_matches = false;
            assert!(
                evaluate(&r, &p, true)
                    .iter()
                    .any(|s| s.contains("does not match"))
            );
        }
    }

    #[test]
    fn other_profiles_get_sanity_bounds_scaled_to_their_round_trip() {
        assert!(limits(&BROADBAND, true).latency_p95_ms < limits(&LOSSY, true).latency_p95_ms);
        assert!(limits(&LOSSY, true).latency_p95_ms < limits(&MOBILE, true).latency_p95_ms);
        // Strictness only changes LAN.
        assert_eq!(
            limits(&MOBILE, true).latency_p95_ms,
            limits(&MOBILE, false).latency_p95_ms
        );
        assert_eq!(limits(&LAN, true).latency_p95_ms, 40.0);
    }

    #[test]
    fn compare_finds_wrong_pixels_regardless_of_the_luma_range() {
        let mask: Vec<u8> = (0..1000)
            .map(|i| if i % 2 == 0 { 255 } else { 0 })
            .collect();
        // Limited range: white 235, black 16.
        let luma: Vec<u8> = mask
            .iter()
            .map(|&m| if m > 127 { 235 } else { 16 })
            .collect();
        let (bad, contrast) = compare(&luma, &mask).unwrap();
        assert_eq!(bad, 0.0);
        assert_eq!(contrast, 219.0);
        let mut broken = luma.clone();
        for v in broken.iter_mut().take(100) {
            *v = 255 - *v;
        }
        assert!(compare(&broken, &mask).unwrap().0 > 5.0);
        assert!(compare(&luma[..10], &mask).is_none());
    }

    #[test]
    fn aggregate_takes_the_median_run_and_keeps_the_worst() {
        let mut runs = Vec::new();
        for p95 in [20.0, 22.0, 90.0] {
            let mut r = good();
            r.client.typing.latency.as_mut().unwrap().p95 = p95;
            runs.push(r);
        }
        let m = aggregate(runs);
        assert_eq!(m.metrics["typing_latency_p95_ms"], 22.0);
        assert_eq!(m.metrics["typing_latency_p95_ms_worst"], 90.0);
        assert_eq!(m.runs, 3);
    }
}
