//! Sample collection, percentile maths, histogram and the JSON summary.

use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Instant;

/// Bucket upper bounds (ms) for the frame-interval histogram shown in the UI.
pub const HIST_EDGES_MS: [f64; 7] = [14.0, 15.5, 17.5, 20.0, 25.0, 33.4, 50.0];

#[derive(Default)]
pub struct Samples {
    /// Decoder: packet sent -> frame received (ms).
    pub decode_ms: Vec<f64>,
    /// Software colour conversion in the decoder thread (path c only) (ms).
    pub convert_ms: Vec<f64>,
    /// decode complete -> frame handed to Slint (image property set) (ms).
    pub handoff_ms: Vec<f64>,
    /// Time spent in our own upload/import/convert code (ms).
    pub prepare_ms: Vec<f64>,
    /// Slint render: BeforeRendering -> AfterRendering of the frame that showed the video (ms).
    pub render_ms: Vec<f64>,
    /// decode complete -> AfterRendering of the first render that showed it (ms).
    pub decode_to_render_ms: Vec<f64>,
    /// Interval between consecutive *new video frames* being rendered (ms).
    pub present_interval_ms: Vec<f64>,
    /// Interval between consecutive renders of any kind (ms).
    pub render_interval_ms: Vec<f64>,
    /// UI event (synthetic click) -> next AfterRendering (ms).
    pub event_to_render_ms: Vec<f64>,
    /// Timer-based event-loop lag: actual minus scheduled fire time (ms).
    pub loop_lag_ms: Vec<f64>,
    pub frames_decoded: u64,
    pub frames_presented: u64,
    /// Decoded frames replaced in the mailbox before they were rendered.
    pub frames_dropped: u64,
    /// Frames whose decode started more than half a frame after their 1/fps schedule slot.
    pub decoder_late: u64,
}

pub struct Stats {
    pub inner: Mutex<Samples>,
}

impl Stats {
    pub fn new() -> Self {
        Self { inner: Mutex::new(Samples::default()) }
    }
    pub fn with<R>(&self, f: impl FnOnce(&mut Samples) -> R) -> R {
        f(&mut self.inner.lock().unwrap())
    }
    pub fn reset(&self) {
        *self.inner.lock().unwrap() = Samples::default();
    }
}

#[derive(Serialize, Clone, Default)]
pub struct Dist {
    pub n: usize,
    pub mean: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub max: f64,
}

pub fn dist(v: &[f64]) -> Dist {
    if v.is_empty() {
        return Dist::default();
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pick = |q: f64| s[(((s.len() - 1) as f64) * q).round() as usize];
    Dist {
        n: s.len(),
        mean: s.iter().sum::<f64>() / s.len() as f64,
        p50: pick(0.50),
        p95: pick(0.95),
        p99: pick(0.99),
        max: *s.last().unwrap(),
    }
}

pub fn histogram(v: &[f64]) -> Vec<u32> {
    let mut h = vec![0u32; HIST_EDGES_MS.len() + 1];
    for &x in v {
        let i = HIST_EDGES_MS.iter().position(|&e| x < e).unwrap_or(HIST_EDGES_MS.len());
        h[i] += 1;
    }
    h
}

/// Standard deviation of the present intervals = frame-pacing jitter.
pub fn stddev(v: &[f64]) -> f64 {
    if v.len() < 2 {
        return 0.0;
    }
    let m = v.iter().sum::<f64>() / v.len() as f64;
    (v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (v.len() - 1) as f64).sqrt()
}

#[derive(Serialize)]
pub struct CpuUsage {
    /// Process CPU seconds (user+system) divided by wall seconds, i.e. cores busy.
    pub process_cores: f64,
    pub user_s: f64,
    pub system_s: f64,
    /// CPU cores busy per thread name (comm), top entries.
    pub per_thread_cores: BTreeMap<String, f64>,
}

#[derive(Clone, Default)]
pub struct CpuSnapshot {
    pub at: Option<Instant>,
    pub user: f64,
    pub system: f64,
    pub threads: BTreeMap<String, f64>,
}

fn clk_tck() -> f64 {
    // SAFETY: sysconf is always safe to call.
    let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if t > 0 { t as f64 } else { 100.0 }
}

fn parse_stat(s: &str) -> Option<(String, f64, f64)> {
    // comm may contain spaces/parens: it is wrapped in the outermost parentheses.
    let l = s.find('(')?;
    let r = s.rfind(')')?;
    let comm = s[l + 1..r].to_string();
    let rest: Vec<&str> = s[r + 2..].split_whitespace().collect();
    // After comm: state(0) ... utime is field 14 overall => index 11 here, stime index 12.
    let ut: f64 = rest.get(11)?.parse().ok()?;
    let st: f64 = rest.get(12)?.parse().ok()?;
    Some((comm, ut / clk_tck(), st / clk_tck()))
}

pub fn cpu_snapshot() -> CpuSnapshot {
    let mut snap = CpuSnapshot { at: Some(Instant::now()), ..Default::default() };
    if let Ok(s) = std::fs::read_to_string("/proc/self/stat")
        && let Some((_, u, sy)) = parse_stat(&s)
    {
        snap.user = u;
        snap.system = sy;
    }
    if let Ok(rd) = std::fs::read_dir("/proc/self/task") {
        for e in rd.flatten() {
            if let Ok(s) = std::fs::read_to_string(e.path().join("stat"))
                && let Some((comm, u, sy)) = parse_stat(&s)
            {
                *snap.threads.entry(comm).or_insert(0.0) += u + sy;
            }
        }
    }
    snap
}

pub fn cpu_usage(a: &CpuSnapshot, b: &CpuSnapshot) -> CpuUsage {
    let wall = b.at.unwrap().duration_since(a.at.unwrap()).as_secs_f64().max(1e-9);
    let mut per = BTreeMap::new();
    for (k, v) in &b.threads {
        let d = v - a.threads.get(k).copied().unwrap_or(0.0);
        if d / wall >= 0.005 {
            per.insert(k.clone(), round3(d / wall));
        }
    }
    CpuUsage {
        process_cores: round3(((b.user - a.user) + (b.system - a.system)) / wall),
        user_s: round3(b.user - a.user),
        system_s: round3(b.system - a.system),
        per_thread_cores: per,
    }
}

pub fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

pub fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .map(|s| s.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
        .unwrap_or_default()
}
