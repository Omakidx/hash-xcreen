//! A deterministic link simulator for the controller: a FIFO bottleneck with a bandwidth
//! schedule, round-trip time, jitter and loss (a loss costs one extra round trip), driven by
//! a source that behaves like the encoder (frame size follows the rate cap, frame rate
//! follows the ceiling, an IDR is several times larger). 1 ms resolution, fixed seed.

use super::*;

pub struct Profile {
    pub name: &'static str,
    /// (from ms, kbit/s): the bottleneck rate, piecewise constant.
    pub bw: Vec<(u64, u32)>,
    pub rtt_ms: u64,
    pub jitter_ms: u64,
    pub loss: f64,
}

impl Profile {
    fn kbps_at(&self, t: u64) -> u32 {
        self.bw
            .iter()
            .rev()
            .find(|(from, _)| *from <= t)
            .map_or(0, |(_, k)| *k)
    }
}

#[derive(Clone, Copy)]
pub enum Content {
    /// Scrolling, video: the encoder fills whatever rate it is given.
    Busy,
    /// Typing: small frames, a few per second.
    Light,
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

struct LinkFrame {
    no: u32,
    sent_ms: u64,
    bytes: usize,
    left: f64,
    ack_ms: Option<u64>,
}

#[derive(Default, Debug)]
pub struct Report {
    pub frames_sent: u64,
    pub frames_dropped_by_gate: u64,
    pub cancels: u64,
    pub resyncs: u64,
    pub step_downs: u64,
    pub final_kbps: u32,
    /// Largest unserved backlog at the bottleneck over the measured window, as time to drain.
    pub max_backlog_ms: f64,
    /// Mean sent payload rate over the measured window, kbit/s.
    pub mean_sent_kbps: f64,
    /// Mean target rate over the measured window.
    pub mean_target_kbps: f64,
    /// Mean fps over the measured window.
    pub mean_fps: f64,
    /// p95 of (ack delay - RTT) over the measured window, ms.
    pub p95_queue_ms: f64,
    /// Target rate each second.
    pub kbps_per_s: Vec<u32>,
    /// Peak target rate seen.
    pub max_kbps: u32,
}

/// Run `secs` seconds; statistics cover `from_s..secs`.
pub fn run(p: &Profile, cap: BandwidthCap, content: Content, secs: u64, from_s: u64) -> Report {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut c = CongestionController::new(
        CongestionConfig {
            cap,
            ..CongestionConfig::default()
        },
        0,
    );
    let mut kbps = c.kbps();
    let mut fps = c.fps();
    let mut link: VecDeque<LinkFrame> = VecDeque::new();
    let mut pending: Vec<LinkFrame> = Vec::new(); // serialised, waiting for the ack
    let mut next_no = 0u32;
    let mut next_idr = true;
    let mut last_emit = 0u64;
    let mut sent_bytes_window = 0u64;
    let mut target_sum = 0f64;
    let mut fps_sum = 0f64;
    let mut samples = 0u64;
    let mut queue_ms: Vec<f64> = Vec::new();
    let mut r = Report::default();
    let mut carry = 0f64;

    let apply = |a: &Actions,
                 kbps: &mut u32,
                 fps: &mut u32,
                 next_idr: &mut bool,
                 link: &mut VecDeque<LinkFrame>,
                 pending: &mut Vec<LinkFrame>| {
        if let Some(k) = a.bitrate_kbps {
            *kbps = k;
        }
        if let Some(f) = a.max_fps {
            *fps = f;
        }
        if a.resync {
            *next_idr = true;
        }
        if !a.cancel.is_empty() {
            link.retain(|f| !a.cancel.contains(&f.no));
            pending.retain(|f| !a.cancel.contains(&f.no));
        }
    };

    for t in 0..secs * 1000 {
        let now = t * MS;
        // Acks due now.
        let mut i = 0;
        while i < pending.len() {
            if pending[i].ack_ms.is_some_and(|a| a <= t) {
                let f = pending.swap_remove(i);
                let ack = FrameAck {
                    frame_number: f.no,
                    bytes: f.bytes,
                    elapsed: Duration::from_millis(t - f.sent_ms),
                    outcome: AckOutcome::Delivered,
                };
                if t >= from_s * 1000 {
                    queue_ms.push((t - f.sent_ms) as f64 - p.rtt_ms as f64);
                }
                let a = c.on_frame_ack(now, ack);
                apply(
                    &a,
                    &mut kbps,
                    &mut fps,
                    &mut next_idr,
                    &mut link,
                    &mut pending,
                );
            } else {
                i += 1;
            }
        }
        // Bottleneck.
        let bw = p.kbps_at(t);
        carry += f64::from(bw) * 1000.0 / 8.0 / 1000.0;
        while carry > 0.0 {
            let Some(f) = link.front_mut() else {
                carry = 0.0;
                break;
            };
            if f.left > carry {
                f.left -= carry;
                carry = 0.0;
            } else {
                carry -= f.left;
                let mut f = link.pop_front().expect("front exists");
                let packets = f.bytes.div_ceil(1200) as i32;
                let lossy = rng.unit() < 1.0 - (1.0 - p.loss).powi(packets);
                let j = if p.jitter_ms > 0 {
                    (rng.unit() * p.jitter_ms as f64) as u64
                        + (rng.unit() * p.jitter_ms as f64) as u64
                } else {
                    0
                };
                let extra = if lossy { p.rtt_ms } else { 0 };
                f.ack_ms = Some(t + p.rtt_ms + j + extra);
                pending.push(f);
            }
        }
        let backlog: f64 = link.iter().map(|f| f.left).sum();
        if bw > 0 && t >= from_s * 1000 {
            r.max_backlog_ms = r.max_backlog_ms.max(backlog * 8.0 / f64::from(bw));
        }
        // Source.
        let interval = match content {
            Content::Busy => 1000 / u64::from(fps.max(1)),
            Content::Light => 100,
        };
        if t - last_emit >= interval {
            last_emit = t;
            let disp = c.on_frame_ready(next_idr);
            match disp {
                FrameDisposition::Drop => r.frames_dropped_by_gate += 1,
                FrameDisposition::Send { .. } => {
                    let base = match content {
                        Content::Busy => f64::from(kbps) * 1000.0 / 8.0 / f64::from(fps.max(1)),
                        Content::Light => 2000.0,
                    };
                    let mut bytes = (base * (0.5 + rng.unit())) as usize;
                    if next_idr {
                        bytes = bytes.max(base as usize) * 3;
                        next_idr = false;
                    }
                    let bytes = bytes.max(200);
                    let no = next_no;
                    next_no += 1;
                    link.push_back(LinkFrame {
                        no,
                        sent_ms: t,
                        bytes,
                        left: bytes as f64,
                        ack_ms: None,
                    });
                    c.on_frame_sent(now, no, bytes);
                    r.frames_sent += 1;
                    if t >= from_s * 1000 {
                        sent_bytes_window += bytes as u64;
                    }
                }
            }
        }
        if t % 5 == 0 {
            let a = c.poll(now);
            apply(
                &a,
                &mut kbps,
                &mut fps,
                &mut next_idr,
                &mut link,
                &mut pending,
            );
        }
        if t % 1000 == 0 {
            r.kbps_per_s.push(c.kbps());
        }
        r.max_kbps = r.max_kbps.max(c.kbps());
        if t >= from_s * 1000 {
            target_sum += f64::from(c.kbps());
            fps_sum += f64::from(c.fps());
            samples += 1;
        }
    }
    let st = c.stats();
    r.cancels = st.cancels;
    r.resyncs = st.resyncs;
    r.step_downs = st.step_downs;
    r.final_kbps = c.kbps();
    let win = (secs - from_s) as f64;
    r.mean_sent_kbps = sent_bytes_window as f64 * 8.0 / 1000.0 / win;
    r.mean_target_kbps = target_sum / samples.max(1) as f64;
    r.mean_fps = fps_sum / samples.max(1) as f64;
    queue_ms.sort_by(|a, b| a.total_cmp(b));
    r.p95_queue_ms = queue_ms
        .get(queue_ms.len() * 95 / 100)
        .copied()
        .unwrap_or(0.0);
    r
}
