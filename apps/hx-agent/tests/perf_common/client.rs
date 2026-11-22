//! The client of the end-to-end run: pair, PIN login, view, type, scroll, idle, final picture
//! check, disconnect and reconnect, with every input event marked and found again in the decoded
//! video (the S2 mark-and-detect method, from input instead of from damage).
//!
//! It runs as its own process inside the client network namespace, started by the orchestrator
//! with `nsenter`; it prints `HXPHASE <name> start|end` lines so the orchestrator can read the
//! CPU of hx-session and hx-gatewayd over exactly the same window, and one `HXCLIENT <json>` line
//! at the end.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hx_crypto::{IdentityKey, PairClientOptions, PairingCredential, Pin};
use hx_proto::VideoCodec;
use hx_proto::channel::CloseCode;
use hx_proto::pb::{
    ControlMessage, InputEvent, KeyEvent, RequestKeyframe, ScrollEvent, ViewConfig,
    control_message::Message as Ctl, input_event::Event as In,
};
use hx_proto::version::{Features, PROTOCOL_MINOR, capabilities};
use hx_transport::{Connection, Target, TransportPreference, VideoFrame};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};

use super::desk::{Geometry, newest_cursor, read_scroll_code};
use super::result::{ClientReport, Latency, Phase, compare};
use crate::e2e_common::Decoder;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Params {
    pub quic: SocketAddr,
    pub code: String,
    pub pin: String,
    pub dump: PathBuf,
    pub width: u32,
    pub height: u32,
    pub keys: u32,
    pub typing_hz: f64,
    pub scroll_ticks: u32,
    pub scroll_hz: f64,
    pub idle_s: u64,
    /// Added to every wait: more on slow profiles.
    pub patience_s: u64,
}

const DEV: &str = "hxc0";

fn target(addr: SocketAddr) -> Target {
    Target {
        addr,
        server_name: ServerName::try_from("hx.invalid").unwrap(),
    }
}

fn net_bytes() -> (u64, u64) {
    std::fs::read_to_string("/proc/net/dev")
        .ok()
        .and_then(|t| super::net::parse_dev(&t, DEV))
        .unwrap_or((0, 0))
}

fn phase_mark(name: &str, what: &str) {
    println!("HXPHASE {name} {what}");
}

#[derive(Default)]
struct Counters {
    frames: u64,
    key_frames: u64,
    bytes: u64,
    decode_failures: u64,
    /// Frames that were not the successor of the previous one and not key frames.
    gaps: u64,
    last_arrival: Option<Instant>,
    max_gap_ms: f64,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Idle,
    Typing,
    Scroll,
}

struct Tracker {
    mode: Mode,
    sent: Vec<Instant>,
    lat_ms: Vec<f64>,
    next: usize,
}

struct Shared {
    counters: Mutex<Counters>,
    tracker: Mutex<Tracker>,
    last_luma: Mutex<Option<Arc<Vec<u8>>>>,
    want_idr: AtomicBool,
    /// The frame loop dropped a gap's frames and has not yet seen the key frame that repairs it:
    /// the request is repeated until it does (a request or its answer can be lost or late).
    awaiting_key: AtomicBool,
    decoded: AtomicU64,
    /// The newest scroll counter read from a picture (diagnostics).
    last_code: AtomicU64,
    started: Instant,
    server_stats: Mutex<Vec<String>>,
    /// The first frames as the transport released them: number, flags, size.
    first_frames: Mutex<Vec<String>>,
    /// Milliseconds from noticing a frame gap to the key frame that repaired it.
    recoveries: Mutex<Vec<f64>>,
    key_frames_seen: Mutex<Vec<String>>,
}

fn spawn_decoder(
    rx: mpsc::Receiver<VideoFrame>,
    shared: Arc<Shared>,
    g: Geometry,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut dec = Decoder::new();
        while let Ok(f) = rx.recv() {
            let Some(pic) = dec.decode(&f.payload) else {
                shared.counters.lock().unwrap().decode_failures += 1;
                shared.want_idr.store(true, SeqCst);
                continue;
            };
            let now = Instant::now();
            shared.decoded.fetch_add(1, SeqCst);
            if pic.width != g.width || pic.height != g.height {
                continue;
            }
            {
                let mut t = shared.tracker.lock().unwrap();
                match t.mode {
                    Mode::Idle => {}
                    Mode::Typing => {
                        if t.next < t.sent.len() {
                            let to = (t.sent.len() as u32 - 1).min(g.typing_capacity());
                            if let Some(j) = newest_cursor(&pic.luma, g, t.next as u32, to) {
                                while t.next <= j as usize {
                                    let ms =
                                        now.duration_since(t.sent[t.next]).as_secs_f64() * 1000.0;
                                    t.lat_ms.push(ms);
                                    t.next += 1;
                                }
                            }
                        }
                    }
                    Mode::Scroll => {
                        if let Some(code) = read_scroll_code(&pic.luma, g) {
                            shared.last_code.store(u64::from(code), SeqCst);
                            // A reading above what was sent is a misread, not a mark.
                            let code = code.min(t.sent.len() as u32) as usize;
                            while t.next < code {
                                let ms = now.duration_since(t.sent[t.next]).as_secs_f64() * 1000.0;
                                t.lat_ms.push(ms);
                                t.next += 1;
                            }
                        }
                    }
                }
            }
            *shared.last_luma.lock().unwrap() = Some(Arc::new(pic.luma));
        }
    })
}

fn key(sc: u32, pressed: bool) -> InputEvent {
    InputEvent {
        event: Some(In::Key(KeyEvent {
            scancode: sc,
            pressed,
        })),
    }
}

fn opts(name: &str) -> hx_crypto::SessionOptions {
    hx_crypto::SessionOptions {
        preference: TransportPreference::Quic,
        device_name: name.into(),
        capabilities: capabilities(&[VideoCodec::H264], Features::defined_up_to(PROTOCOL_MINOR)),
        ..Default::default()
    }
}

async fn login(
    addr: SocketAddr,
    key: &Arc<IdentityKey>,
    server: hx_crypto::PublicKey,
    pin: &str,
    timeout: Duration,
) -> Result<Connection, String> {
    tokio::time::timeout(
        timeout,
        hx_crypto::connect_with_pin(
            &target(addr),
            key,
            server,
            &Pin::new(pin).map_err(|e| format!("{e:?}"))?,
            &opts("perf-client"),
        ),
    )
    .await
    .map_err(|_| "login timed out".to_string())?
    .map_err(|e| format!("login: {e}"))
}

fn view() -> ControlMessage {
    ControlMessage::new(Ctl::ViewConfig(ViewConfig {
        codec: VideoCodec::H264 as i32,
        max_fps: 60,
        clipboard_enabled: true,
        // The server's once-a-second statistics (frames, key frames, drops, target bitrate):
        // recorded in the report, they show what the sender did during a stall.
        stats_enabled: true,
        ..Default::default()
    }))
}

/// Takes the counters of a phase and resets them.
fn take(shared: &Shared, name: &str, secs: f64, net0: (u64, u64)) -> Phase {
    let c = std::mem::take(&mut *shared.counters.lock().unwrap());
    let n1 = net_bytes();
    Phase {
        name: name.into(),
        secs,
        frames: c.frames,
        key_frames: c.key_frames,
        video_bytes: c.bytes,
        max_gap_ms: c.max_gap_ms,
        decode_failures: c.decode_failures,
        frame_gaps: c.gaps,
        net_rx_bytes: n1.0.saturating_sub(net0.0),
        net_tx_bytes: n1.1.saturating_sub(net0.1),
        ..Phase::default()
    }
}

async fn wait_marks(shared: &Shared, n: usize, limit: Duration) {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if shared.tracker.lock().unwrap().next >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let c = shared.counters.lock().unwrap();
    eprintln!(
        "CLIENT gave up waiting for marks: {}/{n} seen, newest scroll code read {}, {} frames and {} decode failures in the phase, {:.1}s since the last frame arrived",
        shared.tracker.lock().unwrap().next,
        shared.last_code.load(SeqCst),
        c.frames,
        c.decode_failures,
        c.last_arrival
            .map_or(f64::NAN, |t| t.elapsed().as_secs_f64())
    );
}

fn latency(shared: &Shared, events: u32) -> Latency {
    let t = shared.tracker.lock().unwrap();
    Latency::from_samples(events, &t.lat_ms)
}

pub async fn run(p: Params) -> ClientReport {
    let mut rep = ClientReport::default();
    match run_inner(&p, &mut rep).await {
        Ok(()) => {}
        Err(e) => rep.errors.push(e),
    }
    rep
}

#[allow(clippy::too_many_lines)]
async fn run_inner(p: &Params, rep: &mut ClientReport) -> Result<(), String> {
    let g = Geometry {
        width: p.width,
        height: p.height,
    };
    let patience = Duration::from_secs(p.patience_s);
    let key_pair = Arc::new(IdentityKey::generate().map_err(|e| format!("key: {e:?}"))?);

    // ----- pair ---------------------------------------------------------------------------
    let t = Instant::now();
    let cred = PairingCredential::parse(&p.code).map_err(|e| format!("code: {e:?}"))?;
    let paired = tokio::time::timeout(
        Duration::from_secs(30) + patience,
        hx_crypto::pair_device(
            &target(p.quic),
            &key_pair,
            &cred,
            &PairClientOptions {
                preference: TransportPreference::Quic,
                device_name: "perf-client".into(),
                ..Default::default()
            },
        ),
    )
    .await
    .map_err(|_| "pairing timed out".to_string())?
    .map_err(|e| format!("pairing: {e}"))?;
    let server = paired.server_key;
    paired.finish().await;
    rep.pair_ms = t.elapsed().as_secs_f64() * 1000.0;

    // ----- PIN login ----------------------------------------------------------------------
    let t = Instant::now();
    let conn = login(
        p.quic,
        &key_pair,
        server,
        &p.pin,
        Duration::from_secs(30) + patience,
    )
    .await?;
    rep.login_ms = t.elapsed().as_secs_f64() * 1000.0;
    rep.transport_rtt_ms = match conn.ping(Duration::from_secs(5)).await {
        Ok(d) => d.as_secs_f64() * 1000.0,
        Err(_) => f64::NAN,
    };

    // ----- the stream ---------------------------------------------------------------------
    let shared = Arc::new(Shared {
        counters: Mutex::new(Counters::default()),
        tracker: Mutex::new(Tracker {
            mode: Mode::Idle,
            sent: Vec::new(),
            lat_ms: Vec::new(),
            next: 0,
        }),
        last_luma: Mutex::new(None),
        want_idr: AtomicBool::new(false),
        awaiting_key: AtomicBool::new(false),
        decoded: AtomicU64::new(0),
        last_code: AtomicU64::new(0),
        started: Instant::now(),
        server_stats: Mutex::new(Vec::new()),
        first_frames: Mutex::new(Vec::new()),
        recoveries: Mutex::new(Vec::new()),
        key_frames_seen: Mutex::new(Vec::new()),
    });
    let (ftx, frx) = mpsc::channel::<VideoFrame>();
    let _decoder = spawn_decoder(frx, shared.clone(), g);
    let (ctx, mut crx) = tokio::sync::mpsc::unbounded_channel::<Ctl>();
    let tasks = {
        let (c, s) = (conn.clone(), shared.clone());
        let frames = tokio::spawn(async move {
            let mut prev: Option<u32> = None;
            let mut awaiting: Option<Instant> = None;
            // With HX_NETEM_OUT: every payload handed to the decoder, as one Annex B stream, to
            // decode again with the ffmpeg program.
            let mut dump = std::env::var_os("HX_NETEM_OUT").and_then(|d| {
                let d = PathBuf::from(d);
                std::fs::create_dir_all(&d).ok()?;
                std::fs::File::create(d.join("stream.h264")).ok()
            });
            while let Ok(f) = c.recv_video_frame().await {
                let now = Instant::now();
                {
                    let mut k = s.counters.lock().unwrap();
                    k.frames += 1;
                    k.bytes += f.payload.len() as u64;
                    if f.header.is_key() {
                        k.key_frames += 1;
                    }
                    if let Some(last) = k.last_arrival {
                        let gap = now.duration_since(last).as_secs_f64() * 1000.0;
                        if gap > k.max_gap_ms {
                            k.max_gap_ms = gap;
                        }
                    }
                    k.last_arrival = Some(now);
                    // A client's duty (protocol 6, `request_keyframe`): a frame that does not
                    // follow the previous one and is not a key frame means the decoder skipped
                    // one (cancelled, or released past by the reorder window), so its picture is
                    // wrong from here on. Ask for a fresh full image.
                    let n = f.header.frame_number;
                    {
                        let mut ff = s.first_frames.lock().unwrap();
                        if ff.len() < 8 {
                            ff.push(format!(
                                "#{n} {}{} {} B at +{:.0} ms",
                                if f.header.is_key() { "KEY" } else { "P" },
                                if f.header.is_resync() { "|RESYNC" } else { "" },
                                f.payload.len(),
                                s.started.elapsed().as_secs_f64() * 1000.0
                            ));
                        }
                    }
                    if prev.is_some_and(|p| n != p.wrapping_add(1)) && !f.header.is_key() {
                        k.gaps += 1;
                        awaiting.get_or_insert(now);
                        s.want_idr.store(true, SeqCst);
                    }
                    prev = Some(n);
                    if f.header.is_key() && n != 0 {
                        // Does a frame flagged KEY carry an IDR slice (NAL type 5)? An intra
                        // refresh recovery point is flagged KEY too but does not reset the
                        // decoder's references.
                        let idr = f
                            .payload
                            .windows(4)
                            .any(|w| w[0] == 0 && w[1] == 0 && w[2] == 1 && w[3] & 0x1f == 5);
                        s.key_frames_seen.lock().unwrap().push(format!(
                            "#{n} {}{} idr_slice={idr} {} B",
                            "KEY",
                            if f.header.is_resync() { "|RESYNC" } else { "" },
                            f.payload.len()
                        ));
                    }
                    if f.header.is_key()
                        && let Some(t) = awaiting.take()
                    {
                        s.recoveries
                            .lock()
                            .unwrap()
                            .push(now.duration_since(t).as_secs_f64() * 1000.0);
                    }
                }
                s.awaiting_key.store(awaiting.is_some(), SeqCst);
                // After a gap the picture is wrong whatever is decoded: nothing but a key frame
                // goes to the decoder until one arrives.
                if awaiting.is_some() && !f.header.is_key() {
                    continue;
                }
                if let Some(w) = dump.as_mut() {
                    let _ = std::io::Write::write_all(w, &f.payload);
                }
                if ftx.send(f).is_err() {
                    break;
                }
            }
        });
        let (c, s) = (conn.clone(), shared.clone());
        let control = tokio::spawn(async move {
            while let Ok(m) = c.recv_control().await {
                if let Some(m) = m.message {
                    if let Ctl::ServerStats(st) = &m {
                        s.server_stats.lock().unwrap().push(format!(
                            "t={:.1}s frames={} key={} dropped={} bitrate={}kbps target={}kbps fps_ceiling={} rtt={}us queue_max={}",
                            s.started.elapsed().as_secs_f64(),
                            st.frames,
                            st.keyframes,
                            st.dropped_frames,
                            st.bitrate_kbps,
                            st.target_bitrate_kbps,
                            st.fps_ceiling,
                            st.rtt_us,
                            st.queue_depth_max
                        ));
                    }
                    let _ = ctx.send(m);
                }
            }
        });
        // The client asks for an IDR when a picture fails to decode (at most twice a second),
        // as a real client does.
        let (c, s) = (conn.clone(), shared.clone());
        let idr = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if s.want_idr.swap(false, SeqCst) || s.awaiting_key.load(SeqCst) {
                    let _ = c
                        .send_control(&ControlMessage::new(Ctl::RequestKeyframe(
                            RequestKeyframe {
                                last_decoded_frame: 0,
                            },
                        )))
                        .await;
                }
            }
        });
        [frames, control, idr]
    };
    struct Abort<'a>(&'a [tokio::task::JoinHandle<()>]);
    impl Drop for Abort<'_> {
        fn drop(&mut self) {
            for t in self.0 {
                t.abort();
            }
        }
    }
    let _abort = Abort(&tasks);

    let t_view = Instant::now();
    conn.send_control(&view())
        .await
        .map_err(|e| format!("view: {e}"))?;
    let info = tokio::time::timeout(Duration::from_secs(30) + patience, async {
        while let Some(m) = crx.recv().await {
            if let Ctl::StreamInfo(i) = m {
                return Some(i);
            }
        }
        None
    })
    .await
    .map_err(|_| "no StreamInfo".to_string())?
    .ok_or("the control channel closed before StreamInfo")?;
    rep.stream = format!("{}x{}", info.width, info.height);
    if (info.width, info.height) != (p.width, p.height) {
        return Err(format!(
            "the stream is {}x{}, the desktop {}x{}",
            info.width, info.height, p.width, p.height
        ));
    }
    // First decoded picture (the decoder thread counts them).
    let end = Instant::now() + Duration::from_secs(30) + patience;
    while shared.decoded.load(SeqCst) == 0 {
        if Instant::now() > end {
            return Err("no decodable frame".into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    rep.first_frame_ms = t_view.elapsed().as_secs_f64() * 1000.0;
    // Let the first IDR burst and any start-up refinement settle before measuring.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    drop(take(&shared, "warmup", 1.0, net_bytes()));

    // ----- typing -------------------------------------------------------------------------
    let keys = p.keys.min(g.typing_capacity());
    {
        let mut t = shared.tracker.lock().unwrap();
        *t = Tracker {
            mode: Mode::Typing,
            sent: Vec::new(),
            lat_ms: Vec::new(),
            next: 0,
        };
    }
    let net0 = net_bytes();
    phase_mark("typing", "start");
    let t0 = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / p.typing_hz));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    for i in 0..keys {
        tick.tick().await;
        shared.tracker.lock().unwrap().sent.push(Instant::now());
        let usage = 0x04 + (i % 26);
        conn.send_input(&key(usage, true))
            .await
            .map_err(|e| format!("key: {e}"))?;
        conn.send_input(&key(usage, false))
            .await
            .map_err(|e| format!("key: {e}"))?;
    }
    wait_marks(&shared, keys as usize, Duration::from_secs(8) + patience).await;
    let secs = t0.elapsed().as_secs_f64();
    phase_mark("typing", "end");
    rep.typing = take(&shared, "typing", secs, net0);
    rep.typing.latency = Some(latency(&shared, keys));

    // ----- scrolling ----------------------------------------------------------------------
    tokio::time::sleep(Duration::from_millis(500)).await;
    {
        let mut t = shared.tracker.lock().unwrap();
        *t = Tracker {
            mode: Mode::Scroll,
            sent: Vec::new(),
            lat_ms: Vec::new(),
            next: 0,
        };
    }
    drop(take(&shared, "gap", 1.0, net_bytes()));
    let net0 = net_bytes();
    phase_mark("scroll", "start");
    let t0 = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / p.scroll_hz));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    for _ in 0..p.scroll_ticks {
        tick.tick().await;
        shared.tracker.lock().unwrap().sent.push(Instant::now());
        conn.send_input(&InputEvent {
            event: Some(In::Scroll(ScrollEvent { dx: 0, dy: -120 })),
        })
        .await
        .map_err(|e| format!("scroll: {e}"))?;
    }
    wait_marks(
        &shared,
        p.scroll_ticks as usize,
        Duration::from_secs(8) + patience,
    )
    .await;
    let secs = t0.elapsed().as_secs_f64();
    phase_mark("scroll", "end");
    rep.scroll = take(&shared, "scroll", secs, net0);
    rep.scroll.latency = Some(latency(&shared, p.scroll_ticks));
    shared.tracker.lock().unwrap().mode = Mode::Idle;

    // ----- idle ---------------------------------------------------------------------------
    // Let the last frames and acks drain, then watch a quiet desktop.
    tokio::time::sleep(Duration::from_secs(2) + patience / 2).await;
    drop(take(&shared, "gap", 1.0, net_bytes()));
    let net0 = net_bytes();
    phase_mark("idle", "start");
    let t0 = Instant::now();
    tokio::time::sleep(Duration::from_secs(p.idle_s)).await;
    let secs = t0.elapsed().as_secs_f64();
    phase_mark("idle", "end");
    rep.idle = take(&shared, "idle", secs, net0);

    // ----- the picture is the desktop -----------------------------------------------------
    // F12 makes the desk dump what it drew; compare it with what was decoded (the last picture
    // may still be on its way over a lossy link, so retry for a while).
    let _ = std::fs::remove_file(&p.dump);
    conn.send_input(&key(0x45, true))
        .await
        .map_err(|e| format!("F12: {e}"))?;
    conn.send_input(&key(0x45, false))
        .await
        .map_err(|e| format!("F12: {e}"))?;
    let end = Instant::now() + Duration::from_secs(10) + patience;
    let mut mask = None;
    while Instant::now() < end {
        if let Ok(m) = std::fs::read(&p.dump) {
            mask = Some(m);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mask = mask.ok_or("the desk did not dump its picture (F12 lost?)")?;
    let end = Instant::now() + Duration::from_secs(8) + patience;
    loop {
        let luma = shared.last_luma.lock().unwrap().clone();
        if let Some((bad, contrast)) = luma.as_deref().and_then(|l| compare(l, &mask)) {
            rep.mismatch_pct = bad;
            rep.contrast = contrast;
            // A picture that is the desktop: under 1 % of the pixels on the wrong side of the
            // black/white threshold (a 720p picture measures 0.000 %, a 1080p one 0.45 %, the
            // 2 px strokes being coded at crf 23; a picture one scrolled line behind measures
            // about 1.5 %, a corrupt one 2 % and more) and a real contrast.
            if bad < 1.0 && contrast > 100.0 {
                rep.final_matches = true;
                break;
            }
        }
        if Instant::now() > end {
            // A wrong picture is easier to understand when seen: with HX_NETEM_OUT set, keep
            // what was decoded and what the desk drew as PGM files.
            if let (Some(dir), Some(l)) = (
                std::env::var_os("HX_NETEM_OUT"),
                shared.last_luma.lock().unwrap().clone(),
            ) {
                let dir = PathBuf::from(dir);
                let _ = std::fs::create_dir_all(&dir);
                let pgm = |name: &str, px: &[u8]| {
                    let mut b = format!("P5\n{} {}\n255\n", g.width, g.height).into_bytes();
                    b.extend_from_slice(px);
                    let _ = std::fs::write(dir.join(name), b);
                };
                pgm("mismatch-decoded.pgm", &l);
                pgm("mismatch-desk.pgm", &mask);
            }
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    rep.server_stats = shared.server_stats.lock().unwrap().clone();
    rep.first_frames = shared.first_frames.lock().unwrap().clone();
    rep.gap_recovery_ms = shared.recoveries.lock().unwrap().clone();
    rep.key_frames = shared.key_frames_seen.lock().unwrap().clone();

    // ----- disconnect, then connect again --------------------------------------------------
    conn.close(CloseCode::NoError, "bye").await;
    let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    rep.disconnect_clean = closed.is_ok();
    drop(_abort);
    for t in &tasks {
        t.abort();
    }
    // The desktop keeps running; the next login gets a fresh stream with an IDR.
    let t = Instant::now();
    let conn2 = login(
        p.quic,
        &key_pair,
        server,
        &p.pin,
        Duration::from_secs(30) + patience,
    )
    .await?;
    conn2
        .send_control(&view())
        .await
        .map_err(|e| format!("view: {e}"))?;
    let mut dec = Decoder::new();
    let end = Instant::now() + Duration::from_secs(20) + patience;
    while Instant::now() < end {
        let f = match tokio::time::timeout(
            Duration::from_secs(10) + patience,
            conn2.recv_video_frame(),
        )
        .await
        {
            Ok(Ok(f)) => f,
            _ => break,
        };
        if dec.decode(&f.payload).is_some() {
            rep.reconnect_decoded = true;
            rep.reconnect_ms = t.elapsed().as_secs_f64() * 1000.0;
            break;
        }
    }
    conn2.close(CloseCode::NoError, "bye").await;
    Ok(())
}
