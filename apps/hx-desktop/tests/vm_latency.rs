//! Latency probe against an installed server, through the app's own session and decoder code
//! (everything the desktop app does except drawing). `#[ignore]`d; run by hand:
//!
//! ```text
//! HX1E_VM_ADDR=ip:443 HX1E_VM_SERVER_KEY=<64 hex> HX1E_VM_CODE=XXXX-XXXX HX1E_VM_PIN_FILE=path \
//!   cargo nextest run --release -p hx-desktop --run-ignored only -E 'test(vm_latency)' --no-capture
//! ```
//!
//! It pairs a new device with the code, logs in with the PIN, asks for the stream like the app
//! does, then measures:
//! * pointer motion -> the server's cursor report of that position (input injection + cursor
//!   tracking + network, no video);
//! * a right click on the desktop -> the first picture decoded after it (the menu appearing:
//!   input, capture, encode, network, decode), then Escape;
//! * the server's own statistics (encode and capture-to-send p95, RTT, bitrate).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hx_desktop::app::desktop_ctl::build_view;
use hx_desktop::session::net::{Event, Link, Session, login, target};
use hx_desktop::video::{Picture, PresentKind, Presenter, Stats, spawn_decoder};
use hx_proto::pb;

struct Timed(Mutex<Vec<Instant>>);

impl Presenter for Timed {
    fn kind(&self) -> PresentKind {
        PresentKind::CpuUpload
    }
    fn present(&self, _p: Picture) {
        self.0.lock().unwrap().push(Instant::now());
    }
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

fn key_hex(h: &str) -> hx_crypto::PublicKey {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
    }
    hx_crypto::PublicKey::from_bytes(&out).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an installed server: HX1E_VM_ADDR, HX1E_VM_SERVER_KEY, HX1E_VM_CODE, HX1E_VM_PIN_FILE"]
async fn vm_latency() {
    let addr = std::env::var("HX1E_VM_ADDR").unwrap();
    let (host, port) = addr.rsplit_once(':').unwrap();
    let server = key_hex(&std::env::var("HX1E_VM_SERVER_KEY").unwrap());
    let pin = std::fs::read_to_string(std::env::var("HX1E_VM_PIN_FILE").unwrap()).unwrap();
    let code = std::env::var("HX1E_VM_CODE").unwrap();

    let device = Arc::new(hx_crypto::IdentityKey::generate().unwrap());
    let t = target(host, port.parse().unwrap()).await.unwrap();
    let cred = hx_crypto::PairingCredential::parse(&code).unwrap();
    let paired = hx_crypto::pair_device(
        &t,
        &device,
        &cred,
        &hx_crypto::PairClientOptions {
            device_name: "latency probe".into(),
            ..Default::default()
        },
    )
    .await
    .expect("pairing");
    assert_eq!(paired.server_key, server);
    paired.finish().await;
    let link = Link {
        host: host.into(),
        port: port.parse().unwrap(),
        server_key: server,
        device,
        device_name: "latency probe".into(),
    };
    let conn = login(&link, pin.trim()).await.expect("PIN login");

    let pics = Arc::new(Timed(Mutex::default()));
    let stats = Arc::new(Stats::default());
    let slot: Arc<Mutex<Option<Arc<Session>>>> = Arc::default();
    let s2 = slot.clone();
    let (tx, _thread) = spawn_decoder(
        pics.clone(),
        stats.clone(),
        Arc::new(move |last| {
            if let Some(s) = s2.lock().unwrap().as_ref() {
                s.request_keyframe(last);
            }
        }),
    )
    .unwrap();
    let (session, mut events) = Session::start(
        conn,
        Some(tx),
        stats.clone(),
        tokio::runtime::Handle::current(),
    );
    let session = Arc::new(session);
    *slot.lock().unwrap() = Some(session.clone());
    // The app's defaults: quality Balanced, no cap, Fit (the remote keeps its size).
    session.view(build_view(0, 0, 0, (1366, 711), true, true));

    // Events go to a shared log so the measurements can wait on them.
    type Log = Arc<Mutex<Vec<(Instant, Event)>>>;
    let log: Log = Arc::default();
    let l2 = log.clone();
    tokio::spawn(async move {
        while let Some(e) = events.recv().await {
            l2.lock().unwrap().push((Instant::now(), e));
        }
    });
    let t0 = Instant::now();
    while pics.0.lock().unwrap().is_empty() {
        assert!(t0.elapsed() < Duration::from_secs(30), "no first picture");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    println!("first picture after {} ms", t0.elapsed().as_millis());
    tokio::time::sleep(Duration::from_secs(2)).await;
    let dec = stats.take_interval();
    println!("decode so far: {dec:?}");

    // 1. Motion -> the server's cursor report of exactly that position.
    let mut motion = Vec::new();
    for i in 0..30 {
        let (x, y) = (400 + i * 7, 300 + i * 3);
        let from = log.lock().unwrap().len();
        let t = Instant::now();
        session.motion(x, y);
        let deadline = t + Duration::from_secs(2);
        let mut got = None;
        while Instant::now() < deadline && got.is_none() {
            tokio::time::sleep(Duration::from_millis(1)).await;
            got = log.lock().unwrap()[from..]
                .iter()
                .find_map(|(at, e)| match e {
                    Event::Cursor(c) => match &c.event {
                        Some(pb::cursor_event::Event::Position(p)) if p.x == x && p.y == y => {
                            Some(*at)
                        }
                        _ => None,
                    },
                    _ => None,
                });
        }
        match got {
            Some(at) => motion.push(at.duration_since(t).as_secs_f64() * 1e3),
            None => println!("motion {i}: no cursor report"),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if !motion.is_empty() {
        println!(
            "motion -> cursor report: n={} p50={:.1} ms p95={:.1} ms max={:.1} ms",
            motion.len(),
            pct(&mut motion.clone(), 0.5),
            pct(&mut motion.clone(), 0.95),
            pct(&mut motion, 1.0)
        );
    }

    // 2. Right click on the desktop -> the first decoded picture after it; then Escape.
    let mut click = Vec::new();
    let mut settle = Vec::new();
    for i in 0..10 {
        // Let the screen go quiet first.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let from = pics.0.lock().unwrap().len();
        let (x, y) = (1500, 700 + i * 10);
        session.motion(x, y);
        let t = Instant::now();
        session.button(pb::MouseButton::Right, true, x, y);
        session.button(pb::MouseButton::Right, false, x, y);
        let deadline = t + Duration::from_secs(3);
        let mut first = None;
        while Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(1)).await;
            let p = pics.0.lock().unwrap();
            if first.is_none() && p.len() > from {
                first = Some(p[from]);
            }
            if first.is_some() && Instant::now() > first.unwrap() + Duration::from_millis(600) {
                break;
            }
        }
        let p = pics.0.lock().unwrap();
        match first {
            Some(f) => {
                click.push(f.duration_since(t).as_secs_f64() * 1e3);
                let last = *p.last().unwrap();
                settle.push(last.duration_since(t).as_secs_f64() * 1e3);
                println!(
                    "click {i}: first picture {:.1} ms, {} pictures, last {:.1} ms",
                    f.duration_since(t).as_secs_f64() * 1e3,
                    p.len() - from,
                    last.duration_since(t).as_secs_f64() * 1e3
                );
            }
            None => println!("click {i}: no picture within 3 s"),
        }
        drop(p);
        session.key(0x29, true);
        session.key(0x29, false);
    }
    if !click.is_empty() {
        println!(
            "right click -> first decoded picture: n={} p50={:.1} ms p95={:.1} ms",
            click.len(),
            pct(&mut click.clone(), 0.5),
            pct(&mut click, 0.95)
        );
    }
    println!("decode interval: {:?}", stats.take_interval());
    for (_, e) in log.lock().unwrap().iter() {
        if let Event::Stats(s) = e {
            println!(
                "server: frames={} kf={} drop={} kbps={} target={} fps_ceiling={} encode_p95={}us total_p95={}us qmax={} rtt={}us",
                s.frames,
                s.keyframes,
                s.dropped_frames,
                s.bitrate_kbps,
                s.target_bitrate_kbps,
                s.fps_ceiling,
                s.encode_p95_us,
                s.total_p95_us,
                s.queue_depth_max,
                s.rtt_us
            );
        }
    }
    session.close().await;
}
