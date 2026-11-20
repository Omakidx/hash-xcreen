//! s2-server: capture (XDamage+XShm) -> convert (yuvutils-rs) -> encode (x264 via libavcodec) -> QUIC.
//! Threads: capture, convert, encode, stats; tokio only for networking.

#![allow(clippy::too_many_arguments)]

use anyhow::{Context, Result, anyhow};
use crossbeam_channel::{Receiver, Sender, bounded};
use ffmpeg_next as ffmpeg;
use s2::wire::{self, FrameHeader};
use s2::{Args, cgroup_cpu_usec, now_ns, process_cpu_ns};
use std::collections::BTreeMap;
use std::io::Write;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use x11rb::connection::Connection;
use x11rb::protocol::Event;
use x11rb::protocol::damage::{self, ConnectionExt as _};
use x11rb::protocol::shm::ConnectionExt as _;
use x11rb::protocol::xfixes::{self, ConnectionExt as _};
use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat};
use x11rb::rust_connection::RustConnection;

// ---------------------------------------------------------------- configuration

#[derive(Clone)]
struct Cfg {
    listen: SocketAddr,
    display: String,
    max_fps: u32,
    crf: u32,
    max_kbps: u32,
    threads: u32,
    sliced: bool,
    intra_refresh: bool,
    keyint: u32,
    preset: String,
    congestion: bool,
    stats_path: String,
    slots: usize,
    cursor: bool,
    /// Directory for raw BGRA source frames (fidelity runs); empty = off.
    dump_dir: String,
    dump_every: u64,
    /// Tag the stream as BT.709 limited range in the H.264 VUI.
    vui: bool,
    /// VBV buffer size in frames of the current rate (1.0 = one frame, the spike default).
    vbv_frames: f64,
}

#[derive(Default)]
struct Shared {
    min_interval_ns: AtomicU64,
    force_idr: AtomicBool,
    resync_flag: AtomicBool,
    kbps: AtomicU32,
    conn_epoch: AtomicU64,
    // stats
    frames_enc: AtomicU64,
    bytes_enc: AtomicU64,
    bytes_sent: AtomicU64,
    frames_sent: AtomicU64,
    cancels: AtomicU64,
    cancelled_streams: AtomicU64,
    lag_ms: AtomicU32,
    rtt_ms: AtomicU32,
    inflight: AtomicU32,
    captures: AtomicU64,
    rate_changes: AtomicU64,
    enc_restarts: AtomicU64,
}

// ---------------------------------------------------------------- shared-memory slots

struct ShmSlot {
    ptr: *mut u8,
    shmid: i32,
}
// SAFETY: slots are handed between threads through channels so only one thread touches a slot at a time.
unsafe impl Send for ShmSlot {}
unsafe impl Sync for ShmSlot {}

struct CapJob {
    slot: usize,
    t_damage: u64,
    t_capture: u64,
    resync: bool,
}

struct ConvJob {
    /// Raw BGRA copy of the captured source frame (fidelity runs only).
    dump: Option<Vec<u8>>,
    yuv: ffmpeg::frame::Video,
    t_damage: u64,
    t_capture: u64,
    t_convert: u64,
    resync: bool,
}

struct OutFrame {
    hdr: FrameHeader,
    payload: Vec<u8>,
}

enum CursorMsg {
    Shape { hash: u64, w: u16, h: u16, xhot: u16, yhot: u16, argb: Vec<u32> },
    Pos { x: i16, y: i16, t: u64 },
}

// ---------------------------------------------------------------- capture thread

fn capture_thread(
    cfg: Cfg,
    sh: Arc<Shared>,
    slots: Arc<Vec<ShmSlot>>,
    free_rx: Receiver<usize>,
    job_tx: Sender<CapJob>,
    cursor_tx: tokio::sync::mpsc::Sender<CursorMsg>,
    w: u16,
    h: u16,
) -> Result<()> {
    let (conn, screen_num) = RustConnection::connect(Some(&cfg.display))?;
    let root = conn.setup().roots[screen_num].root;
    conn.damage_query_version(1, 1)?.reply()?;
    conn.xfixes_query_version(4, 0)?.reply()?;
    conn.shm_query_version()?.reply()?;
    let mut segs = Vec::new();
    for s in slots.iter() {
        let seg = conn.generate_id()?;
        conn.shm_attach(seg, s.shmid as u32, false)?.check()?;
        segs.push(seg);
    }
    let dmg = conn.generate_id()?;
    conn.damage_create(dmg, root, damage::ReportLevel::NON_EMPTY)?.check()?;
    conn.xfixes_select_cursor_input(root, xfixes::CursorNotifyMask::DISPLAY_CURSOR)?.check()?;
    conn.flush()?;
    let fd = conn.stream().as_raw_fd();

    let mut pending: Option<u64> = None;
    let mut last_capture = 0u64;
    let mut epoch = 0u64;
    let mut resync_pending = false;
    let mut cursor_dirty = true;
    let mut last_pos = (i16::MIN, i16::MIN);
    let mut last_poll = 0u64;
    let mut sent_shapes: std::collections::HashSet<u64> = Default::default();
    const POLL_NS: u64 = 33_000_000;

    loop {
        while let Some(ev) = conn.poll_for_event()? {
            match ev {
                Event::DamageNotify(_) => {
                    if pending.is_none() {
                        pending = Some(now_ns());
                    }
                }
                Event::XfixesCursorNotify(_) => cursor_dirty = true,
                _ => {}
            }
        }
        let e = sh.conn_epoch.load(Relaxed);
        if e != epoch {
            // New client connected: capture a fresh full image right away.
            epoch = e;
            resync_pending = true;
            sent_shapes.clear();
            cursor_dirty = true;
            last_pos = (i16::MIN, i16::MIN);
            if pending.is_none() {
                pending = Some(now_ns());
            }
        }
        let now = now_ns();
        if cfg.cursor {
            if cursor_dirty {
                cursor_dirty = false;
                if let Ok(r) = conn.xfixes_get_cursor_image()?.reply() {
                    let hash = r.cursor_serial as u64;
                    if sent_shapes.insert(hash) {
                        let _ = cursor_tx.try_send(CursorMsg::Shape {
                            hash,
                            w: r.width,
                            h: r.height,
                            xhot: r.xhot,
                            yhot: r.yhot,
                            argb: r.cursor_image,
                        });
                    }
                }
            }
            if now.saturating_sub(last_poll) >= POLL_NS {
                last_poll = now;
                if let Ok(p) = conn.query_pointer(root)?.reply()
                    && (p.root_x, p.root_y) != last_pos
                {
                    last_pos = (p.root_x, p.root_y);
                    let _ = cursor_tx.try_send(CursorMsg::Pos { x: p.root_x, y: p.root_y, t: now_ns() });
                }
            }
        }

        let mut timeout_ms: i32 = if cfg.cursor { ((POLL_NS - now.saturating_sub(last_poll).min(POLL_NS)) / 1_000_000) as i32 + 1 } else { -1 };
        if let Some(td) = pending {
            let interval = sh.min_interval_ns.load(Relaxed);
            let due = last_capture + interval;
            if now >= due {
                // Backpressure: wait for a free BGRA slot; damage keeps coalescing meanwhile.
                let slot = match free_rx.recv_timeout(std::time::Duration::from_millis(2)) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                conn.damage_subtract(dmg, x11rb::NONE, x11rb::NONE)?;
                conn.shm_get_image(root, 0, 0, w, h, !0, ImageFormat::Z_PIXMAP.into(), segs[slot], 0)?.reply()?;
                let t_capture = now_ns();
                last_capture = t_capture;
                pending = None;
                sh.captures.fetch_add(1, Relaxed);
                let resync = std::mem::take(&mut resync_pending);
                if job_tx.send(CapJob { slot, t_damage: td, t_capture, resync }).is_err() {
                    return Ok(());
                }
                continue;
            }
            timeout_ms = ((due - now) / 1_000_000) as i32;
            if timeout_ms == 0 {
                // sub-millisecond wait: spin-yield to keep pacing accurate
                std::thread::yield_now();
                continue;
            }
        }
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: valid pollfd, count 1.
        unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    }
}

// ---------------------------------------------------------------- convert thread

fn convert_thread(
    job_rx: Receiver<CapJob>,
    slots: Arc<Vec<ShmSlot>>,
    free_tx: Sender<usize>,
    yuv_free_rx: Receiver<ffmpeg::frame::Video>,
    out_tx: Sender<ConvJob>,
    w: u32,
    h: u32,
    dump_every: u64,
) -> Result<()> {
    use yuvutils_rs::*;
    for (n, job) in (0u64..).zip(job_rx) {
        let mut frame = match yuv_free_rx.recv() {
            Ok(f) => f,
            Err(_) => return Ok(()),
        };
        // SAFETY: planes of a freshly allocated YUV420P frame of w x h; strides come from the frame.
        unsafe {
            let f = frame.as_mut_ptr();
            let (ys, us, vs) = ((*f).linesize[0] as usize, (*f).linesize[1] as usize, (*f).linesize[2] as usize);
            let y = std::slice::from_raw_parts_mut((*f).data[0], ys * h as usize);
            let u = std::slice::from_raw_parts_mut((*f).data[1], us * (h as usize / 2));
            let v = std::slice::from_raw_parts_mut((*f).data[2], vs * (h as usize / 2));
            let mut planar = YuvPlanarImageMut {
                y_plane: BufferStoreMut::Borrowed(y),
                y_stride: ys as u32,
                u_plane: BufferStoreMut::Borrowed(u),
                u_stride: us as u32,
                v_plane: BufferStoreMut::Borrowed(v),
                v_stride: vs as u32,
                width: w,
                height: h,
            };
            let src = std::slice::from_raw_parts(slots[job.slot].ptr, (w * h * 4) as usize);
            bgra_to_yuv420(&mut planar, src, w * 4, YuvRange::Limited, YuvStandardMatrix::Bt709, YuvConversionMode::Balanced)
                .map_err(|e| anyhow!("convert: {e:?}"))?;
        }
        let t_convert = now_ns();
        // Fidelity runs: keep a copy of every Nth captured frame; n equals the frame number the encoder assigns.
        let dump = if dump_every > 0 && n.is_multiple_of(dump_every) {
            // SAFETY: slot still owned by this thread until it is released below.
            Some(unsafe { std::slice::from_raw_parts(slots[job.slot].ptr, (w * h * 4) as usize) }.to_vec())
        } else {
            None
        };
        let _ = free_tx.send(job.slot);
        if out_tx.send(ConvJob { dump, yuv: frame, t_damage: job.t_damage, t_capture: job.t_capture, t_convert, resync: job.resync }).is_err() {
            return Ok(());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- encode thread

fn open_encoder(cfg: &Cfg, kbps: u32, fps: u32, w: u32, h: u32) -> Result<ffmpeg::encoder::Video> {
    let codec = ffmpeg::encoder::find_by_name("libx264").context("libx264 not found")?;
    let ctx = ffmpeg::codec::context::Context::new_with_codec(codec);
    let mut enc = ctx.encoder().video()?;
    enc.set_width(w);
    enc.set_height(h);
    enc.set_format(ffmpeg::format::Pixel::YUV420P);
    enc.set_time_base((1, fps as i32));
    enc.set_frame_rate(Some((fps as i32, 1)));
    enc.set_max_b_frames(0);
    enc.set_flags(ffmpeg::codec::Flags::LOW_DELAY);
    let bufsize = ((kbps as f64 / fps as f64) * cfg.vbv_frames).max(1.0) as u32; // kbit; one frame by default
    let mut params = format!(
        "crf={}:vbv-maxrate={}:vbv-bufsize={}:keyint={}:bframes=0:rc-lookahead=0:sync-lookahead=0:repeat-headers=1:annexb=1:aud=0:threads={}:sliced-threads={}:intra-refresh={}",
        cfg.crf,
        kbps,
        bufsize,
        cfg.keyint,
        cfg.threads,
        cfg.sliced as u8,
        cfg.intra_refresh as u8,
    );
    if !cfg.intra_refresh {
        params.push_str(":scenecut=0");
    }
    if cfg.vui {
        params.push_str(":colorprim=bt709:transfer=bt709:colormatrix=bt709:fullrange=off");
    }
    let mut opts = ffmpeg::Dictionary::new();
    opts.set("preset", &cfg.preset);
    opts.set("tune", "zerolatency");
    opts.set("forced-idr", "1");
    opts.set("x264-params", &params);
    Ok(enc.open_with(opts)?)
}

fn fps_for(cfg: &Cfg, kbps: u32) -> u32 {
    (kbps / 100).clamp(10, cfg.max_fps)
}

fn encode_thread(
    cfg: Cfg,
    sh: Arc<Shared>,
    in_rx: Receiver<ConvJob>,
    yuv_free_tx: Sender<ffmpeg::frame::Video>,
    out_tx: tokio::sync::mpsc::Sender<OutFrame>,
    pool_rx: Receiver<Vec<u8>>,
    w: u32,
    h: u32,
) -> Result<()> {
    let mut cur_kbps = sh.kbps.load(Relaxed);
    let mut cur_fps = fps_for(&cfg, cur_kbps);
    let mut enc = open_encoder(&cfg, cur_kbps, cur_fps, w, h)?;
    let mut frame_no: u32 = 0;
    let mut pkt = ffmpeg::Packet::empty();
    let mut force = true;
    for mut job in in_rx {
        let kbps = sh.kbps.load(Relaxed);
        if kbps != cur_kbps {
            // Rate class changed: reopen the encoder (IDR follows). One-frame VBV keeps that IDR small.
            cur_kbps = kbps;
            cur_fps = fps_for(&cfg, kbps);
            enc = open_encoder(&cfg, cur_kbps, cur_fps, w, h)?;
            sh.enc_restarts.fetch_add(1, Relaxed);
            force = true;
        }
        let want_resync = sh.resync_flag.swap(false, Relaxed);
        if sh.force_idr.swap(false, Relaxed) || job.resync || force {
            force = false;
            job.yuv.set_kind(ffmpeg::picture::Type::I);
        } else {
            job.yuv.set_kind(ffmpeg::picture::Type::None);
        }
        job.yuv.set_pts(Some(frame_no as i64));
        let t_enc_start = now_ns();
        enc.send_frame(&job.yuv)?;
        let mut out: Option<(Vec<u8>, bool)> = None;
        loop {
            match enc.receive_packet(&mut pkt) {
                Ok(()) => {
                    let mut buf = pool_rx.try_recv().unwrap_or_default();
                    buf.clear();
                    buf.extend_from_slice(pkt.data().unwrap_or(&[]));
                    out = Some((buf, pkt.is_key()));
                }
                Err(ffmpeg::Error::Other { errno }) if errno == libc::EAGAIN => break,
                Err(ffmpeg::Error::Eof) => break,
                Err(e) => return Err(e.into()),
            }
        }
        let t_enc_end = now_ns();
        let _ = yuv_free_tx.send(job.yuv);
        let Some((payload, key)) = out else { continue };
        if let Some(raw) = job.dump.take() {
            let _ = std::fs::write(format!("{}/src-{:06}.bgra", cfg.dump_dir, frame_no), raw);
        }
        sh.frames_enc.fetch_add(1, Relaxed);
        sh.bytes_enc.fetch_add(payload.len() as u64, Relaxed);
        let hdr = FrameHeader {
            codec: wire::CODEC_H264,
            flags: (if key { wire::FLAG_KEY } else { 0 }) | (if job.resync || want_resync { wire::FLAG_RESYNC } else { 0 }),
            frame_no,
            len: payload.len() as u32,
            t_damage: job.t_damage,
            t_capture: job.t_capture,
            t_convert: job.t_convert,
            t_enc_start,
            t_enc_end,
            t_send: 0,
        };
        frame_no += 1;
        if out_tx.blocking_send(OutFrame { hdr, payload }).is_err() {
            return Ok(());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- network + congestion control

struct Inflight {
    t_send: u64,
    cancel: tokio::sync::oneshot::Sender<()>,
}

// (time of last ack, [(ack time, ack delay)] of the most recent frames)
type AckLog = Arc<Mutex<(u64, std::collections::VecDeque<(u64, u64)>)>>;
type InflightMap = Arc<Mutex<BTreeMap<u32, Inflight>>>;

async fn serve_connection(
    cfg: &Cfg,
    sh: &Arc<Shared>,
    conn: quinn::Connection,
    frame_rx: &mut tokio::sync::mpsc::Receiver<OutFrame>,
    cursor_rx: &mut tokio::sync::mpsc::Receiver<CursorMsg>,
    pool_tx: &Sender<Vec<u8>>,
) {
    let inflight: InflightMap = Arc::new(Mutex::new(BTreeMap::new()));
    // (time of last ack, ack delays in ns of the most recent frames)
    let acks: AckLog = Arc::new(Mutex::new((0, std::collections::VecDeque::new())));
    // Drop anything stale from before this connection and start with a fresh image.
    while frame_rx.try_recv().is_ok() {}
    while cursor_rx.try_recv().is_ok() {}
    sh.kbps.store(cfg.max_kbps, Relaxed);
    sh.min_interval_ns.store(1_000_000_000 / fps_for(cfg, cfg.max_kbps) as u64, Relaxed);
    sh.force_idr.store(true, Relaxed);
    sh.conn_epoch.fetch_add(1, Relaxed);

    // Clock probe responder (NTP-style, over QUIC datagrams): echo t1, add server receive time t2 and send time t3.
    {
        let c = conn.clone();
        tokio::spawn(async move {
            while let Ok(d) = c.read_datagram().await {
                let t2 = now_ns();
                if d.len() < 8 {
                    continue;
                }
                let mut r = Vec::with_capacity(24);
                r.extend_from_slice(&d[..8]);
                r.extend_from_slice(&t2.to_le_bytes());
                r.extend_from_slice(&now_ns().to_le_bytes());
                let _ = c.send_datagram(r.into());
            }
        });
    }

    // Cursor channel: one long-lived unidirectional stream.
    let cconn = conn.clone();
    let cursor_task = {
        let (ctx, mut crx) = tokio::sync::mpsc::channel::<CursorMsg>(256);
        // forward from the shared receiver for the lifetime of this connection
        let fwd = async move {
            while let Some(m) = cursor_rx.recv().await {
                if ctx.send(m).await.is_err() {
                    break;
                }
            }
        };
        let writer = async move {
            let Ok(mut s) = cconn.open_uni().await else { return };
            if s.write_all(&[wire::KIND_CURSOR]).await.is_err() {
                return;
            }
            let mut buf = Vec::new();
            while let Some(m) = crx.recv().await {
                buf.clear();
                match m {
                    CursorMsg::Shape { hash, w, h, xhot, yhot, argb } => {
                        let len = 8 + 8 + argb.len() * 4;
                        buf.push(wire::CUR_SHAPE);
                        buf.extend_from_slice(&(len as u32).to_le_bytes());
                        buf.extend_from_slice(&hash.to_le_bytes());
                        for v in [w, h, xhot, yhot] {
                            buf.extend_from_slice(&v.to_le_bytes());
                        }
                        for p in argb {
                            buf.extend_from_slice(&p.to_le_bytes());
                        }
                    }
                    CursorMsg::Pos { x, y, t } => {
                        buf.push(wire::CUR_POS);
                        buf.extend_from_slice(&12u32.to_le_bytes());
                        buf.extend_from_slice(&x.to_le_bytes());
                        buf.extend_from_slice(&y.to_le_bytes());
                        buf.extend_from_slice(&t.to_le_bytes());
                    }
                }
                if s.write_all(&buf).await.is_err() {
                    return;
                }
            }
        };
        async move {
            tokio::select! { _ = fwd => {}, _ = writer => {} }
        }
    };
    let mut cursor_task = Box::pin(cursor_task);

    // Base RTT: 20th percentile of the smoothed RTT over the last ~10 s (robust to jitter and to the
    // initial RTT guess; a plain minimum made jittery links look permanently congested).
    let mut rtt_hist: std::collections::VecDeque<u64> = std::collections::VecDeque::new();
    let mut rtt_hist_at = 0u64;
    let mut base_rtt_ms = 0u64;
    let mut last_change = now_ns();
    let mut good_since = now_ns();
    let mut tick_active = true;
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(4));
    // Bitrate ladder (kbit/s): one step per controller decision, so the encoder is reopened rarely.
    let ladder: Vec<u32> = [500u32, 1000, 1500, 2000, 3000, 4000, 6000, 8000, 10_000, 15_000, 20_000, 30_000, 50_000]
        .into_iter()
        .filter(|k| *k < cfg.max_kbps)
        .chain(std::iter::once(cfg.max_kbps))
        .collect();
    let mut level = ladder.len() - 1;
    let mut block_until = vec![0u64; ladder.len()];
    let mut backoff_ns = 2_000_000_000u64;
    let mut kbps;
    let mut cursor_done = false;

    loop {
        tokio::select! {
            _ = &mut cursor_task, if !cursor_done => { cursor_done = true; }
            _ = conn.closed() => { break; }
            _ = tick.tick() => {
                // --- congestion controller (sender side, no client feedback needed) ---
                let st = conn.stats();
                let rtt = st.path.rtt.as_millis() as u64;
                sh.rtt_ms.store(rtt as u32, Relaxed);
                let now = now_ns();
                let (oldest, n) = {
                    let m = inflight.lock().unwrap();
                    (m.values().map(|i| i.t_send).min(), m.len())
                };
                sh.inflight.store(n as u32, Relaxed);
                // Idle: slow the controller tick down so an idle desktop costs ~0 CPU.
                if (n > 0) != tick_active {
                    tick_active = n > 0;
                    tick = tokio::time::interval(std::time::Duration::from_millis(if tick_active { 4 } else { 100 }));
                }
                if acks.lock().unwrap().0 != 0 && now - rtt_hist_at >= 100_000_000 {
                    rtt_hist_at = now;
                    rtt_hist.push_back(rtt);
                    if rtt_hist.len() > 100 {
                        rtt_hist.pop_front();
                    }
                    let mut v: Vec<u64> = rtt_hist.iter().copied().collect();
                    v.sort_unstable();
                    base_rtt_ms = if v.len() < 5 { rtt } else { v[v.len() / 5] };
                }
                let base = if base_rtt_ms == 0 { rtt } else { base_rtt_ms };
                // Queueing estimate that ignores single-packet loss recovery: median ack delay of the
                // last frames (minus the base RTT), or the time since anything was acked if all stalled.
                let (med, last_ack) = {
                    let a = acks.lock().unwrap();
                    // only acks from the last second describe the current queue
                    let mut v: Vec<u64> = a.1.iter().filter(|(t, _)| now - *t < 1_000_000_000).map(|(_, d)| *d).collect();
                    v.sort_unstable();
                    (v.get(v.len() / 2).copied().unwrap_or(0), a.0)
                };
                let med = if n == 0 && now - last_ack > 500_000_000 { 0 } else { med };
                let q_med = med.saturating_sub(base * 1_000_000) / 1_000_000;
                let stall = match oldest {
                    Some(t) => (now - t.max(last_ack)) / 1_000_000,
                    None => 0,
                }
                .saturating_sub(base);
                let lag_ms = q_med.max(stall);
                sh.lag_ms.store(lag_ms as u32, Relaxed);
                if !cfg.congestion { continue; }
                if lag_ms > 100 && now - last_change > 150_000_000 {
                    // Stale: cancel queued frame streams and send a fresh full image.
                    if std::env::var_os("S2_DEBUG").is_some() {
                        eprintln!("cancel: lag={lag_ms} q_med={q_med} stall={stall} base={base} n={n} rtt={rtt} med={med}");
                    }
                    let mut m = inflight.lock().unwrap();
                    let cancelled = m.len() as u64;
                    for (_, i) in std::mem::take(&mut *m) { let _ = i.cancel.send(()); }
                    drop(m);
                    while let Ok(f) = frame_rx.try_recv() { let _ = pool_tx.send(f.payload); sh.cancelled_streams.fetch_add(1, Relaxed); }
                    sh.cancelled_streams.fetch_add(cancelled, Relaxed);
                    sh.cancels.fetch_add(1, Relaxed);
                    sh.force_idr.store(true, Relaxed);
                    sh.resync_flag.store(true, Relaxed);
                    ladder_down(&mut level, 2, &mut block_until, &mut backoff_ns, now);
                    kbps = ladder[level];
                    apply_rate(cfg, sh, kbps);
                    last_change = now;
                    good_since = now;
                } else if lag_ms > 40 && now - last_change > 250_000_000 {
                    ladder_down(&mut level, 1, &mut block_until, &mut backoff_ns, now);
                    kbps = ladder[level];
                    apply_rate(cfg, sh, kbps);
                    last_change = now;
                    good_since = now;
                } else if lag_ms > 15 {
                    good_since = now;
                } else if now - good_since > 700_000_000 && now - last_change > 700_000_000 && level + 1 < ladder.len() && now >= block_until[level + 1] {
                    level += 1;
                    if level + 1 == ladder.len() {
                        backoff_ns = 2_000_000_000;
                    }
                    kbps = ladder[level];
                    apply_rate(cfg, sh, kbps);
                    last_change = now;
                }
            }
            Some(mut f) = frame_rx.recv() => {
                f.hdr.t_send = now_ns();
                let Ok(mut s) = conn.open_uni().await else { break };
                let (ctx, crx) = tokio::sync::oneshot::channel();
                inflight.lock().unwrap().insert(f.hdr.frame_no, Inflight { t_send: f.hdr.t_send, cancel: ctx });
                let inf = inflight.clone();
                let sh2 = sh.clone();
                let pool = pool_tx.clone();
                let acks2 = acks.clone();
                let t_sent = f.hdr.t_send;
                tokio::spawn(async move {
                    let hdr = f.hdr.encode();
                    let n = f.hdr.frame_no;
                    let total = (hdr.len() + f.payload.len()) as u64;
                    let work = async {
                        s.write_all(&hdr).await.ok()?;
                        s.write_all(&f.payload).await.ok()?;
                        s.finish().ok()?;
                        sh2.bytes_sent.fetch_add(total, Relaxed);
                        sh2.frames_sent.fetch_add(1, Relaxed);
                        let _ = s.stopped().await;
                        let t = now_ns();
                        let mut a = acks2.lock().unwrap();
                        a.0 = t;
                        a.1.push_back((t, t - t_sent));
                        if a.1.len() > 8 {
                            a.1.pop_front();
                        }
                        Some(())
                    };
                    tokio::select! {
                        _ = work => {}
                        _ = crx => { /* cancelled: reset happens by dropping below */ }
                    }
                    let _ = s.reset(wire::RESET_STALE.into());
                    inf.lock().unwrap().remove(&n);
                    let _ = pool.send(f.payload);
                });
            }
        }
    }
    // Connection ended: cancel everything in flight.
    for (_, i) in std::mem::take(&mut *inflight.lock().unwrap()) {
        let _ = i.cancel.send(());
    }
}

/// Step down `n` levels and forbid probing back up to the failed level for `backoff` (doubles on repeats).
fn ladder_down(level: &mut usize, n: usize, block_until: &mut [u64], backoff_ns: &mut u64, now: u64) {
    let failed = *level;
    block_until[failed] = now + *backoff_ns;
    *backoff_ns = (*backoff_ns * 2).min(8_000_000_000);
    *level = level.saturating_sub(n);
}

fn apply_rate(cfg: &Cfg, sh: &Shared, kbps: u32) {
    sh.kbps.store(kbps, Relaxed);
    sh.min_interval_ns.store(1_000_000_000 / fps_for(cfg, kbps) as u64, Relaxed);
    sh.rate_changes.fetch_add(1, Relaxed);
}

fn make_endpoint(addr: SocketAddr) -> Result<quinn::Endpoint> {
    let cert = rcgen::generate_simple_self_signed(vec!["s2".to_string()])?;
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key.into())?;
    tls.alpn_protocols = vec![b"hx/1".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut tc = quinn::TransportConfig::default();
    tc.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    tc.max_concurrent_uni_streams(0u32.into());
    tc.initial_rtt(std::time::Duration::from_millis(100));
    tc.send_window(32 * 1024 * 1024);
    tc.stream_receive_window((8u32 * 1024 * 1024).into());
    tc.receive_window((64u32 * 1024 * 1024).into());
    sc.transport_config(Arc::new(tc));
    Ok(quinn::Endpoint::server(sc, addr)?)
}

// ---------------------------------------------------------------- stats thread

fn stats_thread(path: String, sh: Arc<Shared>) {
    let Ok(mut f) = std::fs::File::create(&path) else { return };
    let _ = writeln!(
        f,
        "ts_ns,proc_cpu_ns,cg_cpu_us,captures,frames_enc,bytes_enc,frames_sent,bytes_sent,kbps,fps_cap,lag_ms,rtt_ms,inflight,cancels,cancelled_streams,rate_changes,enc_restarts"
    );
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let ivl = sh.min_interval_ns.load(Relaxed).max(1);
        let _ = writeln!(
            f,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            now_ns(),
            process_cpu_ns(),
            cgroup_cpu_usec().unwrap_or(0),
            sh.captures.load(Relaxed),
            sh.frames_enc.load(Relaxed),
            sh.bytes_enc.load(Relaxed),
            sh.frames_sent.load(Relaxed),
            sh.bytes_sent.load(Relaxed),
            sh.kbps.load(Relaxed),
            1_000_000_000 / ivl,
            sh.lag_ms.load(Relaxed),
            sh.rtt_ms.load(Relaxed),
            sh.inflight.load(Relaxed),
            sh.cancels.load(Relaxed),
            sh.cancelled_streams.load(Relaxed),
            sh.rate_changes.load(Relaxed),
            sh.enc_restarts.load(Relaxed),
        );
        let _ = f.flush();
    }
}

// ---------------------------------------------------------------- main

fn main() -> Result<()> {
    let a = Args::parse();
    let cfg = Cfg {
        listen: a.get_str("listen", "0.0.0.0:4433").parse()?,
        display: a.get_str("display", ":10"),
        max_fps: a.get("fps", 60),
        crf: a.get("crf", 23),
        max_kbps: a.get("kbps", 20_000),
        threads: a.get("threads", 4),
        sliced: a.get::<u32>("sliced", 1) == 1,
        intra_refresh: a.get::<u32>("intra-refresh", 1) == 1,
        keyint: a.get("keyint", 120),
        preset: a.get_str("preset", "ultrafast"),
        congestion: a.get::<u32>("cc", 1) == 1,
        stats_path: a.get_str("stats", "/tmp/s2-server-stats.csv"),
        slots: a.get("slots", 3),
        cursor: a.get::<u32>("cursor", 1) == 1,
        dump_dir: a.get_str("dump", ""),
        dump_every: a.get("dump-every", 40),
        vui: a.get::<u32>("vui", 0) == 1,
        vbv_frames: a.get("vbv-frames", 1.0),
    };
    let dump_every = if cfg.dump_dir.is_empty() { 0 } else { cfg.dump_every };
    ffmpeg::init()?;
    ffmpeg::util::log::set_level(ffmpeg::util::log::Level::Warning);

    // Screen geometry
    let (c0, sn) = RustConnection::connect(Some(&cfg.display))?;
    let scr = &c0.setup().roots[sn];
    let (w, h) = (scr.width_in_pixels, scr.height_in_pixels);
    drop(c0);
    eprintln!("s2-server: display {} {}x{}, x264 preset={} threads={} sliced={} intra_refresh={} crf={} max={}kbps", cfg.display, w, h, cfg.preset, cfg.threads, cfg.sliced, cfg.intra_refresh, cfg.crf, cfg.max_kbps);

    // SysV shm slots shared with Xorg (same container, same IPC namespace).
    let size = w as usize * h as usize * 4;
    let mut slots = Vec::new();
    for _ in 0..cfg.slots {
        // SAFETY: standard SysV shm creation; marked for removal once attached by both sides.
        unsafe {
            let id = libc::shmget(libc::IPC_PRIVATE, size, libc::IPC_CREAT | 0o600);
            anyhow::ensure!(id >= 0, "shmget failed");
            let p = libc::shmat(id, std::ptr::null(), 0);
            anyhow::ensure!(p as isize != -1, "shmat failed");
            slots.push(ShmSlot { ptr: p as *mut u8, shmid: id });
        }
    }
    let slots = Arc::new(slots);

    let sh = Arc::new(Shared::default());
    sh.kbps.store(cfg.max_kbps, Relaxed);
    sh.min_interval_ns.store(1_000_000_000 / fps_for(&cfg, cfg.max_kbps) as u64, Relaxed);

    // Buffer pools / lock-free queues (crossbeam bounded array channels).
    let (free_tx, free_rx) = bounded::<usize>(cfg.slots);
    for i in 0..cfg.slots {
        free_tx.send(i)?;
    }
    let (job_tx, job_rx) = bounded::<CapJob>(cfg.slots);
    let (yuv_free_tx, yuv_free_rx) = bounded::<ffmpeg::frame::Video>(3);
    for _ in 0..3 {
        yuv_free_tx.send(ffmpeg::frame::Video::new(ffmpeg::format::Pixel::YUV420P, w as u32, h as u32))?;
    }
    let (conv_tx, conv_rx) = bounded::<ConvJob>(2);
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<OutFrame>(8);
    let (cursor_tx, mut cursor_rx) = tokio::sync::mpsc::channel::<CursorMsg>(256);
    let (pool_tx, pool_rx) = bounded::<Vec<u8>>(64);
    for _ in 0..16 {
        pool_tx.send(Vec::with_capacity(512 * 1024))?;
    }

    {
        let (cfg, sh, slots, free_rx) = (cfg.clone(), sh.clone(), slots.clone(), free_rx);
        std::thread::Builder::new().name("capture".into()).spawn(move || {
            if let Err(e) = capture_thread(cfg, sh, slots, free_rx, job_tx, cursor_tx, w, h) {
                eprintln!("capture thread: {e:#}");
                std::process::exit(1);
            }
        })?;
    }
    {
        let slots = slots.clone();
        std::thread::Builder::new().name("convert".into()).spawn(move || {
            if let Err(e) = convert_thread(job_rx, slots, free_tx, yuv_free_rx, conv_tx, w as u32, h as u32, dump_every) {
                eprintln!("convert thread: {e:#}");
                std::process::exit(1);
            }
        })?;
    }
    {
        let (cfg, sh) = (cfg.clone(), sh.clone());
        std::thread::Builder::new().name("encode".into()).spawn(move || {
            if let Err(e) = encode_thread(cfg, sh, conv_rx, yuv_free_tx, out_tx, pool_rx, w as u32, h as u32) {
                eprintln!("encode thread: {e:#}");
                std::process::exit(1);
            }
        })?;
    }
    {
        let (p, sh) = (cfg.stats_path.clone(), sh.clone());
        std::thread::Builder::new().name("stats".into()).spawn(move || stats_thread(p, sh))?;
    }

    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    rt.block_on(async move {
        let ep = make_endpoint(cfg.listen)?;
        eprintln!("s2-server: listening on {}", cfg.listen);
        while let Some(incoming) = ep.accept().await {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("accept: {e}");
                    continue;
                }
            };
            eprintln!("s2-server: client {}", conn.remote_address());
            serve_connection(&cfg, &sh, conn, &mut out_rx, &mut cursor_rx, &pool_tx).await;
            eprintln!("s2-server: client gone");
        }
        Ok::<_, anyhow::Error>(())
    })
}
