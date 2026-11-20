//! Spike S1: Slint video presentation paths.
//!
//! * `--path a`: wgpu texture -> `slint::Image` (Slint unstable wgpu integration)
//! * `--path b`: OpenGL texture (EGL dma-buf import on GPU, glTexSubImage2D otherwise) ->
//!   `BorrowedOpenGLTextureBuilder` on Slint's femtovg OpenGL renderer
//! * `--path c`: CPU RGBA `SharedPixelBuffer` per frame (fallback)

mod decode;
mod path_gl;
mod path_wgpu;
mod stats;
mod vk_import;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, ValueEnum};
use decode::{DecodeMode, DecodedFrame, Decoder, DecoderOpts, Mailbox, OutKind, Payload};
use serde_json::json;
use slint::{ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel};
use stats::{Stats, cpu_snapshot, cpu_usage, dist, histogram, stddev};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

slint::include_modules!();

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
enum PathArg {
    /// wgpu texture imported as slint::Image
    A,
    /// OpenGL texture (EGL dma-buf import) in Slint's OpenGL renderer
    B,
    /// CPU upload of an RGBA SharedPixelBuffer per frame
    C,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
enum DecodeArg {
    Auto,
    Vaapi,
    Software,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
enum GlArg {
    /// OpenGL ES 3.0 context
    Es3,
    /// Desktop OpenGL 3.3 context
    Gl33,
}

#[derive(Parser, Debug, Clone)]
#[command(about = "S1: Slint video presentation spike", version)]
struct Args {
    /// Presentation path.
    #[arg(long, value_enum, default_value = "c")]
    path: PathArg,
    /// Input clip (see gen-clip.sh).
    #[arg(long, default_value = "clip-1080p60.mp4")]
    input: String,
    /// Decode backend.
    #[arg(long, value_enum, default_value = "auto")]
    decode: DecodeArg,
    /// Hardware decode + download to CPU instead of DMA-BUF export (paths a/b).
    #[arg(long)]
    no_dmabuf: bool,
    /// Run for this many seconds (after warm-up), print a JSON summary and exit.
    #[arg(long, value_name = "SECONDS")]
    bench: Option<f64>,
    /// Warm-up seconds excluded from the --bench statistics.
    #[arg(long, default_value_t = 3.0)]
    warmup: f64,
    /// Write the JSON summary to this file as well as stdout.
    #[arg(long)]
    json_out: Option<String>,
    /// Window size, WIDTHxHEIGHT (physical pixels).
    #[arg(long, default_value = "1920x1080")]
    window: String,
    /// Source frame rate to pace the decoder at.
    #[arg(long, default_value_t = 60.0)]
    fps: f64,
    /// Software decode slice threads.
    #[arg(long, default_value_t = 4)]
    sw_threads: usize,
    /// Decode as fast as possible instead of real-time (measures decode headroom).
    #[arg(long)]
    unpaced: bool,
    /// Wait for GPU completion after our upload/convert pass and after Slint's render
    /// (makes timings include GPU work; adds a pipeline stall).
    #[arg(long)]
    sync: bool,
    /// Hide the stats overlay (measure pure video cost).
    #[arg(long)]
    no_overlay: bool,
    /// Send synthetic clicks to the probe button every 250 ms (always on in --bench).
    #[arg(long)]
    auto_probe: bool,
    /// OpenGL context flavour requested from Slint (paths b and c).
    #[arg(long, value_enum, default_value = "es3")]
    gl: GlArg,
    /// Print VAAPI / environment capability detection and exit.
    #[arg(long)]
    detect: bool,
    /// Path a: allow a CPU Vulkan adapter (lavapipe). Sets SLINT_WGPU_CPU=1. For GPU-less machines
    /// only; results are then software-rendered and not representative.
    #[arg(long)]
    allow_cpu_adapter: bool,
}

// S1 pass thresholds.
const T_FPS_MIN: f64 = 59.0;
const T_PACING_PCT: f64 = 98.0; // % of intervals within 13.3..20.0 ms
const T_DROP_MAX_PCT: f64 = 1.0;
const T_D2P_P95_MS: f64 = 8.0;
const T_EVENT_P95_MS: f64 = 33.4;
const T_LOOP_LAG_P99_MS: f64 = 20.0;

struct Awaiting {
    decode_done: Instant,
}

struct UiState {
    awaiting: Option<Awaiting>,
    before: Instant,
    last_present: Option<Instant>,
    last_render: Option<Instant>,
    probe_t0: Option<Instant>,
    probe_last_ms: f64,
    probe_clicks: i32,
    error: Option<String>,
    renderer: String,
    presenter_info: String,
}

struct Flag(AtomicBool);
impl Flag {
    fn get(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
    fn set(&self, v: bool) {
        self.0.store(v, Ordering::Relaxed)
    }
}

enum Presenter {
    Gl(Box<path_gl::GlPresenter>),
    Wgpu(Box<path_wgpu::WgpuPresenter>),
    None,
}

fn parse_size(s: &str) -> Result<(u32, u32)> {
    let (w, h) = s.split_once('x').ok_or_else(|| anyhow!("--window must be WIDTHxHEIGHT"))?;
    Ok((w.parse()?, h.parse()?))
}

fn is_software_renderer(s: &str) -> bool {
    let l = s.to_lowercase();
    ["llvmpipe", "softpipe", "lavapipe", "swrast", "software", "cpu"].iter().any(|k| l.contains(k))
}

fn main() {
    let args = Args::parse();
    if args.detect {
        print!("{}", decode::detect_report());
        println!("DISPLAY={:?} WAYLAND_DISPLAY={:?}", std::env::var("DISPLAY").ok(), std::env::var("WAYLAND_DISPLAY").ok());
        return;
    }
    let path_name = format!("{:?}", args.path).to_lowercase();
    if args.allow_cpu_adapter {
        // SAFETY: called first thing in main, before any other thread exists.
        unsafe { std::env::set_var("SLINT_WGPU_CPU", "1") };
    }
    match run(&args) {
        Ok(summary) => {
            let text = serde_json::to_string_pretty(&summary).unwrap();
            println!("{text}");
            if let Some(p) = &args.json_out {
                let _ = std::fs::write(p, &text);
            }
        }
        Err(e) => {
            let summary = json!({
                "spike": "s1", "path": path_name, "status": "unavailable",
                "reason": format!("{e:#}"),
                "decode_mode": format!("{:?}", args.decode).to_lowercase(),
                "loadavg": stats::loadavg(),
            });
            let text = serde_json::to_string_pretty(&summary).unwrap();
            eprintln!("[s1] path {path_name} cannot run: {e:#}");
            println!("{text}");
            if let Some(p) = &args.json_out {
                let _ = std::fs::write(p, &text);
            }
            std::process::exit(2);
        }
    }
}

fn run(args: &Args) -> Result<serde_json::Value> {
    let (win_w, win_h) = parse_size(&args.window)?;
    let out = match args.path {
        PathArg::C => OutKind::Rgba,
        _ => OutKind::Planes { dmabuf: !args.no_dmabuf },
    };
    let mode = match args.decode {
        DecodeArg::Auto => DecodeMode::Auto,
        DecodeArg::Vaapi => DecodeMode::Vaapi,
        DecodeArg::Software => DecodeMode::Software,
    };
    let decoder = Decoder::open(DecoderOpts {
        input: args.input.clone(),
        mode,
        out,
        fps: args.fps,
        threads: args.sw_threads,
        realtime: !args.unpaced,
    })
    .context("decoder")?;
    let decoder_desc = decoder.info.description.clone();
    let hw_active = decoder.info.hw_active;
    let dmabuf_zero_copy = hw_active && matches!(out, OutKind::Planes { dmabuf: true });
    eprintln!("[s1] decoder: {decoder_desc} ({}x{})", decoder.info.width, decoder.info.height);

    // ---- backend selection per path ----
    let selector = slint::BackendSelector::new().backend_name("winit".into());
    let selector = match args.path {
        PathArg::A => {
            let cfg = if dmabuf_zero_copy { vk_import::manual_config().context("wgpu device with DMA-BUF import extensions")? } else { slint::wgpu_30::WGPUConfiguration::default() };
            selector.require_wgpu_30(cfg)
        }
        _ => {
            let s = selector.renderer_name("femtovg".into());
            match args.gl {
                GlArg::Es3 => s.require_opengl_es_with_version(3, 0),
                GlArg::Gl33 => s.require_opengl_with_version(3, 3),
            }
        }
    };
    selector.select().map_err(|e| anyhow!("Slint backend selection failed for path {:?}: {e}", args.path))?;

    let ui = App::new().map_err(|e| anyhow!("{e}"))?;
    ui.window().set_size(slint::PhysicalSize::new(win_w, win_h));
    ui.set_show_overlay(!args.no_overlay);
    ui.set_path_label(
        format!(
            "path {} | {} | {}",
            format!("{:?}", args.path).to_lowercase(),
            match args.path {
                PathArg::A => "wgpu texture -> slint::Image",
                PathArg::B => "GL texture -> BorrowedOpenGLTexture",
                PathArg::C => "CPU SharedPixelBuffer",
            },
            if hw_active { "VAAPI" } else { "sw decode" }
        )
        .into(),
    );

    let stats = Arc::new(Stats::new());
    let mailbox = Mailbox::new();
    let stop = Arc::new(AtomicBool::new(false));
    let st = Arc::new(Mutex::new(UiState {
        awaiting: None,
        before: Instant::now(),
        last_present: None,
        last_render: None,
        probe_t0: None,
        probe_last_ms: 0.0,
        probe_clicks: 0,
        error: None,
        renderer: String::new(),
        presenter_info: String::new(),
    }));
    let measuring = Arc::new(Flag(AtomicBool::new(true)));

    // ---- probe button ----
    {
        let st = st.clone();
        let weak = ui.as_weak();
        ui.on_probe_clicked(move || {
            let mut s = st.lock().unwrap();
            s.probe_t0 = Some(Instant::now());
            s.probe_clicks += 1;
            if let Some(ui) = weak.upgrade() {
                ui.set_probe_count(s.probe_clicks);
            }
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_toggle_overlay(move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_show_overlay(!ui.get_show_overlay());
            }
        });
    }

    // ---- rendering notifier ----
    let presenter: Rc<RefCell<Presenter>> = Rc::new(RefCell::new(Presenter::None));
    {
        let (st, stats, mailbox, weak, presenter, measuring) = (st.clone(), stats.clone(), mailbox.clone(), ui.as_weak(), presenter.clone(), measuring.clone());
        let (path, sync, want_dmabuf) = (args.path, args.sync, dmabuf_zero_copy);
        ui.window()
            .set_rendering_notifier(move |state, api| match state {
                slint::RenderingState::RenderingSetup => {
                    let res: Result<(Presenter, String)> = (|| match api {
                        slint::GraphicsAPI::NativeOpenGL { get_proc_address } => {
                            if path == PathArg::B {
                                let p = path_gl::GlPresenter::new(get_proc_address, sync)?;
                                let info = p.info.clone();
                                Ok((Presenter::Gl(Box::new(p)), info))
                            } else {
                                // Path c: just identify the GL renderer.
                                use glow::HasContext;
                                // SAFETY: context is current during RenderingSetup.
                                let r = unsafe {
                                    let gl = glow::Context::from_loader_function_cstr(|s| get_proc_address(s));
                                    format!("GL {} / {}", gl.get_parameter_string(glow::VERSION), gl.get_parameter_string(glow::RENDERER))
                                };
                                Ok((Presenter::None, r))
                            }
                        }
                        slint::GraphicsAPI::WGPU30 { device, queue, .. } => {
                            let ai = device.adapter_info();
                            let name = format!("{} ({:?}, {:?})", ai.name, ai.device_type, ai.backend);
                            let p = path_wgpu::WgpuPresenter::new(device.clone(), queue.clone(), name.clone(), sync, want_dmabuf)?;
                            let info = p.info.clone();
                            Ok((Presenter::Wgpu(Box::new(p)), info))
                        }
                        _ => bail!("unexpected graphics API from Slint"),
                    })();
                    let mut s = st.lock().unwrap();
                    match res {
                        Ok((p, info)) => {
                            s.renderer = info.clone();
                            s.presenter_info = info;
                            *presenter.borrow_mut() = p;
                        }
                        Err(e) => {
                            s.error = Some(format!("presenter setup: {e:#}"));
                            let _ = slint::quit_event_loop();
                        }
                    }
                }
                slint::RenderingState::BeforeRendering => {
                    let mut s = st.lock().unwrap();
                    s.before = Instant::now();
                    let mut pr = presenter.borrow_mut();
                    let res: Result<Option<slint::Image>> = match &mut *pr {
                        Presenter::None => Ok(None),
                        p => (|| {
                            let Some(fr) = mailbox.take() else { return Ok(None) };
                            let tp = Instant::now();
                            let img = match p {
                                Presenter::Gl(g) => g.prepare(&fr)?,
                                Presenter::Wgpu(w) => w.prepare(&fr)?,
                                Presenter::None => unreachable!(),
                            };
                            let handed = Instant::now();
                            let new = Awaiting { decode_done: fr.decode_done };
                            let replaced = s.awaiting.replace(new).is_some();
                            if measuring.get() {
                                stats.with(|x| {
                                    x.prepare_ms.push((handed - tp).as_secs_f64() * 1e3);
                                    x.handoff_ms.push((handed - fr.decode_done).as_secs_f64() * 1e3);
                                    if replaced {
                                        x.frames_dropped += 1;
                                    }
                                });
                            }
                            Ok(Some(img))
                        })(),
                    };
                    match res {
                        Ok(Some(img)) => {
                            if let Some(ui) = weak.upgrade() {
                                ui.set_video_frame(img);
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            s.error = Some(format!("{e:#}"));
                            let _ = slint::quit_event_loop();
                        }
                    }
                }
                slint::RenderingState::AfterRendering => {
                    if let Presenter::Gl(g) = &*presenter.borrow() {
                        g.finish_render();
                    }
                    let now = Instant::now();
                    let mut s = st.lock().unwrap();
                    let render_ms = (now - s.before).as_secs_f64() * 1e3;
                    let aw = s.awaiting.take();
                    let prev_present = s.last_present;
                    let prev_render = s.last_render.replace(now);
                    let probe = s.probe_t0.take();
                    if let Some(p) = probe {
                        s.probe_last_ms = (now - p).as_secs_f64() * 1e3;
                    }
                    if aw.is_some() {
                        s.last_present = Some(now);
                    }
                    let probe_ms = s.probe_last_ms;
                    drop(s);
                    if !measuring.get() {
                        return;
                    }
                    stats.with(|x| {
                        if let Some(pr) = prev_render {
                            x.render_interval_ms.push((now - pr).as_secs_f64() * 1e3);
                        }
                        if let Some(a) = aw {
                            x.frames_presented += 1;
                            x.render_ms.push(render_ms);
                            x.decode_to_render_ms.push((now - a.decode_done).as_secs_f64() * 1e3);
                            if let Some(pp) = prev_present {
                                x.present_interval_ms.push((now - pp).as_secs_f64() * 1e3);
                            }
                        }
                        if probe.is_some() {
                            x.event_to_render_ms.push(probe_ms);
                        }
                    });
                }
                slint::RenderingState::RenderingTeardown => {
                    *presenter.borrow_mut() = Presenter::None;
                }
                _ => {}
            })
            .map_err(|e| anyhow!("set_rendering_notifier: {e:?}"))?;
    }

    // ---- decoder thread wiring ----
    let rgba_path = args.path == PathArg::C;
    let on_frame = {
        let (mailbox, weak, stats, st, measuring) = (mailbox.clone(), ui.as_weak(), stats.clone(), st.clone(), measuring.clone());
        move || {
            let (mailbox, stats, st, measuring) = (mailbox.clone(), stats.clone(), st.clone(), measuring.clone());
            let _ = slint::invoke_from_event_loop({
                let weak = weak.clone();
                move || {
                    let Some(ui) = weak.upgrade() else { return };
                    mailbox.pending.store(false, Ordering::Release);
                    if rgba_path {
                        // Path c: build the Slint image on the UI thread, straight from the pixel buffer.
                        if let Some(DecodedFrame { payload: Payload::Rgba(buf), decode_done, .. }) = mailbox.take() {
                            let img = slint::Image::from_rgba8(buf);
                            ui.set_video_frame(img);
                            let handed = Instant::now();
                            let replaced = st.lock().unwrap().awaiting.replace(Awaiting { decode_done }).is_some();
                            if measuring.get() {
                                stats.with(|x| {
                                    x.handoff_ms.push((handed - decode_done).as_secs_f64() * 1e3);
                                    if replaced {
                                        x.frames_dropped += 1;
                                    }
                                });
                            }
                        }
                    }
                    ui.window().request_redraw();
                }
            });
        }
    };
    let dec_stats = stats.clone();
    let dec_mailbox = mailbox.clone();
    let dec_stop = stop.clone();
    let dec_thread = std::thread::Builder::new()
        .name("decoder".into())
        .spawn(move || decoder.run(dec_mailbox, dec_stats, dec_stop, on_frame))
        .context("spawn decoder")?;

    // ---- timers: overlay refresh, loop lag, synthetic probe, bench control ----
    let mut timers: Vec<Timer> = Vec::new();
    // Event-loop lag probe.
    {
        let stats = stats.clone();
        let measuring = measuring.clone();
        let last = Rc::new(std::cell::Cell::new(Instant::now()));
        let t = Timer::default();
        t.start(TimerMode::Repeated, Duration::from_millis(5), move || {
            let now = Instant::now();
            let lag = (now - last.replace(now)).as_secs_f64() * 1e3 - 5.0;
            if measuring.get() {
                stats.with(|s| s.loop_lag_ms.push(lag.max(0.0)));
            }
        });
        timers.push(t);
    }
    // Synthetic clicks on the probe button.
    if args.bench.is_some() || args.auto_probe {
        let weak = ui.as_weak();
        let t = Timer::default();
        t.start(TimerMode::Repeated, Duration::from_millis(250), move || {
            let Some(ui) = weak.upgrade() else { return };
            let pos = slint::LogicalPosition::new(ui.get_probe_x(), ui.get_probe_y());
            let w = ui.window();
            w.dispatch_event(slint::platform::WindowEvent::PointerPressed { position: pos, button: slint::platform::PointerEventButton::Left });
            w.dispatch_event(slint::platform::WindowEvent::PointerReleased { position: pos, button: slint::platform::PointerEventButton::Left });
        });
        timers.push(t);
    }
    // Overlay refresh (2 Hz).
    {
        let (weak, stats, st) = (ui.as_weak(), stats.clone(), st.clone());
        let t = Timer::default();
        t.start(TimerMode::Repeated, Duration::from_millis(500), move || {
            let Some(ui) = weak.upgrade() else { return };
            let (text, bars) = stats.with(|s| {
                // Keep memory bounded in interactive mode.
                let tail = |v: &Vec<f64>, n: usize| v[v.len().saturating_sub(n)..].to_vec();
                let iv = tail(&s.present_interval_ms, 240);
                let d2r = dist(&tail(&s.decode_to_render_ms, 240));
                let dec = dist(&tail(&s.decode_ms, 240));
                let prep = dist(&tail(&s.prepare_ms, 240));
                let rnd = dist(&tail(&s.render_ms, 240));
                let ivd = dist(&iv);
                let fps = if ivd.mean > 0.0 { 1000.0 / ivd.mean } else { 0.0 };
                let text = format!(
                    "present {fps:.1} fps | interval p50 {:.1} p99 {:.1} ms (sd {:.2})\ndecode p50 {:.2} p95 {:.2} ms | prepare/upload p50 {:.2} | render p50 {:.2}\ndecode->render p50 {:.2} p95 {:.2} ms | dropped {} / decoded {}",
                    ivd.p50, ivd.p99, stddev(&iv), dec.p50, dec.p95, prep.p50, rnd.p50, d2r.p50, d2r.p95, s.frames_dropped, s.frames_decoded
                );
                let h = histogram(&iv);
                let max = *h.iter().max().unwrap_or(&1).max(&1) as f32;
                let labels = ["<14", "<15.5", "<17.5", "<20", "<25", "<33", "<50", ">50"];
                let bars: Vec<Bar> = h
                    .iter()
                    .enumerate()
                    .map(|(i, &c)| Bar { h: 56.0 * c as f32 / max, label: SharedString::from(labels[i]), hot: i != 1 && i != 2 })
                    .collect();
                (text, bars)
            });
            ui.set_stats_text(text.into());
            ui.set_bars(ModelRc::new(VecModel::from(bars)));
            let s = st.lock().unwrap();
            ui.set_probe_text(format!("last event->render {:.1} ms", s.probe_last_ms).into());
            let _ = ui.get_bars().row_count();
        });
        timers.push(t);
    }

    // Bench control: warm-up, then measure for N seconds, then quit.
    struct BenchResult {
        cpu: Option<(stats::CpuSnapshot, stats::CpuSnapshot)>,
        load: (String, String),
        wall: f64,
    }
    let bench_result: Rc<RefCell<Option<BenchResult>>> = Rc::new(RefCell::new(None));
    if let Some(secs) = args.bench {
        measuring.set(false);
        let (stats, measuring, bench_result) = (stats.clone(), measuring.clone(), bench_result.clone());
        let warm = Duration::from_secs_f64(args.warmup);
        let run = Duration::from_secs_f64(secs);
        let t = Timer::default();
        t.start(TimerMode::SingleShot, warm, {
            let (stats2, measuring2, bench_result2) = (stats.clone(), measuring.clone(), bench_result.clone());
            move || {
                stats2.reset();
                measuring2.set(true);
                let snap0 = cpu_snapshot();
                let load0 = stats::loadavg();
                let t_start = Instant::now();
                let (stats3, measuring3, bench_result3) = (stats2.clone(), measuring2.clone(), bench_result2.clone());
                let end = Timer::default();
                end.start(TimerMode::SingleShot, run, move || {
                    measuring3.set(false);
                    let snap1 = cpu_snapshot();
                    *bench_result3.borrow_mut() = Some(BenchResult { cpu: Some((snap0.clone(), snap1)), load: (load0.clone(), stats::loadavg()), wall: t_start.elapsed().as_secs_f64() });
                    let _ = &stats3;
                    let _ = slint::quit_event_loop();
                });
                // Keep the end timer alive for the duration of the run.
                std::mem::forget(end);
            }
        });
        timers.push(t);
    }

    ui.show().map_err(|e| anyhow!("{e}"))?;
    slint::run_event_loop().map_err(|e| anyhow!("{e}"))?;
    stop.store(true, Ordering::Relaxed);
    let _ = dec_thread.join();
    drop(timers);

    if let Some(e) = st.lock().unwrap().error.clone() {
        bail!("{e}");
    }

    // ---- summary ----
    let s = st.lock().unwrap();
    let br = bench_result.borrow();
    let samples = stats.inner.lock().unwrap();
    let wall = br.as_ref().map(|b| b.wall).unwrap_or(0.0);
    let present = dist(&samples.present_interval_ms);
    let in_band = samples.present_interval_ms.iter().filter(|&&x| (13.3..=20.0).contains(&x)).count() as f64
        / samples.present_interval_ms.len().max(1) as f64
        * 100.0;
    let presented_fps = if wall > 0.0 { samples.frames_presented as f64 / wall } else { 0.0 };
    let decoded_fps = if wall > 0.0 { samples.frames_decoded as f64 / wall } else { 0.0 };
    let drop_pct = samples.frames_dropped as f64 / samples.frames_decoded.max(1) as f64 * 100.0;
    let d2r = dist(&samples.decode_to_render_ms);
    let ev = dist(&samples.event_to_render_ms);
    let lag = dist(&samples.loop_lag_ms);
    let software = is_software_renderer(&s.renderer);

    let verdict = |ok: bool| if software { if ok { "meets threshold, but NOT representative (software rendering)" } else { "fails threshold on software rendering (NOT representative)" } } else if ok { "PASS" } else { "FAIL" };
    let c_fps = presented_fps >= T_FPS_MIN;
    let c_pace = in_band >= T_PACING_PCT && drop_pct <= T_DROP_MAX_PCT;
    let c_d2p = d2r.n > 0 && d2r.p95 <= T_D2P_P95_MS;
    let c_ui = ev.n > 0 && ev.p95 <= T_EVENT_P95_MS && lag.p99 <= T_LOOP_LAG_P99_MS;

    let cpu = br.as_ref().and_then(|b| b.cpu.as_ref()).map(|(a, b)| cpu_usage(a, b));
    Ok(json!({
        "spike": "s1",
        "path": format!("{:?}", args.path).to_lowercase(),
        "status": "ok",
        "representative_of_gpu_hardware": !software,
        "warning": if software { "SOFTWARE RENDERING / no GPU: these numbers are NOT representative of GPU hardware" } else { "" },
        "environment": {
            "decoder": decoder_desc,
            "hw_decode_active": hw_active,
            "zero_copy_dmabuf": dmabuf_zero_copy,
            "presenter": s.presenter_info,
            "window": args.window,
            "overlay": !args.no_overlay,
            "sync_gpu": args.sync,
            "clip": args.input,
            "loadavg_start": br.as_ref().map(|b| b.load.0.clone()),
            "loadavg_end": br.as_ref().map(|b| b.load.1.clone()),
            "cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
            "display": std::env::var("DISPLAY").ok(),
            "wayland_display": std::env::var("WAYLAND_DISPLAY").ok(),
            "slint": "1.19.0",
            "bench_seconds": args.bench,
            "measured_wall_s": stats::round3(wall),
        },
        "video": {
            "source_fps": args.fps,
            "decoded_fps": stats::round3(decoded_fps),
            "presented_fps": stats::round3(presented_fps),
            "frames_decoded": samples.frames_decoded,
            "frames_presented": samples.frames_presented,
            "frames_dropped": samples.frames_dropped,
            "dropped_pct": stats::round3(drop_pct),
            "decoder_late_frames": samples.decoder_late,
        },
        "decode_ms": dist(&samples.decode_ms),
        "convert_ms_cpu_swscale": dist(&samples.convert_ms),
        "handoff_decode_to_handed_ms": dist(&samples.handoff_ms),
        "prepare_upload_ms": dist(&samples.prepare_ms),
        "render_ms": dist(&samples.render_ms),
        "decode_to_render_ms": d2r,
        "present_interval_ms": {
            "dist": present,
            "stddev": stats::round3(stddev(&samples.present_interval_ms)),
            "pct_within_13.3_20.0ms": stats::round3(in_band),
            "histogram_edges_ms": stats::HIST_EDGES_MS,
            "histogram_counts": histogram(&samples.present_interval_ms),
        },
        "render_interval_ms": dist(&samples.render_interval_ms),
        "ui_responsiveness": {
            "event_to_render_ms": ev,
            "event_loop_lag_ms": lag,
            "probe_clicks": s.probe_clicks,
            "note": "event = synthetic Slint pointer click dispatched by a timer; excludes OS/compositor input latency",
        },
        "cpu": cpu,
        "s1_criteria": {
            "thresholds": {
                "presented_fps_min": T_FPS_MIN, "pacing_pct_within_13.3_20.0ms_min": T_PACING_PCT,
                "dropped_pct_max": T_DROP_MAX_PCT, "decode_to_render_p95_ms_max": T_D2P_P95_MS,
                "event_to_render_p95_ms_max": T_EVENT_P95_MS, "event_loop_lag_p99_ms_max": T_LOOP_LAG_P99_MS
            },
            "sustained_60fps": verdict(c_fps),
            "even_frame_pacing": verdict(c_pace),
            "decode_to_present_le_8ms": verdict(c_d2p),
            "ui_responsive": verdict(c_ui),
            "decode_to_present_caveat": "measured decode-complete -> end of Slint render (AfterRendering); swap/scanout latency is not observable from the rendering notifier",
        },
    }))
}
