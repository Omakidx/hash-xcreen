//! `hx-session-bench`: run capture, convert and encode against a display for a while and
//! print per-stage timings, bitrate and CPU. A local harness, not the session daemon.
//!
//! ```text
//! hx-session-bench [--display :0] [--secs 10] [--workload idle|typing|scroll]
//!                  [--bitrate KBPS] [--fps N] [--vbv-frames F] [--threads N]
//!                  [--crf N] [--nv12] [--no-intra-refresh]
//! ```
//! With a workload the bench draws on the display's root window itself (its own CPU is
//! subtracted from the report); without one it measures whatever is happening on the display.

mod workload;

use hx_session::pipeline::{Pipeline, PipelineConfig};
use hx_session::stats::{Percentiles, StatsSnapshot};
use std::process::ExitCode;
use std::time::{Duration, Instant};
use workload::{Kind, Workload};

struct Args {
    display: Option<String>,
    secs: f64,
    workload: Option<Kind>,
    cfg: PipelineConfig,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        display: None,
        secs: 10.0,
        workload: None,
        cfg: PipelineConfig::default(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
        fn num<T: std::str::FromStr>(name: &str, s: String) -> Result<T, String> {
            s.parse()
                .map_err(|_| format!("{name}: invalid number {s:?}"))
        }
        match flag.as_str() {
            "--display" => a.display = Some(value("--display")?),
            "--secs" => a.secs = num("--secs", value("--secs")?)?,
            "--workload" => {
                let v = value("--workload")?;
                a.workload = Some(Kind::parse(&v).ok_or(format!("unknown workload {v:?}"))?);
            }
            "--bitrate" => a.cfg.encoder.bitrate_kbps = num("--bitrate", value("--bitrate")?)?,
            "--fps" => a.cfg.max_fps = num("--fps", value("--fps")?)?,
            "--vbv-frames" => {
                a.cfg.encoder.vbv_frames = num("--vbv-frames", value("--vbv-frames")?)?
            }
            "--threads" => a.cfg.encoder.threads = num("--threads", value("--threads")?)?,
            "--crf" => a.cfg.encoder.crf = num("--crf", value("--crf")?)?,
            "--nv12" => a.cfg.encoder.format = hx_codec::encode::YuvFormat::Nv12,
            "--no-intra-refresh" => a.cfg.encoder.intra_refresh = false,
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if !(a.secs.is_finite() && a.secs > 0.0 && a.secs <= 86_400.0) {
        return Err("--secs must be between 0 and 86400".to_string());
    }
    a.cfg.capture.display = a.display.clone();
    Ok(a)
}

fn ms(us: u64) -> f64 {
    us as f64 / 1000.0
}

fn row(name: &str, p: &Percentiles) {
    println!(
        "  {name:<18} {:>8.2} {:>8.2} {:>8.2} {:>8.2}   n={}",
        ms(p.p50_us),
        ms(p.p95_us),
        ms(p.p99_us),
        ms(p.max_us),
        p.count
    );
}

fn report(s: &StatsSnapshot, workload_cpu: Duration) {
    let secs = s.elapsed.as_secs_f64();
    println!(
        "frames {} ({:.1}/s)   captures {}   keyframes {} (idr {})   errors {}",
        s.frames,
        s.frames as f64 / secs,
        s.captures,
        s.keyframes,
        s.idr_frames,
        s.errors
    );
    println!(
        "bitrate {:.0} kbit/s   frame mean {:.1} KB, max {:.1} KB",
        s.bitrate_kbps(),
        s.mean_frame_bytes() / 1024.0,
        s.max_frame_bytes as f64 / 1024.0
    );
    println!(
        "\n  {:<18} {:>8} {:>8} {:>8} {:>8}   (ms)",
        "stage", "p50", "p95", "p99", "max"
    );
    row("damage->capture", &s.stages.damage_to_capture);
    row("capture (grab)", &s.stages.capture);
    row("convert", &s.stages.convert);
    row("encode", &s.stages.encode);
    row("damage->encoded", &s.stages.total);
    println!();
    for (name, q) in ["capture->convert", "convert->encode", "encode->output"]
        .iter()
        .zip(&s.queues)
    {
        println!(
            "  queue {name:<17} depth max {}/{}  mean {:.2}",
            q.max, q.capacity, q.mean
        );
    }
    println!("  capture buffer waits {}", s.capture_buffer_waits);
    let own = s.cpu.saturating_sub(workload_cpu);
    println!(
        "\ncpu: {:.2} cores for the pipeline ({:.2} s over {:.1} s); workload thread excluded: {:.2} s",
        own.as_secs_f64() / secs,
        own.as_secs_f64(),
        secs,
        workload_cpu.as_secs_f64()
    );
}

fn main() -> ExitCode {
    let args = match parse() {
        Ok(a) => a,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("error: {msg}\n");
            }
            eprintln!(
                "usage: hx-session-bench [--display :0] [--secs 10] [--workload idle|typing|scroll]\n       [--bitrate KBPS] [--fps N] [--vbv-frames F] [--threads N] [--crf N] [--nv12] [--no-intra-refresh]"
            );
            return ExitCode::from(2);
        }
    };
    let pipeline = match Pipeline::start_x11(args.cfg.clone()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot start the pipeline: {e}");
            return ExitCode::FAILURE;
        }
    };
    let load = match args.workload {
        Some(kind) => match Workload::start(args.display.clone(), kind) {
            Ok(w) => Some(w),
            Err(e) => {
                eprintln!("error: cannot start the workload: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };
    println!(
        "hx-session-bench: display {}, workload {:?}, {:.0} s, cap {} kbit/s at up to {} fps, vbv {} frames",
        args.display.as_deref().unwrap_or("$DISPLAY"),
        args.workload,
        args.secs,
        args.cfg.encoder.bitrate_kbps,
        args.cfg.max_fps,
        args.cfg.encoder.vbv_frames
    );

    // Consume frames like a sender would: take them and drop them.
    let end = Instant::now() + Duration::from_secs_f64(args.secs);
    let ctl = pipeline.control();
    let mut cursor_events = 0u64;
    while Instant::now() < end && ctl.is_running() {
        let _ = pipeline.frames().recv_timeout(Duration::from_millis(20));
        while pipeline.cursor_events().try_recv().is_ok() {
            cursor_events += 1;
        }
    }
    let workload_cpu = load.map(Workload::stop).unwrap_or_default();
    let stats = pipeline.stats();
    let result = pipeline.shutdown();
    report(&stats, workload_cpu);
    println!("cursor events received: {cursor_events}");
    if let Some(e) = ctl.last_error() {
        println!("last recoverable error: {e}");
    }
    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
