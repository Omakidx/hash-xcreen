//! The capture-to-encode handoff end to end inside the session: a rectangle is painted on a
//! private Xvfb and the clock stops when the pipeline (X damage, screen read, conversion, x264)
//! delivers the encoded frame. This is the server half of the added latency of S2, without the
//! network. Skipped, with a message, when Xvfb is not installed.
//! Run with `cargo bench -p hx-session --bench capture_to_encode`.

#[path = "../../../crates/hx-capture/tests/common/mod.rs"]
mod common;

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use hx_capture::X11Config;
use hx_session::pipeline::{Pipeline, PipelineConfig};

fn damage_to_frame(c: &mut Criterion) {
    let Some(x) = common::Xvfb::start(1280, 720) else {
        eprintln!("capture_to_encode: Xvfb is not available, skipping");
        return;
    };
    let cfg = PipelineConfig {
        capture: X11Config {
            display: Some(x.display.clone()),
            ..X11Config::default()
        },
        ..PipelineConfig::default()
    };
    let pipeline = Pipeline::start_x11(cfg).expect("the pipeline");
    // The first frame is the IDR of the connect.
    pipeline
        .frames()
        .recv_timeout(Duration::from_secs(10))
        .expect("the first frame");
    let mut n = 0u32;
    let mut g = c.benchmark_group("session_pipeline");
    g.sample_size(40);
    g.measurement_time(Duration::from_secs(10));
    g.bench_function("damage_to_encoded_frame_720p", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                // Drain what an earlier iteration left, let the pacing interval pass.
                std::thread::sleep(Duration::from_millis(40));
                while pipeline.frames().try_recv().is_ok() {}
                n = n.wrapping_add(1);
                let t = Instant::now();
                common::fill_root(
                    &x.display,
                    (20 + (n % 40) as i16 * 10, 20, 30, 30),
                    n.wrapping_mul(0x0001_0203),
                );
                pipeline
                    .frames()
                    .recv_timeout(Duration::from_secs(5))
                    .expect("a frame for the damage");
                total += t.elapsed();
            }
            total
        })
    });
    g.finish();
    let _ = pipeline.shutdown();
}

criterion_group!(benches, damage_to_frame);
criterion_main!(benches);
