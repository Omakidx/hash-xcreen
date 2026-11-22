//! Microbenchmarks of the work between the screen read and the encoded frame: BGRX to YUV
//! conversion, the x264 encode of a small change (typing) and of a large one (scrolling), and
//! the buffer pool the stages hand frames through. Run with `cargo bench -p hx-codec`.
//!
//! The encoder is the same configuration the session uses (S2 settings, one picture size per
//! group); pictures are synthetic and deterministic.

use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hx_codec::encode::{EncoderConfig, FrameMeta, X264Encoder, YuvFormat, YuvFrame, convert_bgrx};
use hx_codec::pool::BufPool;

const W: u32 = 1920;
const H: u32 = 1080;

/// A BGRX screen: white with a grid of text-like dark strokes, shifted by `shift` rows.
fn screen(shift: u32) -> Vec<u8> {
    let mut px = vec![0xffu8; (W * H * 4) as usize];
    for y in 0..H {
        let row = (y + shift) % 24;
        for x in 0..W {
            let stroke = row < 2 || (x % 12 < 2 && row < 18) || (row == 9 && x % 12 < 8);
            if stroke && !(x / 12 + (y + shift) / 24).is_multiple_of(3) {
                let i = ((y * W + x) * 4) as usize;
                px[i..i + 3].copy_from_slice(&[0x10, 0x10, 0x10]);
            }
        }
    }
    px
}

fn convert(c: &mut Criterion) {
    let mut g = c.benchmark_group("convert_bgrx_1080p");
    let src = screen(0);
    g.throughput(Throughput::Bytes(src.len() as u64));
    for (name, fmt) in [("i420", YuvFormat::I420), ("nv12", YuvFormat::Nv12)] {
        let mut dst = YuvFrame::new(fmt, W, H).unwrap();
        g.bench_function(name, |b| {
            b.iter(|| convert_bgrx(black_box(&src), (W * 4) as usize, &mut dst).unwrap())
        });
    }
    g.finish();
}

fn encode(c: &mut Criterion) {
    let mut g = c.benchmark_group("x264_encode_1080p");
    g.sample_size(30);
    // Two pictures that differ a little (a cursor block, as in typing) and a lot (the whole
    // screen shifted, as in scrolling).
    let base = screen(0);
    let mut typed = base.clone();
    for y in 100..124 {
        for x in 100..112 {
            let i = ((y * W + x) * 4) as usize;
            typed[i..i + 3].copy_from_slice(&[0, 0, 0]);
        }
    }
    let scrolled = screen(24 * 3 + 5);
    for (name, a, b) in [("typing", &base, &typed), ("scrolling", &base, &scrolled)] {
        let mut ya = YuvFrame::new(YuvFormat::I420, W, H).unwrap();
        let mut yb = YuvFrame::new(YuvFormat::I420, W, H).unwrap();
        convert_bgrx(a, (W * 4) as usize, &mut ya).unwrap();
        convert_bgrx(b, (W * 4) as usize, &mut yb).unwrap();
        let mut enc = X264Encoder::new(EncoderConfig::new(W, H)).unwrap();
        let mut t = 0u64;
        // Prime the encoder (the first picture is the IDR).
        let meta = |t: &mut u64| {
            *t += 16_666_667;
            FrameMeta {
                t_damage_ns: *t,
                t_capture_ns: *t,
                t_convert_ns: *t,
            }
        };
        enc.encode(&ya, &meta(&mut t)).unwrap();
        let mut flip = false;
        g.bench_function(BenchmarkId::new("p_frame", name), |bch| {
            bch.iter(|| {
                flip = !flip;
                let pic = if flip { &yb } else { &ya };
                black_box(enc.encode(pic, &meta(&mut t)).unwrap())
            })
        });
    }
    g.finish();
}

fn pool(c: &mut Criterion) {
    let pool = BufPool::new(4, 256 * 1024);
    let payload = vec![0x42u8; 16 * 1024];
    c.bench_function("bufpool_get_fill_drop_16k", |b| {
        b.iter_batched(
            || (),
            |()| {
                let mut buf = pool.get();
                buf.set(black_box(&payload));
                black_box(buf)
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, convert, encode, pool);
criterion_main!(benches);
