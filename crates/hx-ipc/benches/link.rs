//! Microbenchmarks of the session link's frame path: what the gateway does for every video frame
//! it relays (read the frame off the link, check its layout and media header, keep the body as
//! one buffer to forward unchanged) and what the session does to write one. Together with the
//! transport's own work this is the relay forwarding cost per frame. Run with
//! `cargo bench -p hx-ipc --features link`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hx_ipc::Decoder;
use hx_ipc::link::frames::{encode_gateway_message, encode_video_prefix, parse};
use hx_ipc::link::{Lane, LinkPolicy, Role, pb};
use hx_proto::VideoCodec;
use hx_proto::media::{FLAG_KEY, MediaHeader};

const MAX_FRAME: u32 = 4 * 1024 * 1024;

fn video_frame(payload: usize) -> Vec<u8> {
    let header = MediaHeader {
        codec: VideoCodec::H264,
        flags: FLAG_KEY,
        frame_number: 1,
        capture_timestamp_us: 1_000_000,
        payload_len: payload as u32,
    };
    let mut v = encode_video_prefix(&header, MAX_FRAME).unwrap().to_vec();
    v.resize(v.len() + payload, 0xa5);
    v
}

fn video(c: &mut Criterion) {
    // Typing frames are a few hundred bytes, scrolling frames tens of kilobytes, a key frame
    // of a busy 1080p screen hundreds.
    let mut g = c.benchmark_group("link_video_frame");
    let policy = LinkPolicy::new(Role::Gateway, Lane::Media);
    for payload in [512usize, 16 * 1024, 256 * 1024] {
        let wire = video_frame(payload);
        g.throughput(Throughput::Bytes(wire.len() as u64));
        g.bench_with_input(
            BenchmarkId::new("read_and_parse", payload),
            &wire,
            |b, wire| {
                b.iter(|| {
                    let mut d = Decoder::new(policy);
                    let (used, raw) = d.feed(black_box(wire)).unwrap();
                    let frame = parse(&policy, raw.expect("a whole frame"), 0).unwrap();
                    black_box((used, frame))
                })
            },
        );
        let header = MediaHeader {
            codec: VideoCodec::H264,
            flags: 0,
            frame_number: 9,
            capture_timestamp_us: 5,
            payload_len: payload as u32,
        };
        g.bench_with_input(
            BenchmarkId::new("encode_prefix", payload),
            &header,
            |b, h| b.iter(|| black_box(encode_video_prefix(black_box(h), MAX_FRAME).unwrap())),
        );
    }
    g.finish();
}

fn control(c: &mut Criterion) {
    let mut g = c.benchmark_group("link_ctl");
    // The feedback the gateway sends the session for acknowledged frames: 64 results is the
    // largest batch.
    let feedback = pb::GatewayToSession {
        message: Some(pb::gateway_to_session::Message::FrameFeedback(
            pb::FrameFeedback {
                results: (0..64)
                    .map(|i| pb::FrameResult {
                        frame_number: i,
                        outcome: pb::FrameOutcome::Delivered as i32,
                        bytes: 1_200,
                        elapsed_us: 2_500,
                        queued_us: 100,
                    })
                    .collect(),
            },
        )),
    };
    g.bench_function("encode_frame_feedback_64", |b| {
        b.iter(|| black_box(encode_gateway_message(black_box(&feedback)).unwrap()))
    });
    let wire = encode_gateway_message(&feedback).unwrap();
    let policy = LinkPolicy::new(Role::Session, Lane::Ctl);
    g.bench_function("read_and_parse_frame_feedback_64", |b| {
        b.iter(|| {
            let mut d = Decoder::new(policy);
            let (_, raw) = d.feed(black_box(&wire)).unwrap();
            black_box(parse(&policy, raw.unwrap(), 0).unwrap())
        })
    });
    g.finish();
}

criterion_group!(benches, video, control);
criterion_main!(benches);
