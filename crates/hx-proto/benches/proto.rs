//! Microbenchmarks of the wire protocol's hot paths: the media header (every video frame), the
//! length-prefixed control framing (every input event and control message) and the datagrams
//! (mouse motion). Run with `cargo bench -p hx-proto`; `perf/run.sh` runs all of them and
//! `perf/check.py` compares the results with `perf/baseline.json`.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use hx_proto::VideoCodec;
use hx_proto::datagram::{MouseCoalescer, MouseMove, decode_datagram};
use hx_proto::media::{FLAG_KEY, MEDIA_HEADER_LEN, MediaHeader};
use hx_proto::message::{decode_framed, encode_framed};
use hx_proto::pb::{
    ControlMessage, InputEvent, KeyEvent, control_message::Message as Ctl, input_event::Event as In,
};

fn header(payload_len: u32) -> MediaHeader {
    MediaHeader {
        codec: VideoCodec::H264,
        flags: FLAG_KEY,
        frame_number: 123_456,
        capture_timestamp_us: 9_876_543_210,
        payload_len,
    }
}

fn media(c: &mut Criterion) {
    let mut g = c.benchmark_group("media_header");
    let h = header(4096);
    g.bench_function("encode", |b| {
        b.iter(|| black_box(black_box(&h).encode().unwrap()))
    });
    let bytes = h.encode().unwrap();
    g.bench_function("decode", |b| {
        b.iter(|| black_box(MediaHeader::decode(black_box(&bytes)).unwrap()))
    });
    // A whole frame: header plus a 64 KiB payload, split without copying.
    let mut frame = h.encode().unwrap().to_vec();
    let mut h64 = header(64 * 1024);
    h64.flags = 0;
    frame.clear();
    frame.extend_from_slice(&h64.encode().unwrap());
    frame.resize(MEDIA_HEADER_LEN + 64 * 1024, 0x5a);
    g.throughput(Throughput::Bytes(frame.len() as u64));
    g.bench_function("decode_frame_64k", |b| {
        b.iter(|| black_box(MediaHeader::decode_frame(black_box(&frame)).unwrap()))
    });
    g.finish();
}

fn framing(c: &mut Criterion) {
    let mut g = c.benchmark_group("control_framing");
    let key = InputEvent {
        event: Some(In::Key(KeyEvent {
            scancode: 0x04,
            pressed: true,
        })),
    };
    g.bench_function("encode_framed_input_event", |b| {
        b.iter(|| black_box(encode_framed(black_box(&key)).unwrap()))
    });
    let framed = encode_framed(&key).unwrap();
    g.bench_function("decode_framed_input_event", |b| {
        b.iter(|| black_box(decode_framed::<InputEvent>(black_box(&framed)).unwrap()))
    });
    let ping = ControlMessage::new(Ctl::Ping(hx_proto::pb::Ping { nonce: 42 }));
    g.bench_function("encode_framed_control_ping", |b| {
        b.iter(|| black_box(encode_framed(black_box(&ping)).unwrap()))
    });
    let framed = encode_framed(&ping).unwrap();
    g.bench_function("decode_framed_control_ping", |b| {
        b.iter(|| black_box(decode_framed::<ControlMessage>(black_box(&framed)).unwrap()))
    });
    g.finish();
}

fn datagrams(c: &mut Criterion) {
    let mut g = c.benchmark_group("datagram");
    let m = MouseMove {
        relative: false,
        seq: 77,
        x: 640,
        y: 360,
    };
    g.bench_function("mouse_move_encode", |b| {
        b.iter(|| black_box(black_box(&m).encode()))
    });
    let bytes = m.encode();
    g.bench_function("mouse_move_decode", |b| {
        b.iter(|| black_box(decode_datagram(black_box(&bytes)).unwrap()))
    });
    // A burst of 100 motion events coalesced into one update, as the gateway does.
    g.bench_function("mouse_coalesce_100", |b| {
        b.iter(|| {
            let mut co = MouseCoalescer::new();
            for i in 0..100u32 {
                co.push(MouseMove {
                    relative: false,
                    seq: i,
                    x: i as i32,
                    y: 2 * i as i32,
                });
            }
            black_box(co.take())
        })
    });
    g.finish();
}

criterion_group!(benches, media, framing, datagrams);
criterion_main!(benches);
