//! Encoder tests. Streams are decoded with libavcodec to check what a client would see.

use ffmpeg_next as ffmpeg;
use hx_codec::encode::{
    EncodeError, EncoderConfig, FrameMeta, X264Encoder, YuvFormat, YuvFrame, convert_bgrx, h264,
};
use hx_codec::{Codec, EncodedFrame};

const W: u32 = 640;
const H: u32 = 360;

struct Decoder {
    dec: ffmpeg::decoder::Video,
}

/// What the decoder reports about a decoded picture.
struct Decoded {
    width: u32,
    height: u32,
    space: ffmpeg::color::Space,
    range: ffmpeg::color::Range,
    primaries: ffmpeg::color::Primaries,
    transfer: ffmpeg::color::TransferCharacteristic,
    luma_mean: f64,
}

impl Decoder {
    fn new() -> Self {
        ffmpeg::init().expect("init");
        let codec = ffmpeg::decoder::find(ffmpeg::codec::Id::H264).expect("h264 decoder");
        let dec = ffmpeg::codec::context::Context::new_with_codec(codec)
            .decoder()
            .video()
            .expect("decoder");
        Self { dec }
    }

    /// Feed one access unit; returns the picture if the decoder produced one.
    fn decode(&mut self, data: &[u8]) -> Option<Decoded> {
        let pkt = ffmpeg::Packet::copy(data);
        self.dec.send_packet(&pkt).expect("send packet");
        let mut f = ffmpeg::frame::Video::empty();
        if self.dec.receive_frame(&mut f).is_err() {
            return None;
        }
        let y = f.data(0);
        let stride = f.stride(0);
        let mut sum = 0u64;
        for row in 0..f.height() as usize {
            sum += y[row * stride..row * stride + f.width() as usize]
                .iter()
                .map(|&v| u64::from(v))
                .sum::<u64>();
        }
        Some(Decoded {
            width: f.width(),
            height: f.height(),
            space: f.color_space(),
            range: f.color_range(),
            primaries: f.color_primaries(),
            transfer: f.color_transfer_characteristic(),
            luma_mean: sum as f64 / f64::from(f.width() * f.height()),
        })
    }
}

/// Deterministic pseudo-random BGRX picture; `noise` 0 gives a smooth gradient instead.
fn picture(w: u32, h: u32, seed: u32, noise: bool) -> Vec<u8> {
    let mut s = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    let mut out = Vec::with_capacity((w * h * 4) as usize);
    for y in 0..h {
        for x in 0..w {
            let (b, g, r) = if noise {
                s ^= s << 13;
                s ^= s >> 17;
                s ^= s << 5;
                (s as u8, (s >> 8) as u8, (s >> 16) as u8)
            } else {
                (((x + seed * 3) % 256) as u8, (y % 256) as u8, 128)
            };
            out.extend_from_slice(&[b, g, r, 255]);
        }
    }
    out
}

struct Source {
    yuv: YuvFrame,
    n: u32,
    noise: bool,
}

impl Source {
    fn new(format: YuvFormat, w: u32, h: u32, noise: bool) -> Self {
        Self {
            yuv: YuvFrame::new(format, w, h).expect("yuv"),
            n: 0,
            noise,
        }
    }

    fn next(&mut self, enc: &mut X264Encoder) -> EncodedFrame {
        let (w, h) = (self.yuv.width(), self.yuv.height());
        convert_bgrx(
            &picture(w, h, self.n, self.noise),
            (w * 4) as usize,
            &mut self.yuv,
        )
        .expect("convert");
        let t = u64::from(self.n) * 16_666_667 + 1_000;
        self.n += 1;
        enc.encode(
            &self.yuv,
            &FrameMeta {
                t_damage_ns: t.saturating_sub(500),
                t_capture_ns: t,
                t_convert_ns: t + 100,
            },
        )
        .expect("encode")
        .expect("one packet per frame")
    }
}

fn config() -> EncoderConfig {
    let mut c = EncoderConfig::new(W, H);
    c.threads = 2;
    c
}

fn assert_bt709_limited(d: &Decoded) {
    assert_eq!(d.space, ffmpeg::color::Space::BT709, "matrix coefficients");
    assert_eq!(d.range, ffmpeg::color::Range::MPEG, "limited range");
    assert_eq!(d.primaries, ffmpeg::color::Primaries::BT709, "primaries");
    assert_eq!(
        d.transfer,
        ffmpeg::color::TransferCharacteristic::BT709,
        "transfer"
    );
}

#[test]
fn stream_is_decodable_and_tagged_bt709_limited() {
    for (format, intra_refresh, sliced) in [
        (YuvFormat::I420, true, true),
        (YuvFormat::I420, false, true),
        // Without slice threads only a single encoder thread keeps one packet per frame.
        (YuvFormat::Nv12, true, false),
    ] {
        let mut cfg = config();
        cfg.format = format;
        cfg.intra_refresh = intra_refresh;
        cfg.sliced_threads = sliced;
        if !sliced {
            cfg.threads = 1;
        }
        let mut enc = X264Encoder::new(cfg).expect("encoder");
        let mut src = Source::new(format, W, H, false);
        let mut dec = Decoder::new();
        let mut decoded = 0;
        for _ in 0..12 {
            let f = src.next(&mut enc);
            assert_eq!(f.codec, Codec::H264);
            assert_eq!((f.width, f.height), (W, H));
            if let Some(d) = dec.decode(f.bytes()) {
                assert_eq!((d.width, d.height), (W, H));
                assert_bt709_limited(&d);
                assert!(d.luma_mean > 20.0 && d.luma_mean < 235.0);
                decoded += 1;
            }
        }
        assert!(
            decoded >= 10,
            "{format:?} intra_refresh={intra_refresh} decoded only {decoded} of 12"
        );
    }
}

#[test]
fn first_frame_is_idr_with_headers_and_later_frames_are_not() {
    let mut enc = X264Encoder::new(config()).expect("encoder");
    let mut src = Source::new(YuvFormat::I420, W, H, false);
    let first = src.next(&mut enc);
    assert!(first.idr && first.keyframe);
    assert_eq!(h264::first_slice_nal_type(first.bytes()), Some(5));
    // SPS and PPS travel with the IDR so a client can join at any keyframe.
    assert!(
        first.bytes().windows(4).any(|w| w == [0, 0, 1, 0x67])
            || first.bytes().windows(5).any(|w| w == [0, 0, 0, 1, 0x67])
    );
    for n in 1..20 {
        let f = src.next(&mut enc);
        assert!(!f.idr, "frame {n} must not be an IDR");
        assert_eq!(f.frame_no, n);
    }
}

#[test]
fn request_idr_produces_exactly_one_idr() {
    for intra_refresh in [true, false] {
        let mut cfg = config();
        cfg.intra_refresh = intra_refresh;
        let mut enc = X264Encoder::new(cfg).expect("encoder");
        let mut src = Source::new(YuvFormat::I420, W, H, false);
        let mut dec = Decoder::new();
        for _ in 0..10 {
            dec.decode(src.next(&mut enc).bytes());
        }
        enc.request_idr();
        let idr = src.next(&mut enc);
        assert!(idr.idr && idr.keyframe, "intra_refresh={intra_refresh}");
        assert!(h264::starts_with_idr(idr.bytes()));
        assert!(!src.next(&mut enc).idr, "only one IDR per request");
        // A decoder that joins at the IDR (a new client) decodes it.
        let mut late = Decoder::new();
        assert!(late.decode(idr.bytes()).is_some());
    }
}

#[test]
fn rate_changes_apply_without_reopening() {
    let mut cfg = config();
    cfg.bitrate_kbps = 20_000;
    let mut enc = X264Encoder::new(cfg).expect("encoder");
    let mut src = Source::new(YuvFormat::I420, W, H, true);
    let mut dec = Decoder::new();
    let avg = |enc: &mut X264Encoder, src: &mut Source, dec: &mut Decoder, n: usize| {
        let mut total = 0usize;
        for _ in 0..n {
            let f = src.next(enc);
            total += f.bytes().len();
            dec.decode(f.bytes());
        }
        total / n
    };
    avg(&mut enc, &mut src, &mut dec, 5); // warm up past the first IDR
    let high = avg(&mut enc, &mut src, &mut dec, 20);

    enc.set_bitrate_kbps(1_000).expect("lower the cap");
    avg(&mut enc, &mut src, &mut dec, 5); // let the VBV drain
    let low = avg(&mut enc, &mut src, &mut dec, 20);
    assert!(
        low * 4 < high,
        "frames must shrink under a 20x lower cap: {high} -> {low} bytes"
    );
    assert_eq!(enc.reopen_count(), 0, "no reopen for a rate change");

    enc.set_bitrate_kbps(20_000).expect("raise the cap");
    avg(&mut enc, &mut src, &mut dec, 5);
    let high_again = avg(&mut enc, &mut src, &mut dec, 20);
    assert!(high_again > low * 4, "{low} -> {high_again}");
    assert_eq!(enc.reopen_count(), 0);

    // Still one continuous, decodable stream: no IDR was forced by the changes.
    let f = src.next(&mut enc);
    assert!(!f.idr);
    assert!(dec.decode(f.bytes()).is_some());

    // fps and VBV changes are also live.
    enc.set_fps(30).expect("fps");
    enc.set_vbv_frames(4.0).expect("vbv");
    assert!(dec.decode(src.next(&mut enc).bytes()).is_some());
    assert_eq!(enc.reopen_count(), 0);
}

#[test]
fn resize_reopens_and_starts_with_an_idr() {
    let mut enc = X264Encoder::new(config()).expect("encoder");
    let mut src = Source::new(YuvFormat::I420, W, H, false);
    for _ in 0..3 {
        src.next(&mut enc);
    }
    // Wrong-sized pictures are rejected, not encoded.
    assert!(matches!(
        enc.encode(
            &YuvFrame::new(YuvFormat::I420, 320, 180).unwrap(),
            &FrameMeta::default()
        ),
        Err(EncodeError::Config(_))
    ));
    enc.resize(320, 180).expect("resize");
    assert_eq!(enc.reopen_count(), 1);
    let mut src = Source::new(YuvFormat::I420, 320, 180, false);
    let f = src.next(&mut enc);
    assert!(f.idr);
    assert_eq!((f.width, f.height), (320, 180));
    let d = Decoder::new()
        .decode(f.bytes())
        .expect("decodes at the new size");
    assert_eq!((d.width, d.height), (320, 180));
    assert_bt709_limited(&d);
    // Resizing to the same size is a no-op.
    enc.resize(320, 180).expect("noop");
    assert_eq!(enc.reopen_count(), 1);
}

#[test]
fn invalid_settings_are_typed_errors() {
    let bad = |f: &dyn Fn(&mut EncoderConfig)| {
        let mut c = config();
        f(&mut c);
        match X264Encoder::new(c) {
            Err(EncodeError::Config(_)) => {}
            Err(e) => panic!("wrong error: {e}"),
            Ok(_) => panic!("accepted invalid settings"),
        }
    };
    bad(&|c| c.width = 641);
    bad(&|c| c.height = 0);
    bad(&|c| c.width = 4);
    bad(&|c| c.fps = 0);
    bad(&|c| c.bitrate_kbps = 5);
    bad(&|c| c.bitrate_kbps = 10_000_000);
    bad(&|c| c.crf = 99);
    bad(&|c| c.vbv_frames = f32::NAN);
    bad(&|c| c.preset = "ultrafast:threads=99".to_string());
    // An unknown preset is refused by libx264 and reported, not a panic.
    let mut c = config();
    c.preset = "nonsense".to_string();
    assert!(X264Encoder::new(c).is_err());

    let mut enc = X264Encoder::new(config()).expect("encoder");
    assert!(enc.set_bitrate_kbps(0).is_err());
    assert!(enc.set_fps(1000).is_err());
    assert_eq!(
        enc.config().bitrate_kbps,
        8_000,
        "failed updates change nothing"
    );
}

#[test]
fn output_buffers_are_pooled_and_timing_is_recorded() {
    let mut enc = X264Encoder::new(config()).expect("encoder");
    let mut src = Source::new(YuvFormat::I420, W, H, false);
    let f = src.next(&mut enc);
    let t = f.timing;
    assert!(t.t_damage_ns < t.t_capture_ns && t.t_capture_ns < t.t_convert_ns);
    assert!(t.t_encode_start_ns > 0 && t.t_encode_end_ns >= t.t_encode_start_ns);
    drop(f);
    // Steady state: dropped frames' buffers are reused, so a long run touches only the
    // pool's few allocations, not one per frame.
    let mut seen = std::collections::HashSet::new();
    for _ in 0..60 {
        let f = src.next(&mut enc);
        seen.insert(f.bytes().as_ptr() as usize);
    }
    assert!(
        seen.len() <= 9,
        "{} distinct buffers over 60 frames",
        seen.len()
    );
}

// ---------------------------------------------------------------------------------------------
// Key frames under a tight VBV (the lossy-link defect, docs/testing.md 2.8)
// ---------------------------------------------------------------------------------------------

/// A text-dense BGRX picture (black glyph-like marks on white) that needs far more than a one
/// frame budget at a few Mbit/s, like a desktop full of text. `seed` moves the marks.
fn text_picture(w: u32, h: u32, seed: u32) -> Vec<u8> {
    let mut out = vec![255u8; (w * h * 4) as usize];
    let mut s = seed.wrapping_mul(2_654_435_761).wrapping_add(7);
    for cy in 0..h / 24 {
        for cx in 0..w / 12 {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            for bit in 0..12u32 {
                if s >> bit & 1 == 1 {
                    let (gx, gy) = (bit % 3, bit / 3);
                    for y in 0..4 {
                        for x in 0..3 {
                            let (px, py) = (cx * 12 + gx * 3 + x, cy * 24 + 2 + gy * 5 + y);
                            let i = ((py * w + px) * 4) as usize;
                            out[i..i + 3].copy_from_slice(&[0, 0, 0]);
                        }
                    }
                }
            }
        }
    }
    out
}

/// Luma samples that differ from the encoder's input by more than 40 (marks are black on white).
fn wrong_pixels(dec: &ffmpeg::frame::Video, src: &YuvFrame) -> usize {
    let (y, stride) = (dec.data(0), dec.stride(0));
    let p = src.plane(0);
    let mut bad = 0;
    for row in 0..p.rows {
        for col in 0..p.row_bytes {
            let a = i32::from(y[row * stride + col]);
            let b = i32::from(p.data[row * p.stride + col]);
            bad += usize::from((a - b).abs() > 40);
        }
    }
    bad
}

fn decode_frame(dec: &mut ffmpeg::decoder::Video, data: &[u8]) -> ffmpeg::frame::Video {
    dec.send_packet(&ffmpeg::Packet::copy(data)).expect("send");
    let mut f = ffmpeg::frame::Video::empty();
    dec.receive_frame(&mut f).expect("a picture per packet");
    f
}

/// A key frame requested while the VBV is empty (a busy screen, a link at a low rung of the
/// ladder) is a complete IDR with SPS and PPS that decodes alone, but its picture is far from the
/// screen: the rate control spends what the buffer allows. Repeating the *unchanged* picture
/// refines it to the picture (under 0.5 % of the pixels wrong) within a bounded number of frames. A session that sends the
/// key frame and then, the screen being static, nothing, leaves the client with that blurry
/// picture for good: the end state of the lossy end-to-end run.
#[test]
fn a_starved_key_frame_is_refined_by_repeating_the_unchanged_picture() {
    ffmpeg::init().expect("init");
    let mut cfg = config();
    cfg.bitrate_kbps = 2_000;
    cfg.vbv_frames = 2.0;
    let mut enc = X264Encoder::new(cfg).expect("encoder");
    let mut yuv = YuvFrame::new(YuvFormat::I420, W, H).expect("yuv");
    let mut t = 1_000u64;
    let mut encode = |enc: &mut X264Encoder, yuv: &mut YuvFrame, seed: u32| {
        convert_bgrx(&text_picture(W, H, seed), (W * 4) as usize, yuv).expect("convert");
        t += 16_666_667;
        enc.encode(
            yuv,
            &FrameMeta {
                t_damage_ns: t - 500,
                t_capture_ns: t,
                t_convert_ns: t + 100,
            },
        )
        .expect("encode")
        .expect("one packet per frame")
    };
    // Busy: every frame is new, so the buffer is empty when the key frame is requested.
    for n in 0..30 {
        encode(&mut enc, &mut yuv, n);
    }
    enc.request_idr();
    let idr = encode(&mut enc, &mut yuv, 99);
    eprintln!("IDR qp {:?} bytes {}", idr.qp, idr.bytes().len());
    assert!(idr.idr && h264::starts_with_idr(idr.bytes()));
    // Alone, a decoder that joins at this frame gets a picture (SPS and PPS are in band).
    let codec = ffmpeg::decoder::find(ffmpeg::codec::Id::H264).expect("h264");
    let mut dec = ffmpeg::codec::context::Context::new_with_codec(codec)
        .decoder()
        .video()
        .expect("decoder");
    let first = decode_frame(&mut dec, idr.bytes());
    let total = (W * H) as usize;
    let wrong_first = wrong_pixels(&first, &yuv);
    assert!(
        wrong_first * 100 > total,
        "the key frame is expected to be starved ({wrong_first} of {total} pixels wrong); \
         if this stops holding the refinement may no longer be needed"
    );
    // The screen is now static: the same picture again, as a refinement pass sends it.
    let mut wrong = wrong_first;
    let mut passes = 0;
    while wrong * 200 > total && passes < 60 {
        let f = encode(&mut enc, &mut yuv, 99);
        assert!(!f.idr, "a refinement is a P frame");
        wrong = wrong_pixels(&decode_frame(&mut dec, f.bytes()), &yuv);
        passes += 1;
    }
    assert!(
        wrong * 200 <= total,
        "still {wrong} of {total} pixels wrong after {passes} refinement frames"
    );
    eprintln!("starved key frame: {wrong_first} wrong, exact after {passes} refinement frames");
}
