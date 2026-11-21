//! Conversions between the pipeline's types and the link's wire types (`docs/ipc.md` 14.2, 15.1,
//! 20.2). Pure functions, tested without a display.

use hx_capture::CursorShape;
use hx_codec::{Codec, EncodedFrame};
use hx_ipc::link::pb;
use hx_proto::media::{FLAG_KEY, FLAG_RESYNC, MediaHeader};
use hx_proto::pb as hx;

use crate::stats::StatsSnapshot;

/// Largest cursor edge sent to the gateway (protocol.md 5.4).
pub(crate) const MAX_CURSOR_EDGE: u32 = 256;

/// The wire codec for a pipeline codec.
pub(crate) fn wire_codec(c: Codec) -> hx::VideoCodec {
    match c {
        Codec::H264 => hx::VideoCodec::H264,
    }
}

/// The media header of `frame` (`docs/ipc.md` 15.1): `KEY` is an IDR (a gradual-intra-refresh
/// recovery point does not decode without earlier frames), `RESYNC` answers a resync request.
pub(crate) fn media_header(frame: &EncodedFrame, number: u32, resync: bool) -> MediaHeader {
    let mut flags = 0;
    if frame.idr {
        flags |= FLAG_KEY;
    }
    if resync {
        flags |= FLAG_RESYNC;
    }
    let t = frame.timing;
    let capture_ns = if t.t_capture_ns != 0 {
        t.t_capture_ns
    } else {
        t.t_damage_ns
    };
    MediaHeader {
        codec: wire_codec(frame.codec),
        flags,
        frame_number: number,
        capture_timestamp_us: capture_ns / 1000,
        payload_len: u32::try_from(frame.bytes().len()).unwrap_or(u32::MAX),
    }
}

/// Premultiplied `0xAARRGGBB` to straight RGBA, cropped to at most 256 x 256 (top left), with
/// the hotspot clamped into the image. `None` for an empty or inconsistent shape.
pub(crate) fn cursor_shape_to_wire(s: &CursorShape) -> Option<hx::CursorShape> {
    let (w, h) = (u32::from(s.width), u32::from(s.height));
    if w == 0 || h == 0 || s.argb.len() != (w * h) as usize {
        return None;
    }
    let (cw, ch) = (w.min(MAX_CURSOR_EDGE), h.min(MAX_CURSOR_EDGE));
    let mut rgba = Vec::with_capacity((cw * ch * 4) as usize);
    for y in 0..ch {
        let row = &s.argb[(y * w) as usize..(y * w + cw) as usize];
        for &p in row {
            let a = p >> 24;
            let un = |c: u32| -> u8 {
                if a == 0 {
                    0
                } else {
                    ((c * 255 + a / 2) / a).min(255) as u8
                }
            };
            rgba.extend_from_slice(&[
                un((p >> 16) & 0xff),
                un((p >> 8) & 0xff),
                un(p & 0xff),
                a as u8,
            ]);
        }
    }
    Some(hx::CursorShape {
        id: s.id,
        width: cw,
        height: ch,
        hotspot_x: u32::from(s.xhot).min(cw - 1),
        hotspot_y: u32::from(s.yhot).min(ch - 1),
        rgba: rgba.into(),
    })
}

fn sat32(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// The interval between two snapshots as a wire `SessionStats` (every value saturating).
pub(crate) fn session_stats(
    prev: &StatsSnapshot,
    now: &StatsSnapshot,
    interval_ms: u32,
    queue_depth_max: u32,
) -> pb::SessionStats {
    let d = |a: u64, b: u64| a.saturating_sub(b);
    pb::SessionStats {
        interval_ms,
        captures: sat32(d(now.captures, prev.captures)),
        frames: sat32(d(now.frames, prev.frames)),
        keyframes: sat32(d(now.keyframes, prev.keyframes)),
        idr_frames: sat32(d(now.idr_frames, prev.idr_frames)),
        bytes: d(now.bytes, prev.bytes),
        max_frame_bytes: sat32(now.max_frame_bytes),
        errors: sat32(d(now.errors, prev.errors)),
        capture_buffer_waits: sat32(d(now.capture_buffer_waits, prev.capture_buffer_waits)),
        encode_p50_us: sat32(now.stages.encode.p50_us),
        encode_p95_us: sat32(now.stages.encode.p95_us),
        total_p95_us: sat32(now.stages.total.p95_us),
        cpu_ms: sat32(
            u64::try_from(now.cpu.saturating_sub(prev.cpu).as_millis()).unwrap_or(u64::MAX),
        ),
        target_bitrate_kbps: now.target_kbps,
        fps_ceiling: now.max_fps,
        queue_depth_max,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_proto::message::Wire;

    fn shape(w: u16, h: u16, px: u32, xhot: u16, yhot: u16) -> CursorShape {
        // Constructed through the public fields: `CursorShape::new` is crate-private to
        // hx-capture, and the id is only a label here.
        CursorShape {
            id: 7,
            width: w,
            height: h,
            xhot,
            yhot,
            argb: vec![px; usize::from(w) * usize::from(h)],
        }
    }

    fn shape_event(s: hx::CursorShape) -> hx::CursorEvent {
        hx::CursorEvent {
            event: Some(hx::cursor_event::Event::Shape(s)),
        }
    }

    #[test]
    fn premultiplied_argb_becomes_straight_rgba() {
        // 50% alpha, premultiplied red 0x40 and blue 0x20 (straight 0x80 and 0x40).
        let s = shape(1, 1, 0x80_40_00_20, 0, 0);
        let w = cursor_shape_to_wire(&s).unwrap();
        assert_eq!(w.rgba.as_ref(), &[0x80, 0x00, 0x40, 0x80]);
        shape_event(w).validate().unwrap();
        // Fully transparent stays black, opaque is unchanged, no overflow on bad premultiply.
        let t = cursor_shape_to_wire(&shape(1, 1, 0x00_ff_ff_ff, 0, 0)).unwrap();
        assert_eq!(t.rgba.as_ref(), &[0, 0, 0, 0]);
        let o = cursor_shape_to_wire(&shape(1, 1, 0xff_12_34_56, 0, 0)).unwrap();
        assert_eq!(o.rgba.as_ref(), &[0x12, 0x34, 0x56, 0xff]);
        let bad = cursor_shape_to_wire(&shape(1, 1, 0x01_ff_ff_ff, 0, 0)).unwrap();
        assert_eq!(bad.rgba.as_ref(), &[255, 255, 255, 1]);
    }

    #[test]
    fn large_shapes_are_cropped_and_the_hotspot_clamped() {
        let s = shape(300, 400, 0xff_00_00_00, 299, 399);
        let w = cursor_shape_to_wire(&s).unwrap();
        assert_eq!((w.width, w.height), (256, 256));
        assert_eq!((w.hotspot_x, w.hotspot_y), (255, 255));
        assert_eq!(w.rgba.len(), 256 * 256 * 4);
        shape_event(w).validate().unwrap();
        // Empty or inconsistent shapes are refused.
        assert!(cursor_shape_to_wire(&shape(0, 4, 0, 0, 0)).is_none());
        let mut bad = shape(2, 2, 0, 0, 0);
        bad.argb.pop();
        assert!(cursor_shape_to_wire(&bad).is_none());
    }

    #[test]
    fn stats_are_interval_values_and_saturate() {
        let prev = StatsSnapshot {
            frames: 10,
            bytes: 1_000,
            ..StatsSnapshot::default()
        };
        let now = StatsSnapshot {
            frames: 40,
            bytes: 9_000,
            max_frame_bytes: u64::MAX,
            target_kbps: 4_000,
            max_fps: 60,
            ..StatsSnapshot::default()
        };
        let s = session_stats(&prev, &now, 1000, 3);
        assert_eq!(
            (s.frames, s.bytes, s.interval_ms, s.queue_depth_max),
            (30, 8_000, 1000, 3)
        );
        assert_eq!(s.max_frame_bytes, u32::MAX);
        // A counter that went backwards (pipeline restarted) does not underflow.
        let s = session_stats(&now, &prev, 1000, 0);
        assert_eq!(s.frames, 0);
    }
}
