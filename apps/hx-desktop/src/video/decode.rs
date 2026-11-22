//! Software H.264 decode with FFmpeg into RGBA.
//!
//! Video colour is BT.709, limited range (protocol 5.2). `hx-codec` has no decode side yet, so
//! this uses `ffmpeg-next` (already a workspace dependency) directly, and `yuvutils-rs` for the
//! YUV to RGBA conversion.

use slint::{Rgba8Pixel, SharedPixelBuffer};
use yuvutils_rs::{YuvPlanarImage, YuvRange, YuvStandardMatrix};

use super::pool::FramePool;

/// A decoded picture, ready for presentation.
pub struct Picture {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// RGBA pixels.
    pub pixels: SharedPixelBuffer<Rgba8Pixel>,
}

/// Why a frame was not decoded.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// FFmpeg could not be initialised or the codec is missing.
    #[error("video decoder unavailable: {0}")]
    Unavailable(String),
    /// The decoder rejected the data: ask for a keyframe.
    #[error("undecodable frame: {0}")]
    Bad(String),
    /// A pixel format the converter does not handle.
    #[error("unsupported pixel format")]
    Format,
}

/// The H.264 decoder.
pub struct Decoder {
    dec: ffmpeg_next::decoder::Video,
    frame: ffmpeg_next::frame::Video,
    pool: FramePool,
}

impl Decoder {
    /// Opens an H.264 decoder.
    pub fn new() -> Result<Self, DecodeError> {
        ffmpeg_next::init().map_err(|e| DecodeError::Unavailable(e.to_string()))?;
        let codec = ffmpeg_next::decoder::find(ffmpeg_next::codec::Id::H264)
            .ok_or_else(|| DecodeError::Unavailable("no H.264 decoder".into()))?;
        let dec = ffmpeg_next::codec::context::Context::new_with_codec(codec)
            .decoder()
            .video()
            .map_err(|e| DecodeError::Unavailable(e.to_string()))?;
        Ok(Self {
            dec,
            frame: ffmpeg_next::frame::Video::empty(),
            pool: FramePool::new(4),
        })
    }

    /// Feeds one access unit. `Ok(None)` means the decoder needs more data.
    pub fn decode(&mut self, data: &[u8]) -> Result<Option<Picture>, DecodeError> {
        let pkt = ffmpeg_next::Packet::copy(data);
        self.dec
            .send_packet(&pkt)
            .map_err(|e| DecodeError::Bad(e.to_string()))?;
        match self.dec.receive_frame(&mut self.frame) {
            Ok(()) => {}
            Err(ffmpeg_next::Error::Other { errno }) if errno == ffmpeg_next::error::EAGAIN => {
                return Ok(None);
            }
            Err(ffmpeg_next::Error::Eof) => return Ok(None),
            Err(e) => return Err(DecodeError::Bad(e.to_string())),
        }
        if self.frame.format() != ffmpeg_next::format::Pixel::YUV420P {
            return Err(DecodeError::Format);
        }
        let (w, h) = (self.frame.width(), self.frame.height());
        if w == 0 || h == 0 {
            return Ok(None);
        }
        let buf = self.pool.take(w, h);
        let out = buf.make_mut_bytes();
        let img = YuvPlanarImage {
            y_plane: self.frame.data(0),
            y_stride: self.frame.stride(0) as u32,
            u_plane: self.frame.data(1),
            u_stride: self.frame.stride(1) as u32,
            v_plane: self.frame.data(2),
            v_stride: self.frame.stride(2) as u32,
            width: w,
            height: h,
        };
        yuv420_to_rgba(&img, out, w * 4).map_err(|e| DecodeError::Bad(e.to_string()))?;
        Ok(Some(Picture {
            width: w,
            height: h,
            pixels: buf.clone(),
        }))
    }
}

/// BT.709 limited-range YUV 4:2:0 to RGBA.
pub fn yuv420_to_rgba(img: &YuvPlanarImage<u8>, out: &mut [u8], stride: u32) -> Result<(), yuvutils_rs::YuvError> {
    yuvutils_rs::yuv420_to_rgba(img, out, stride, YuvRange::Limited, YuvStandardMatrix::Bt709)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bt709_limited_primaries() {
        // 2x2 pictures of one colour each: (Y, U, V) of BT.709 limited.
        let cases: [([u8; 3], [u8; 3]); 3] = [
            ([16, 128, 128], [0, 0, 0]),         // black
            ([235, 128, 128], [255, 255, 255]),  // white
            ([63, 102, 240], [255, 0, 0]),       // red
        ];
        for (yuv, rgb) in cases {
            let (y, u, v) = ([yuv[0]; 4], [yuv[1]], [yuv[2]]);
            let img = YuvPlanarImage {
                y_plane: &y,
                y_stride: 2,
                u_plane: &u,
                u_stride: 1,
                v_plane: &v,
                v_stride: 1,
                width: 2,
                height: 2,
            };
            let mut out = [0u8; 16];
            yuv420_to_rgba(&img, &mut out, 8).unwrap();
            for px in out.chunks(4) {
                for c in 0..3 {
                    assert!(
                        (i32::from(px[c]) - i32::from(rgb[c])).abs() <= 3,
                        "{yuv:?} -> {px:?} want {rgb:?}"
                    );
                }
                assert_eq!(px[3], 255);
            }
        }
    }

    #[test]
    fn garbage_is_an_error_or_nothing_never_a_panic() {
        let mut d = Decoder::new().expect("ffmpeg h264 decoder");
        for data in [&[0u8; 0][..], &[0, 0, 0, 1, 0x65, 1, 2, 3][..], &[0xff; 64][..]] {
            let _ = d.decode(data);
        }
    }
}
