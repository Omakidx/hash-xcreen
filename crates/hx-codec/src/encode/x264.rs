//! x264 through libavcodec, configured as in spike S2 (architecture.md section 6.2).

use super::EncodeError;
use super::convert::{YuvFormat, YuvFrame, check_dimensions};
use super::h264;
use crate::clock::mono_ns;
use crate::frame::{Codec, EncodedFrame, FrameTiming};
use crate::pool::BufPool;
use ffmpeg_next as ffmpeg;
use ffmpeg_next::format::Pixel;
use std::sync::Once;

const MIN_DIMENSION: u32 = 16;
const MAX_DIMENSION: u32 = 8192;
/// The bitrate ladder tops out at 20 Mbps; this is the hard validation limit above it.
const MAX_BITRATE_KBPS: u32 = 100_000;
const MIN_BITRATE_KBPS: u32 = 100;
/// Encoder timestamps are milliseconds, so rate control sees real elapsed time even though
/// frames arrive irregularly (damage-driven, not on a fixed clock).
const TIME_BASE_DEN: i32 = 1000;

static FFMPEG_INIT: Once = Once::new();

fn init_ffmpeg() {
    FFMPEG_INIT.call_once(|| {
        // Failure to initialise only loses logging control; opening the codec reports real errors.
        let _ = ffmpeg::init();
        // x264 prints its configuration banner at info level on every open.
        ffmpeg::log::set_level(ffmpeg::log::Level::Warning);
    });
}

/// Encoder settings. [`EncoderConfig::new`] gives the production defaults from S2.
#[derive(Clone, Debug, PartialEq)]
pub struct EncoderConfig {
    /// Picture size; even, 16 to 8192.
    pub width: u32,
    pub height: u32,
    pub format: YuvFormat,
    /// Frame rate ceiling. Frames need not arrive at this rate; it sizes the VBV budget.
    pub fps: u32,
    /// Rate cap in kbit/s (VBV max rate). The ladder tops out at 20000.
    pub bitrate_kbps: u32,
    /// Constant rate factor; quality target, capped by the VBV.
    pub crf: u8,
    /// VBV buffer size in frames of the current rate (a tunable; 2 to 4 is the provisional
    /// range, S2 measured with 1).
    pub vbv_frames: f32,
    /// Encoder threads; 0 means one per available core, at most 4.
    pub threads: u32,
    /// Slice-based threading (lowest latency, one packet per frame). Off means frame threading
    /// when `threads` > 1, which makes the encoder lag by about `threads` frames.
    pub sliced_threads: bool,
    /// Maximum frames between keyframes.
    pub keyint: u32,
    /// Spread intra coding over successive frames instead of periodic IDRs.
    pub intra_refresh: bool,
    /// x264 preset.
    pub preset: String,
}

impl EncoderConfig {
    /// S2 settings for a `width` x `height` picture: ultrafast, zerolatency, crf 23, VBV of
    /// 2 frames, 60 fps ceiling, 8 Mbps start, sliced threads, keyint 120, intra refresh.
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            format: YuvFormat::I420,
            fps: 60,
            bitrate_kbps: 8_000,
            crf: 23,
            vbv_frames: 2.0,
            threads: 0,
            sliced_threads: true,
            keyint: 120,
            intra_refresh: true,
            preset: "ultrafast".to_string(),
        }
    }

    fn validate(&self) -> Result<(), EncodeError> {
        let bad = |m: String| Err(EncodeError::Config(m));
        check_dimensions(self.width, self.height)?;
        if !(MIN_DIMENSION..=MAX_DIMENSION).contains(&self.width)
            || !(MIN_DIMENSION..=MAX_DIMENSION).contains(&self.height)
        {
            return bad(format!(
                "{}x{} is outside {MIN_DIMENSION} to {MAX_DIMENSION}",
                self.width, self.height
            ));
        }
        if !(1..=240).contains(&self.fps) {
            return bad(format!("fps {} is outside 1 to 240", self.fps));
        }
        if !(MIN_BITRATE_KBPS..=MAX_BITRATE_KBPS).contains(&self.bitrate_kbps) {
            return bad(format!(
                "bitrate {} kbit/s is outside {MIN_BITRATE_KBPS} to {MAX_BITRATE_KBPS}",
                self.bitrate_kbps
            ));
        }
        if self.crf > 51 {
            return bad(format!("crf {} is above 51", self.crf));
        }
        if !(self.vbv_frames.is_finite() && (0.5..=60.0).contains(&self.vbv_frames)) {
            return bad(format!(
                "vbv_frames {} is outside 0.5 to 60",
                self.vbv_frames
            ));
        }
        if self.keyint == 0 || self.keyint > 100_000 {
            return bad(format!("keyint {} is outside 1 to 100000", self.keyint));
        }
        if self.threads > 64 {
            return bad(format!("threads {} is above 64", self.threads));
        }
        if self.preset.is_empty() || !self.preset.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return bad("preset must be a plain x264 preset name".to_string());
        }
        Ok(())
    }

    fn resolved_threads(&self) -> u32 {
        if self.threads > 0 {
            self.threads
        } else {
            std::thread::available_parallelism()
                .map_or(1, |n| n.get())
                .min(4) as u32
        }
    }

    /// VBV max rate in bit/s.
    fn max_rate_bps(&self) -> i64 {
        i64::from(self.bitrate_kbps) * 1000
    }

    /// VBV buffer in bits: `vbv_frames` frames of the current rate.
    fn buffer_bits(&self) -> i64 {
        let per_frame = self.max_rate_bps() as f64 / f64::from(self.fps);
        ((per_frame * f64::from(self.vbv_frames)) as i64).max(1000)
    }
}

/// Per-frame input that is carried through to the [`EncodedFrame`].
#[derive(Clone, Copy, Debug, Default)]
pub struct FrameMeta {
    /// Damage arrival ([`crate::mono_ns`]).
    pub t_damage_ns: u64,
    /// Screen read ([`crate::mono_ns`]). Also drives the encoder timestamps, so it must not
    /// go backwards.
    pub t_capture_ns: u64,
    /// Colour conversion finished ([`crate::mono_ns`]).
    pub t_convert_ns: u64,
}

/// An x264 H.264 encoder producing low-latency Annex B streams with BT.709 limited-range
/// VUI tags.
///
/// **Rate changes** ([`set_bitrate_kbps`](Self::set_bitrate_kbps),
/// [`set_fps`](Self::set_fps), [`set_vbv_frames`](Self::set_vbv_frames)) take effect on the
/// next frame without reopening the encoder or forcing an IDR: libx264's libavcodec wrapper
/// applies a changed `rc_max_rate` and `rc_buffer_size` through `x264_encoder_reconfig`.
/// Only a size change ([`resize`](Self::resize)) reopens the encoder, and then the next frame
/// is an IDR. The frame rate given at open time stays what x264 uses for timing; `set_fps`
/// only re-sizes the VBV budget.
pub struct X264Encoder {
    cfg: EncoderConfig,
    enc: ffmpeg::encoder::Video,
    frame: ffmpeg::frame::Video,
    pkt: ffmpeg::Packet,
    pool: BufPool,
    frame_no: u64,
    want_idr: bool,
    /// `t_capture_ns` of the first frame since the encoder was opened: timestamp zero.
    base_ns: Option<u64>,
    last_pts: i64,
    reopens: u32,
}

impl X264Encoder {
    pub fn new(cfg: EncoderConfig) -> Result<Self, EncodeError> {
        cfg.validate()?;
        init_ffmpeg();
        let enc = open(&cfg)?;
        let frame = alloc_frame(&cfg);
        // Output buffers are sized for a worst-case keyframe at a couple of frames of rate.
        let cap = (cfg.buffer_bits() as usize / 8).clamp(64 * 1024, 4 * 1024 * 1024);
        Ok(Self {
            pool: BufPool::new(8, cap),
            cfg,
            enc,
            frame,
            pkt: ffmpeg::Packet::empty(),
            frame_no: 0,
            want_idr: true,
            base_ns: None,
            last_pts: -1,
            reopens: 0,
        })
    }

    pub fn config(&self) -> &EncoderConfig {
        &self.cfg
    }

    /// Times the encoder has been reopened since creation (only [`resize`](Self::resize) does).
    pub fn reopen_count(&self) -> u32 {
        self.reopens
    }

    /// Make the next frame an IDR (a client connected or lost sync).
    pub fn request_idr(&mut self) {
        self.want_idr = true;
    }

    /// Change the rate cap, effective on the next frame, no reopen.
    pub fn set_bitrate_kbps(&mut self, kbps: u32) -> Result<(), EncodeError> {
        self.update(|c| c.bitrate_kbps = kbps)
    }

    /// Change the frame rate ceiling used to size the VBV budget, no reopen.
    pub fn set_fps(&mut self, fps: u32) -> Result<(), EncodeError> {
        self.update(|c| c.fps = fps)
    }

    /// Change the VBV buffer size in frames, no reopen.
    pub fn set_vbv_frames(&mut self, frames: f32) -> Result<(), EncodeError> {
        self.update(|c| c.vbv_frames = frames)
    }

    fn update(&mut self, change: impl FnOnce(&mut EncoderConfig)) -> Result<(), EncodeError> {
        let mut next = self.cfg.clone();
        change(&mut next);
        next.validate()?;
        self.cfg = next;
        self.apply_rate();
        Ok(())
    }

    fn apply_rate(&mut self) {
        self.enc.set_max_bit_rate(self.cfg.max_rate_bps() as usize);
        let bits = self.cfg.buffer_bits();
        // SAFETY: `as_mut_ptr` returns the live AVCodecContext owned by `self.enc`; we are the
        // only user, called between frames, and rc_buffer_size is a plain integer field that
        // libx264's wrapper re-reads on the next frame. ffmpeg-next has no safe setter for it.
        unsafe {
            (*self.enc.as_mut_ptr()).rc_buffer_size = bits.min(i64::from(i32::MAX)) as i32;
        }
    }

    /// Change the picture size. Reopens the encoder; the next frame is an IDR.
    pub fn resize(&mut self, width: u32, height: u32) -> Result<(), EncodeError> {
        let mut next = self.cfg.clone();
        next.width = width;
        next.height = height;
        next.validate()?;
        if (width, height) == (self.cfg.width, self.cfg.height) {
            return Ok(());
        }
        // Open first so a failure leaves the old encoder usable.
        let enc = open(&next)?;
        self.frame = alloc_frame(&next);
        self.enc = enc;
        self.cfg = next;
        self.reopens += 1;
        self.want_idr = true;
        self.base_ns = None;
        self.last_pts = -1;
        Ok(())
    }

    /// Encode one picture. Returns `None` if the encoder produced no output for it (it buffers
    /// nothing in zero-latency mode, so this is not expected in practice).
    pub fn encode(
        &mut self,
        yuv: &YuvFrame,
        meta: &FrameMeta,
    ) -> Result<Option<EncodedFrame>, EncodeError> {
        if (yuv.width(), yuv.height()) != (self.cfg.width, self.cfg.height) {
            return Err(EncodeError::Config(format!(
                "picture is {}x{} but the encoder is {}x{}; call resize first",
                yuv.width(),
                yuv.height(),
                self.cfg.width,
                self.cfg.height
            )));
        }
        if yuv.format() != self.cfg.format {
            return Err(EncodeError::Config(format!(
                "picture format {:?} differs from the encoder's {:?}",
                yuv.format(),
                self.cfg.format
            )));
        }
        upload(&mut self.frame, yuv);

        let base = *self.base_ns.get_or_insert(meta.t_capture_ns);
        let elapsed_ms = (meta.t_capture_ns.saturating_sub(base) / 1_000_000) as i64;
        let pts = elapsed_ms.max(self.last_pts + 1);
        self.last_pts = pts;
        self.frame.set_pts(Some(pts));
        let idr = std::mem::take(&mut self.want_idr);
        self.frame.set_kind(if idr {
            ffmpeg::picture::Type::I
        } else {
            ffmpeg::picture::Type::None
        });

        let t_start = mono_ns();
        self.enc
            .send_frame(&self.frame)
            .map_err(EncodeError::Encode)?;
        let mut out = None;
        loop {
            match self.enc.receive_packet(&mut self.pkt) {
                Ok(()) => {
                    let mut buf = self.pool.get();
                    buf.set(self.pkt.data().unwrap_or(&[]));
                    out = Some((buf, self.pkt.is_key()));
                }
                Err(ffmpeg::Error::Other { errno }) if errno == EAGAIN => break,
                Err(ffmpeg::Error::Eof) => break,
                Err(e) => return Err(EncodeError::Encode(e)),
            }
        }
        let t_end = mono_ns();
        let Some((data, key)) = out else {
            return Ok(None);
        };
        let is_idr = h264::starts_with_idr(&data);
        let frame_no = self.frame_no;
        self.frame_no += 1;
        Ok(Some(EncodedFrame {
            frame_no,
            codec: Codec::H264,
            keyframe: key || is_idr,
            idr: is_idr,
            width: self.cfg.width,
            height: self.cfg.height,
            timing: FrameTiming {
                t_damage_ns: meta.t_damage_ns,
                t_capture_ns: meta.t_capture_ns,
                t_convert_ns: meta.t_convert_ns,
                t_encode_start_ns: t_start,
                t_encode_end_ns: t_end,
            },
            data,
        }))
    }
}

/// `EAGAIN` on Linux; libavcodec returns `AVERROR(EAGAIN)` when it wants more input.
const EAGAIN: i32 = 11;

fn pixel_format(f: YuvFormat) -> Pixel {
    match f {
        YuvFormat::I420 => Pixel::YUV420P,
        YuvFormat::Nv12 => Pixel::NV12,
    }
}

fn alloc_frame(cfg: &EncoderConfig) -> ffmpeg::frame::Video {
    let mut f = ffmpeg::frame::Video::new(pixel_format(cfg.format), cfg.width, cfg.height);
    f.set_color_space(ffmpeg::color::Space::BT709);
    f.set_color_range(ffmpeg::color::Range::MPEG);
    f
}

fn open(cfg: &EncoderConfig) -> Result<ffmpeg::encoder::Video, EncodeError> {
    let codec = ffmpeg::encoder::find_by_name("libx264").ok_or(EncodeError::EncoderMissing)?;
    let ctx = ffmpeg::codec::context::Context::new_with_codec(codec);
    let mut enc = ctx.encoder().video().map_err(EncodeError::Open)?;
    enc.set_width(cfg.width);
    enc.set_height(cfg.height);
    enc.set_format(pixel_format(cfg.format));
    enc.set_time_base((1, TIME_BASE_DEN));
    enc.set_frame_rate(Some((cfg.fps as i32, 1)));
    enc.set_gop(cfg.keyint);
    enc.set_max_b_frames(0);
    enc.set_flags(ffmpeg::codec::Flags::LOW_DELAY);
    // Colour tags, always: an untagged stream makes the client guess (S2: 10 to 25 dB off).
    enc.set_colorspace(ffmpeg::color::Space::BT709);
    enc.set_color_range(ffmpeg::color::Range::MPEG);

    let mut x264 = format!(
        "crf={}:keyint={}:bframes=0:rc-lookahead=0:sync-lookahead=0:repeat-headers=1:annexb=1:aud=0:threads={}:sliced-threads={}:intra-refresh={}",
        cfg.crf,
        cfg.keyint,
        cfg.resolved_threads(),
        u8::from(cfg.sliced_threads),
        u8::from(cfg.intra_refresh),
    );
    if !cfg.intra_refresh {
        x264.push_str(":scenecut=0");
    }
    x264.push_str(":colorprim=bt709:transfer=bt709:colormatrix=bt709:fullrange=off");

    let mut opts = ffmpeg::Dictionary::new();
    opts.set("preset", &cfg.preset);
    opts.set("tune", "zerolatency");
    opts.set("forced-idr", "1");
    // VBV goes through the codec context (not x264-params) so a later change of the context
    // fields is what libx264's wrapper compares and applies.
    opts.set("maxrate", &cfg.max_rate_bps().to_string());
    opts.set("bufsize", &cfg.buffer_bits().to_string());
    opts.set("x264-params", &x264);
    enc.open_with(opts).map_err(EncodeError::Open)
}

/// Copy a converted picture into the encoder's frame, honouring its (aligned) strides.
fn upload(dst: &mut ffmpeg::frame::Video, src: &YuvFrame) {
    for i in 0..src.plane_count() {
        let p = src.plane(i);
        let dst_stride = dst.stride(i);
        let out = dst.data_mut(i);
        if dst_stride == p.stride {
            let n = (p.stride * p.rows).min(out.len()).min(p.data.len());
            out[..n].copy_from_slice(&p.data[..n]);
        } else {
            for (row, src_row) in p.data.chunks(p.stride).take(p.rows).enumerate() {
                let o = row * dst_stride;
                out[o..o + p.row_bytes].copy_from_slice(&src_row[..p.row_bytes]);
            }
        }
    }
}
