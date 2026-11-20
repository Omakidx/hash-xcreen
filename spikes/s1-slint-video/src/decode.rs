//! libavcodec decoding (VAAPI or software) on a dedicated thread, paced in real time.
//!
//! Output per frame is one of:
//!  * `Payload::Rgba`: CPU RGBA pixel buffer (path c),
//!  * `Payload::Yuv`: CPU planar frame (software decode, or VAAPI + download) for paths a/b,
//!  * `Payload::Drm`: VAAPI surface exported as DRM PRIME / DMA-BUF descriptor (zero copy, paths a/b).

use crate::stats::Stats;
use anyhow::{Context, Result, anyhow, bail};
use ffmpeg_next as ffmpeg;
use ffmpeg_next::ffi;
use slint::{Rgba8Pixel, SharedPixelBuffer};
use std::ffi::CString;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecodeMode {
    Auto,
    Vaapi,
    Software,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OutKind {
    /// CPU RGBA (path c).
    Rgba,
    /// GPU-friendly: DRM PRIME if VAAPI is used and `dmabuf` is true, else CPU planes.
    Planes { dmabuf: bool },
}

pub struct AvFrame(pub *mut ffi::AVFrame);
// SAFETY: an AVFrame is a refcounted buffer set; we never access it from two threads at once
// without external synchronisation (it is moved through the mailbox).
unsafe impl Send for AvFrame {}
unsafe impl Sync for AvFrame {}
impl AvFrame {
    pub fn alloc() -> Result<Self> {
        // SAFETY: plain allocation.
        let p = unsafe { ffi::av_frame_alloc() };
        if p.is_null() { bail!("av_frame_alloc failed") } else { Ok(Self(p)) }
    }
    pub fn width(&self) -> i32 {
        unsafe { (*self.0).width }
    }
    pub fn height(&self) -> i32 {
        unsafe { (*self.0).height }
    }
    pub fn format(&self) -> i32 {
        unsafe { (*self.0).format }
    }
    pub fn data(&self, i: usize) -> *const u8 {
        unsafe { (*self.0).data[i] }
    }
    pub fn linesize(&self, i: usize) -> i32 {
        unsafe { (*self.0).linesize[i] }
    }
}
impl Drop for AvFrame {
    fn drop(&mut self) {
        // SAFETY: pointer came from av_frame_alloc and is freed exactly once.
        unsafe { ffi::av_frame_free(&mut self.0) }
    }
}

/// A VAAPI surface mapped to DRM PRIME. Keeps the VAAPI frame alive so the surface (and the
/// DMA-BUF fds) stay valid.
pub struct DrmFrame {
    pub drm: AvFrame,
    _src: AvFrame,
}
impl DrmFrame {
    pub fn desc(&self) -> &ffi::AVDRMFrameDescriptor {
        // SAFETY: for AV_PIX_FMT_DRM_PRIME data[0] points at an AVDRMFrameDescriptor.
        unsafe { &*((*self.drm.0).data[0] as *const ffi::AVDRMFrameDescriptor) }
    }
    /// All (layer, plane) descriptors flattened in order (NV12: Y then interleaved CbCr).
    pub fn planes(&self) -> Vec<ffi::AVDRMPlaneDescriptor> {
        let d = self.desc();
        d.layers.iter().take(d.nb_layers as usize).flat_map(|l| l.planes.iter().take(l.nb_planes as usize).copied()).collect()
    }
    pub fn width(&self) -> i32 {
        self.drm.width()
    }
    pub fn height(&self) -> i32 {
        self.drm.height()
    }
}

pub enum Payload {
    Rgba(SharedPixelBuffer<Rgba8Pixel>),
    Yuv(Arc<AvFrame>),
    Drm(Arc<DrmFrame>),
}

pub struct DecodedFrame {
    pub decode_done: Instant,
    pub payload: Payload,
}

/// Latest-frame-wins slot between the decoder thread and the UI/render thread.
pub struct Mailbox {
    slot: Mutex<Option<DecodedFrame>>,
    pub pending: AtomicBool,
    pub produced: AtomicU64,
}
impl Mailbox {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { slot: Mutex::new(None), pending: AtomicBool::new(false), produced: AtomicU64::new(0) })
    }
    /// Returns true if an undisplayed frame was replaced (a drop).
    pub fn put(&self, f: DecodedFrame) -> bool {
        self.produced.fetch_add(1, Ordering::Relaxed);
        self.slot.lock().unwrap().replace(f).is_some()
    }
    pub fn take(&self) -> Option<DecodedFrame> {
        self.slot.lock().unwrap().take()
    }
}

#[derive(Clone)]
pub struct DecoderOpts {
    pub input: String,
    pub mode: DecodeMode,
    pub out: OutKind,
    pub fps: f64,
    pub threads: usize,
    pub realtime: bool,
}

pub fn av_err(e: i32) -> String {
    let mut buf = [0i8; 128];
    // SAFETY: buffer is large enough; av_strerror NUL-terminates.
    unsafe {
        ffi::av_strerror(e, buf.as_mut_ptr(), buf.len());
        std::ffi::CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
    }
}

/// Render nodes to try for VAAPI.
fn render_nodes() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir("/dev/dri")
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path().to_string_lossy().into_owned())
                .filter(|p| p.contains("renderD"))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Try to create a VAAPI hardware device. Returns the device ref and a description, or a
/// clear reason why VAAPI is unavailable.
pub fn open_vaapi() -> Result<(*mut ffi::AVBufferRef, String)> {
    let nodes = render_nodes();
    if nodes.is_empty() {
        bail!(
            "no DRM render node (/dev/dri/renderD*) present: no GPU is exposed to this machine \
             (only {:?}); VAAPI cannot be used",
            std::fs::read_dir("/dev/dri")
                .map(|r| r.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect::<Vec<_>>())
                .unwrap_or_default()
        );
    }
    let mut last = String::new();
    for n in &nodes {
        let c = CString::new(n.as_str())?;
        let mut dev: *mut ffi::AVBufferRef = ptr::null_mut();
        // SAFETY: valid out-pointer and NUL-terminated path.
        let r = unsafe {
            ffi::av_hwdevice_ctx_create(&mut dev, ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_VAAPI, c.as_ptr(), ptr::null_mut(), 0)
        };
        if r >= 0 {
            return Ok((dev, n.clone()));
        }
        last = format!("{n}: {}", av_err(r));
    }
    Err(anyhow!("VAAPI device creation failed on all render nodes ({last}); check `vainfo` and drivers"))
}

unsafe extern "C" fn pick_vaapi(_ctx: *mut ffi::AVCodecContext, fmts: *const ffi::AVPixelFormat) -> ffi::AVPixelFormat {
    let mut p = fmts;
    // SAFETY: the list is terminated with AV_PIX_FMT_NONE.
    unsafe {
        while *p != ffi::AVPixelFormat::AV_PIX_FMT_NONE {
            if *p == ffi::AVPixelFormat::AV_PIX_FMT_VAAPI {
                return *p;
            }
            p = p.add(1);
        }
    }
    ffi::AVPixelFormat::AV_PIX_FMT_NONE
}

struct Sws {
    ctx: *mut ffi::SwsContext,
    fmt: i32,
    w: i32,
    h: i32,
}
impl Drop for Sws {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            unsafe { ffi::sws_freeContext(self.ctx) }
        }
    }
}

fn to_rgba(sws: &mut Option<Sws>, src: *const ffi::AVFrame) -> Result<SharedPixelBuffer<Rgba8Pixel>> {
    // SAFETY: src is a valid decoded software frame.
    unsafe {
        let (w, h, fmt) = ((*src).width, (*src).height, (*src).format);
        if sws.as_ref().is_none_or(|s| s.fmt != fmt || s.w != w || s.h != h) {
            let src_fmt: ffi::AVPixelFormat = std::mem::transmute(fmt);
            let ctx = ffi::sws_getContext(
                w,
                h,
                src_fmt,
                w,
                h,
                ffi::AVPixelFormat::AV_PIX_FMT_RGBA,
                ffi::SWS_BILINEAR,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
            );
            if ctx.is_null() {
                bail!("sws_getContext failed");
            }
            // BT.709, limited-range source -> full-range RGB, matching the GPU shaders.
            let coef = ffi::sws_getCoefficients(ffi::SWS_CS_ITU709);
            ffi::sws_setColorspaceDetails(ctx, coef, 0, coef, 1, 0, 1 << 16, 1 << 16);
            *sws = Some(Sws { ctx, fmt, w, h });
        }
        let mut buf = SharedPixelBuffer::<Rgba8Pixel>::new(w as u32, h as u32);
        let dst_ptr = buf.make_mut_bytes().as_mut_ptr();
        let dst: [*mut u8; 4] = [dst_ptr, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()];
        let dst_stride: [i32; 4] = [w * 4, 0, 0, 0];
        ffi::sws_scale(
            sws.as_ref().unwrap().ctx,
            (*src).data.as_ptr() as *const *const u8,
            (*src).linesize.as_ptr(),
            0,
            h,
            dst.as_ptr(),
            dst_stride.as_ptr(),
        );
        Ok(buf)
    }
}

pub struct DecoderInfo {
    pub description: String,
    pub hw_active: bool,
    pub width: u32,
    pub height: u32,
}

/// Open the input and decoder, returning a runnable closure-less struct.
pub struct Decoder {
    ictx: ffmpeg::format::context::Input,
    dec: ffmpeg::decoder::Video,
    stream_idx: usize,
    hw: bool,
    opts: DecoderOpts,
    pub info: DecoderInfo,
    _hw_dev: *mut ffi::AVBufferRef,
}
unsafe impl Send for Decoder {}

impl Decoder {
    pub fn open(opts: DecoderOpts) -> Result<Self> {
        ffmpeg::init().context("ffmpeg init")?;
        let ictx = ffmpeg::format::input(&opts.input).with_context(|| format!("open {}", opts.input))?;
        let stream = ictx.streams().best(ffmpeg::media::Type::Video).ok_or_else(|| anyhow!("no video stream"))?;
        let stream_idx = stream.index();
        let mut cctx = ffmpeg::codec::context::Context::from_parameters(stream.parameters())?;

        let mut hw_dev: *mut ffi::AVBufferRef = ptr::null_mut();
        let mut desc = String::new();
        let mut hw = false;
        if opts.mode != DecodeMode::Software {
            match open_vaapi() {
                Ok((dev, node)) => {
                    // SAFETY: cctx holds a valid AVCodecContext; we give it its own device reference.
                    unsafe {
                        let p = cctx.as_mut_ptr();
                        (*p).hw_device_ctx = ffi::av_buffer_ref(dev);
                        (*p).get_format = Some(pick_vaapi);
                    }
                    hw_dev = dev;
                    hw = true;
                    desc = format!("libavcodec h264 + VAAPI ({node})");
                }
                Err(e) if opts.mode == DecodeMode::Vaapi => return Err(e.context("--decode vaapi requested")),
                Err(e) => eprintln!("[decode] VAAPI unavailable, using software decode: {e}"),
            }
        }
        if !hw {
            cctx.set_threading(ffmpeg::threading::Config {
                kind: ffmpeg::threading::Type::Slice,
                count: opts.threads,
            });
            desc = format!("libavcodec h264 software ({} slice threads)", opts.threads);
        }
        let dec = cctx.decoder().video().context("open decoder")?;
        let (width, height) = (dec.width(), dec.height());
        Ok(Self { ictx, dec, stream_idx, hw, info: DecoderInfo { description: desc, hw_active: hw, width, height }, opts, _hw_dev: hw_dev })
    }

    /// Decode loop; runs until `stop` is set. Frames go to `mailbox`; `on_frame` is called after
    /// each put (used to wake the UI thread).
    pub fn run(mut self, mailbox: Arc<Mailbox>, stats: Arc<Stats>, stop: Arc<AtomicBool>, on_frame: impl Fn() + Send) {
        let frame_dur = Duration::from_secs_f64(1.0 / self.opts.fps);
        let start = Instant::now();
        let mut n: u64 = 0;
        let mut sws: Option<Sws> = None;
        let mut sw_frame = ffmpeg::frame::Video::empty();
        let mut hw_frame = ffmpeg::frame::Video::empty();
        let idx = self.stream_idx;
        'outer: loop {
            let mut got_any = false;
            let mut eof = true;
            loop {
                if stop.load(Ordering::Relaxed) {
                    break 'outer;
                }
                let mut pkt = ffmpeg::Packet::empty();
                match pkt.read(&mut self.ictx) {
                    Ok(()) => {}
                    Err(_) => break,
                }
                if pkt.stream() != idx {
                    continue;
                }
                eof = false;
                if self.opts.realtime {
                    let due = start + frame_dur.mul_f64(n as f64);
                    sleep_until(due);
                }
                let t0 = Instant::now();
                if self.dec.send_packet(&pkt).is_err() {
                    continue;
                }
                loop {
                    let target = if self.hw { &mut hw_frame } else { &mut sw_frame };
                    if self.dec.receive_frame(target).is_err() {
                        break;
                    }
                    got_any = true;
                    let decode_ms = t0.elapsed().as_secs_f64() * 1e3;
                    let tc = Instant::now();
                    let res = self.finish_frame(&mut sw_frame, &mut hw_frame, &mut sws);
                    let convert_ms = tc.elapsed().as_secs_f64() * 1e3;
                    let payload = match res {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("[decode] frame {n}: {e:#}");
                            stop.store(true, Ordering::Relaxed);
                            break 'outer;
                        }
                    };
                    let now = Instant::now();
                    // Late = decoding of this frame could only start more than half a frame after its slot
                    // (the decoder was still busy with earlier frames).
                    if self.opts.realtime && t0 > start + frame_dur.mul_f64(n as f64) + frame_dur / 2 {
                        stats.with(|s| s.decoder_late += 1);
                    }
                    let f = DecodedFrame { decode_done: now, payload };
                    stats.with(|s| {
                        s.frames_decoded += 1;
                        s.decode_ms.push(decode_ms);
                        if matches!(f.payload, Payload::Rgba(_)) {
                            s.convert_ms.push(convert_ms);
                        }
                    });
                    if mailbox.put(f) {
                        stats.with(|s| s.frames_dropped += 1);
                    }
                    if !mailbox.pending.swap(true, Ordering::AcqRel) {
                        on_frame();
                    }
                    n += 1;
                }
            }
            if eof && !got_any {
                eprintln!("[decode] no video packets in input");
                break;
            }
            // Loop the clip.
            let _ = self.ictx.seek(0, ..1);
            self.dec.flush();
        }
    }

    fn finish_frame(
        &self,
        sw_frame: &mut ffmpeg::frame::Video,
        hw_frame: &mut ffmpeg::frame::Video,
        sws: &mut Option<Sws>,
    ) -> Result<Payload> {
        // SAFETY: frames were filled by the decoder; the FFI calls below follow libavutil's contracts.
        unsafe {
            let wants_rgba = self.opts.out == OutKind::Rgba;
            if !self.hw {
                if wants_rgba {
                    return Ok(Payload::Rgba(to_rgba(sws, sw_frame.as_ptr())?));
                }
                return Ok(Payload::Yuv(Arc::new(clone_frame(sw_frame.as_ptr())?)));
            }
            let dmabuf = matches!(self.opts.out, OutKind::Planes { dmabuf: true });
            if dmabuf {
                let src = clone_frame(hw_frame.as_ptr())?;
                let drm = AvFrame::alloc()?;
                (*drm.0).format = ffi::AVPixelFormat::AV_PIX_FMT_DRM_PRIME as i32;
                let r = ffi::av_hwframe_map(drm.0, src.0, ffi::AV_HWFRAME_MAP_READ as i32);
                if r < 0 {
                    bail!("av_hwframe_map(VAAPI -> DRM_PRIME) failed: {}", av_err(r));
                }
                return Ok(Payload::Drm(Arc::new(DrmFrame { drm, _src: src })));
            }
            // Hardware decode + download to system memory (NV12).
            let dl = AvFrame::alloc()?;
            let r = ffi::av_hwframe_transfer_data(dl.0, hw_frame.as_ptr(), 0);
            if r < 0 {
                bail!("av_hwframe_transfer_data failed: {}", av_err(r));
            }
            if wants_rgba {
                Ok(Payload::Rgba(to_rgba(sws, dl.0)?))
            } else {
                Ok(Payload::Yuv(Arc::new(dl)))
            }
        }
    }
}

unsafe fn clone_frame(src: *const ffi::AVFrame) -> Result<AvFrame> {
    let f = AvFrame::alloc()?;
    // SAFETY: both pointers are valid; av_frame_ref takes a new reference to the buffers (no copy).
    let r = unsafe { ffi::av_frame_ref(f.0, src) };
    if r < 0 {
        bail!("av_frame_ref failed: {}", av_err(r));
    }
    Ok(f)
}

fn sleep_until(t: Instant) {
    loop {
        let now = Instant::now();
        if now >= t {
            return;
        }
        let rem = t - now;
        if rem > Duration::from_micros(1500) {
            std::thread::sleep(rem - Duration::from_micros(1000));
        } else {
            std::hint::spin_loop();
        }
    }
}

/// Human-readable VAAPI/capability probe for `--detect`.
pub fn detect_report() -> String {
    let mut s = String::new();
    let v = ffmpeg::codec::version();
    s += &format!("ffmpeg libavcodec: {}.{}.{}\n", v >> 16, (v >> 8) & 0xff, v & 0xff);
    match open_vaapi() {
        Ok((dev, node)) => {
            s += &format!("VAAPI: OK on {node}\n");
            // SAFETY: dev was created by open_vaapi.
            unsafe {
                let mut d = dev;
                ffi::av_buffer_unref(&mut d);
            }
        }
        Err(e) => s += &format!("VAAPI: UNAVAILABLE: {e}\n"),
    }
    s
}
