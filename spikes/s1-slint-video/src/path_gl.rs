#![allow(unsafe_op_in_unsafe_fn)] // spike: raw GL/EGL FFI, every call is unsafe by nature
//! Path (b): OpenGL texture handed to Slint's femtovg OpenGL renderer via
//! `BorrowedOpenGLTextureBuilder`.
//!
//! Frames arrive either as CPU planes (uploaded with glTexSubImage2D: this is the "software GL"
//! variant that runs without a GPU) or as DRM PRIME / DMA-BUF descriptors imported with
//! `EGL_EXT_image_dma_buf_import` (the zero-copy hardware route; needs a VAAPI GPU and an EGL
//! context). Either way a YUV->RGB pass renders into an RGBA8 texture that Slint samples.

use crate::decode::{DecodedFrame, DrmFrame, Payload};
use anyhow::{Context as _, Result, anyhow, bail};
use ffmpeg_next::ffi;
use glow::HasContext;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::num::NonZeroU32;
use std::sync::Arc;

const VS: &str = "
out vec2 v_uv;
void main() {
    vec2 p = vec2(float((gl_VertexID << 1) & 2), float(gl_VertexID & 2));
    gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);
}";

const FS: &str = "
precision highp float;
uniform sampler2D t0;
uniform sampler2D t1;
uniform sampler2D t2;
uniform int mode;      // 0 = I420 (Y,U,V planes), 1 = NV12 (Y, interleaved UV)
uniform vec2 size;
out vec4 o;
void main() {
    vec2 uv = gl_FragCoord.xy / size;
    float y = texture(t0, uv).r;
    vec2 c = (mode == 0) ? vec2(texture(t1, uv).r, texture(t2, uv).r) : texture(t1, uv).rg;
    y = (y - 16.0 / 255.0) * (255.0 / 219.0);
    c = (c - 128.0 / 255.0) * (255.0 / 224.0);
    // BT.709 limited range -> full range RGB
    o = vec4(y + 1.5748 * c.y, y - 0.1873 * c.x - 0.4681 * c.y, y + 1.8556 * c.x, 1.0);
}";

const DRM_FORMAT_R8: u32 = u32::from_le_bytes(*b"R8  ");
const DRM_FORMAT_GR88: u32 = u32::from_le_bytes(*b"GR88");
const DRM_MOD_INVALID: u64 = 0x00ff_ffff_ffff_ffff;

type EglCreateImage = unsafe extern "C" fn(*mut c_void, *mut c_void, u32, *mut c_void, *const i32) -> *mut c_void;
type EglDestroyImage = unsafe extern "C" fn(*mut c_void, *mut c_void) -> u32;
type GlImageTarget = unsafe extern "C" fn(u32, *mut c_void);

pub struct EglImport {
    display: *mut c_void,
    create: EglCreateImage,
    destroy: EglDestroyImage,
    target: GlImageTarget,
    pub has_modifiers: bool,
    pub info: String,
    _egl: khronos_egl::DynamicInstance<khronos_egl::EGL1_4>,
}

impl EglImport {
    /// Check that the *current* GL context is an EGL one with dma-buf import support.
    fn probe() -> Result<Self> {
        // SAFETY: loads libEGL.so.1 dynamically; fails cleanly if absent.
        let egl = unsafe { khronos_egl::DynamicInstance::<khronos_egl::EGL1_4>::load_required() }
            .map_err(|e| anyhow!("cannot load libEGL.so.1: {e}"))?;
        let ctx = egl.get_current_context();
        let dpy = egl.get_current_display();
        let (Some(_ctx), Some(dpy)) = (ctx, dpy) else {
            bail!(
                "Slint's OpenGL context is not an EGL context (it is GLX on X11); EGL_EXT_image_dma_buf_import \
                 needs an EGL context: run under a Wayland session (or an EGL-based Slint platform)"
            );
        };
        let exts = egl.query_string(Some(dpy), khronos_egl::EXTENSIONS).map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        if !exts.contains("EGL_EXT_image_dma_buf_import") {
            bail!("EGL display lacks EGL_EXT_image_dma_buf_import");
        }
        let has_modifiers = exts.contains("EGL_EXT_image_dma_buf_import_modifiers");
        let get = |n: &str| -> Result<*const c_void> {
            egl.get_proc_address(n).map(|f| f as *const c_void).ok_or_else(|| anyhow!("missing EGL entry point {n}"))
        };
        // SAFETY: the transmuted signatures match the EGL_KHR_image_base / GL_OES_EGL_image specs.
        unsafe {
            Ok(Self {
                display: dpy.as_ptr(),
                create: std::mem::transmute::<*const c_void, EglCreateImage>(get("eglCreateImageKHR")?),
                destroy: std::mem::transmute::<*const c_void, EglDestroyImage>(get("eglDestroyImageKHR")?),
                target: std::mem::transmute::<*const c_void, GlImageTarget>(get("glEGLImageTargetTexture2DOES")?),
                has_modifiers,
                info: format!("EGL dma-buf import OK (modifiers: {has_modifiers})"),
                _egl: egl,
            })
        }
    }
}

pub struct GlPresenter {
    gl: glow::Context,
    prog: glow::Program,
    vao: glow::VertexArray,
    fbo: glow::Framebuffer,
    target: glow::Texture,
    target_size: (u32, u32),
    planes: [glow::Texture; 3],
    plane_dims: [(u32, u32); 3],
    plane_fmt_nv12: Option<bool>,
    egl: Option<EglImport>,
    egl_err: Option<String>,
    hold: VecDeque<Arc<DrmFrame>>,
    pub sync: bool,
    pub info: String,
}

impl GlPresenter {
    pub fn new(get_proc: &dyn Fn(&std::ffi::CStr) -> *const c_void, sync: bool) -> Result<Self> {
        // SAFETY: Slint guarantees its GL context is current inside the rendering notifier.
        unsafe {
            let gl = glow::Context::from_loader_function_cstr(|s| get_proc(s));
            let v = gl.version().clone();
            let header = if v.is_embedded { "#version 300 es\n" } else { "#version 330 core\n" };
            let renderer = gl.get_parameter_string(glow::RENDERER);
            let version = gl.get_parameter_string(glow::VERSION);
            let vs = format!("{header}{VS}");
            let fs = format!("{header}{FS}");
            let prog = gl.create_program().map_err(|e| anyhow!(e))?;
            for (ty, src) in [(glow::VERTEX_SHADER, vs), (glow::FRAGMENT_SHADER, fs)] {
                let sh = gl.create_shader(ty).map_err(|e| anyhow!(e))?;
                gl.shader_source(sh, &src);
                gl.compile_shader(sh);
                if !gl.get_shader_compile_status(sh) {
                    bail!("shader compile: {}", gl.get_shader_info_log(sh));
                }
                gl.attach_shader(prog, sh);
            }
            gl.link_program(prog);
            if !gl.get_program_link_status(prog) {
                bail!("program link: {}", gl.get_program_info_log(prog));
            }
            let vao = gl.create_vertex_array().map_err(|e| anyhow!(e))?;
            let fbo = gl.create_framebuffer().map_err(|e| anyhow!(e))?;
            let target = gl.create_texture().map_err(|e| anyhow!(e))?;
            let mk = |gl: &glow::Context| -> Result<glow::Texture> {
                let t = gl.create_texture().map_err(|e| anyhow!(e))?;
                gl.bind_texture(glow::TEXTURE_2D, Some(t));
                gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_MIN_FILTER, glow::LINEAR as i32);
                gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_MAG_FILTER, glow::LINEAR as i32);
                gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_WRAP_S, glow::CLAMP_TO_EDGE as i32);
                gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_WRAP_T, glow::CLAMP_TO_EDGE as i32);
                Ok(t)
            };
            let planes = [mk(&gl)?, mk(&gl)?, mk(&gl)?];
            gl.bind_texture(glow::TEXTURE_2D, None);
            let (egl, egl_err) = match EglImport::probe() {
                Ok(e) => (Some(e), None),
                Err(e) => (None, Some(format!("{e:#}"))),
            };
            let info = format!(
                "GL {version} / {renderer}; {}",
                egl.as_ref().map(|e| e.info.clone()).unwrap_or_else(|| format!("DMA-BUF import unavailable: {}", egl_err.clone().unwrap_or_default()))
            );
            Ok(Self {
                gl,
                prog,
                vao,
                fbo,
                target,
                target_size: (0, 0),
                planes,
                plane_dims: [(0, 0); 3],
                plane_fmt_nv12: None,
                egl,
                egl_err,
                hold: VecDeque::new(),
                sync,
                info,
            })
        }
    }

    fn ensure_target(&mut self, w: u32, h: u32) {
        if self.target_size == (w, h) {
            return;
        }
        // SAFETY: GL context current.
        unsafe {
            let gl = &self.gl;
            gl.bind_texture(glow::TEXTURE_2D, Some(self.target));
            gl.tex_image_2d(glow::TEXTURE_2D, 0, glow::RGBA8 as i32, w as i32, h as i32, 0, glow::RGBA, glow::UNSIGNED_BYTE, glow::PixelUnpackData::Slice(None));
            gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_MIN_FILTER, glow::LINEAR as i32);
            gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_MAG_FILTER, glow::LINEAR as i32);
            gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_WRAP_S, glow::CLAMP_TO_EDGE as i32);
            gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_WRAP_T, glow::CLAMP_TO_EDGE as i32);
            gl.bind_texture(glow::TEXTURE_2D, None);
            gl.bind_framebuffer(glow::FRAMEBUFFER, Some(self.fbo));
            gl.framebuffer_texture_2d(glow::FRAMEBUFFER, glow::COLOR_ATTACHMENT0, glow::TEXTURE_2D, Some(self.target), 0);
        }
        self.target_size = (w, h);
    }

    /// Upload CPU planes (I420 or NV12) with glTexSubImage2D.
    unsafe fn upload_cpu(&mut self, f: &crate::decode::AvFrame) -> Result<i32> {
        let (w, h) = (f.width() as u32, f.height() as u32);
        let nv12 = f.format() == ffi::AVPixelFormat::AV_PIX_FMT_NV12 as i32;
        let i420 = f.format() == ffi::AVPixelFormat::AV_PIX_FMT_YUV420P as i32;
        if !nv12 && !i420 {
            bail!("unsupported software pixel format {} (expected yuv420p or nv12)", f.format());
        }
        let gl = &self.gl;
        let specs: Vec<(usize, u32, u32, u32, u32, usize)> = if nv12 {
            vec![(0, w, h, glow::R8, glow::RED, 1), (1, w / 2, h / 2, glow::RG8, glow::RG, 2)]
        } else {
            vec![(0, w, h, glow::R8, glow::RED, 1), (1, w / 2, h / 2, glow::R8, glow::RED, 1), (2, w / 2, h / 2, glow::R8, glow::RED, 1)]
        };
        for (i, pw, ph, ifmt, fmt, bpp) in specs {
            gl.active_texture(glow::TEXTURE0 + i as u32);
            gl.bind_texture(glow::TEXTURE_2D, Some(self.planes[i]));
            gl.pixel_store_i32(glow::UNPACK_ROW_LENGTH, f.linesize(i) / bpp as i32);
            gl.pixel_store_i32(glow::UNPACK_ALIGNMENT, 1);
            let len = f.linesize(i) as usize * (ph as usize - 1) + pw as usize * bpp;
            // SAFETY: plane i of a decoded frame is at least linesize*(h-1)+w*bpp bytes.
            let data = unsafe { std::slice::from_raw_parts(f.data(i), len) };
            if self.plane_dims[i] != (pw, ph) || self.plane_fmt_nv12 != Some(nv12) {
                gl.tex_image_2d(glow::TEXTURE_2D, 0, ifmt as i32, pw as i32, ph as i32, 0, fmt, glow::UNSIGNED_BYTE, glow::PixelUnpackData::Slice(Some(data)));
                self.plane_dims[i] = (pw, ph);
            } else {
                gl.tex_sub_image_2d(glow::TEXTURE_2D, 0, 0, 0, pw as i32, ph as i32, fmt, glow::UNSIGNED_BYTE, glow::PixelUnpackData::Slice(Some(data)));
            }
        }
        self.plane_fmt_nv12 = Some(nv12);
        gl.pixel_store_i32(glow::UNPACK_ROW_LENGTH, 0);
        Ok(if nv12 { 1 } else { 0 })
    }

    /// Import the DRM PRIME planes as EGLImages and bind them to the plane textures.
    /// Returns the created images (to destroy after the draw) and the shader mode (NV12).
    unsafe fn import_drm(&mut self, f: &DrmFrame) -> Result<(Vec<*mut c_void>, i32)> {
        let Some(egl) = self.egl.as_ref() else {
            bail!("DMA-BUF import unavailable: {}", self.egl_err.clone().unwrap_or_default());
        };
        let d = f.desc();
        let planes = f.planes();
        if planes.len() != 2 {
            bail!("expected 2 planes (NV12) in DRM frame, got {}", planes.len());
        }
        let (w, h) = (f.width(), f.height());
        let mut images = Vec::new();
        for (i, p) in planes.iter().enumerate() {
            let obj = &d.objects[p.object_index as usize];
            let (fourcc, pw, ph) = if i == 0 { (DRM_FORMAT_R8, w, h) } else { (DRM_FORMAT_GR88, w / 2, h / 2) };
            let mut a: Vec<i32> = vec![
                0x3057, pw, // EGL_WIDTH
                0x3056, ph, // EGL_HEIGHT
                0x3271, fourcc as i32, // EGL_LINUX_DRM_FOURCC_EXT
                0x3272, obj.fd, // EGL_DMA_BUF_PLANE0_FD_EXT
                0x3273, p.offset as i32, // PLANE0_OFFSET
                0x3274, p.pitch as i32, // PLANE0_PITCH
            ];
            if egl.has_modifiers && obj.format_modifier != DRM_MOD_INVALID {
                a.extend([0x3443, (obj.format_modifier & 0xffff_ffff) as i32, 0x3444, (obj.format_modifier >> 32) as i32]);
            }
            a.push(0x3038); // EGL_NONE
            // SAFETY: attribute list is NONE-terminated; fds are valid while `f` lives.
            let img = unsafe { (egl.create)(egl.display, std::ptr::null_mut(), 0x3270 /* EGL_LINUX_DMA_BUF_EXT */, std::ptr::null_mut(), a.as_ptr()) };
            if img.is_null() {
                for i in images {
                    unsafe { (egl.destroy)(egl.display, i) };
                }
                bail!("eglCreateImageKHR failed for plane {i} (modifier {:#x}, fourcc {:#x})", obj.format_modifier, fourcc);
            }
            images.push(img);
            self.gl.active_texture(glow::TEXTURE0 + i as u32);
            self.gl.bind_texture(glow::TEXTURE_2D, Some(self.planes[i]));
            // SAFETY: GL context current, image valid.
            unsafe { (egl.target)(glow::TEXTURE_2D, img) };
        }
        // The plane textures now alias EGLImages; force a re-create next time CPU planes are used.
        self.plane_dims = [(0, 0); 3];
        self.plane_fmt_nv12 = None;
        Ok((images, 1))
    }

    /// Convert/upload one decoded frame and return the Slint image wrapping the RGBA target.
    pub fn prepare(&mut self, fr: &DecodedFrame) -> Result<slint::Image> {
        let (w, h, hold) = match &fr.payload {
            Payload::Yuv(f) => (f.width() as u32, f.height() as u32, None),
            Payload::Drm(f) => (f.width() as u32, f.height() as u32, Some(f.clone())),
            Payload::Rgba(_) => bail!("RGBA payload given to the GL presenter"),
        };
        self.ensure_target(w, h);
        // SAFETY: GL context is current; all objects were created on it.
        unsafe {
            // Save the state we touch.
            let gl = &self.gl;
            let prev_fbo = gl.get_parameter_i32(glow::DRAW_FRAMEBUFFER_BINDING);
            let prev_prog = gl.get_parameter_i32(glow::CURRENT_PROGRAM);
            let mut vp = [0i32; 4];
            gl.get_parameter_i32_slice(glow::VIEWPORT, &mut vp);
            let caps = [glow::BLEND, glow::SCISSOR_TEST, glow::DEPTH_TEST, glow::STENCIL_TEST, glow::CULL_FACE];
            let was: Vec<bool> = caps.iter().map(|&c| gl.is_enabled(c)).collect();
            for &c in &caps {
                gl.disable(c);
            }

            let mut images = Vec::new();
            let mode = match &fr.payload {
                Payload::Yuv(f) => self.upload_cpu(f)?,
                Payload::Drm(f) => {
                    let (imgs, m) = self.import_drm(f)?;
                    images = imgs;
                    m
                }
                Payload::Rgba(_) => unreachable!(),
            };
            let gl = &self.gl;
            gl.bind_framebuffer(glow::FRAMEBUFFER, Some(self.fbo));
            gl.viewport(0, 0, w as i32, h as i32);
            gl.use_program(Some(self.prog));
            for (i, n) in ["t0", "t1", "t2"].iter().enumerate() {
                gl.uniform_1_i32(gl.get_uniform_location(self.prog, n).as_ref(), i as i32);
                gl.active_texture(glow::TEXTURE0 + i as u32);
                gl.bind_texture(glow::TEXTURE_2D, Some(self.planes[i]));
            }
            gl.uniform_1_i32(gl.get_uniform_location(self.prog, "mode").as_ref(), mode);
            gl.uniform_2_f32(gl.get_uniform_location(self.prog, "size").as_ref(), w as f32, h as f32);
            gl.bind_vertex_array(Some(self.vao));
            gl.draw_arrays(glow::TRIANGLES, 0, 3);
            gl.bind_vertex_array(None);
            if self.sync || !images.is_empty() {
                // Include GPU completion in the timing; also required before destroying imports.
                gl.finish();
            }
            for i in 0..3 {
                gl.active_texture(glow::TEXTURE0 + i);
                gl.bind_texture(glow::TEXTURE_2D, None);
            }
            gl.active_texture(glow::TEXTURE0);
            if let Some(egl) = self.egl.as_ref() {
                for img in images {
                    (egl.destroy)(egl.display, img);
                }
            }
            // Restore state.
            gl.use_program(std::num::NonZeroU32::new(prev_prog as u32).map(glow::NativeProgram));
            gl.bind_framebuffer(glow::FRAMEBUFFER, std::num::NonZeroU32::new(prev_fbo as u32).map(glow::NativeFramebuffer));
            gl.viewport(vp[0], vp[1], vp[2], vp[3]);
            for (c, on) in caps.iter().zip(was) {
                if on {
                    gl.enable(*c);
                }
            }
            if let Some(h) = hold {
                self.hold.push_back(h);
                while self.hold.len() > 3 {
                    self.hold.pop_front();
                }
            }
            let id = NonZeroU32::new(self.target.0.get()).context("target texture id")?;
            Ok(slint::BorrowedOpenGLTextureBuilder::new_gl_2d_rgba_texture(id, [w, h].into()).build())
        }
    }

    pub fn finish_render(&self) {
        if self.sync {
            // SAFETY: GL context current in AfterRendering.
            unsafe { self.gl.finish() };
        }
    }
}
