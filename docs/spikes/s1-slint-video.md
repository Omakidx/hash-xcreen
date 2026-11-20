# Spike S1: Slint video presentation

Status: **built and run on a GPU-less VM; the GPU measurement is still to be done.**
Branch: `spike/s1-slint-video`. Code: `spikes/s1-slint-video/`. Date: 2026-11-20.

## 1. Goal

Decide how the desktop client (Phase 1G) puts decoded 1080p60 H.264 on screen inside a Slint window
with hardware decode and no CPU copy per frame. Pass criteria from `docs/execution-phase.md`:

1. sustained 60 fps with even frame pacing;
2. decode-to-present of 8 ms or less;
3. the UI stays responsive while video plays.

Paths compared:

| Path | Route |
|---|---|
| **a** | VAAPI surface -> DMA-BUF -> Vulkan image -> `wgpu::Texture` (NV12) -> YUV-to-RGB pass -> `slint::Image::try_from(wgpu::Texture)` (Slint's unstable wgpu integration) |
| **b** | VAAPI surface -> DRM PRIME / DMA-BUF -> `EGLImage` (`EGL_EXT_image_dma_buf_import`) -> GL textures -> YUV-to-RGB pass into an RGBA texture -> `BorrowedOpenGLTextureBuilder` on Slint's femtovg OpenGL renderer |
| **c** | decode (VAAPI + download, or software) -> swscale to RGBA -> `SharedPixelBuffer` -> `slint::Image::from_rgba8` every frame (fallback) |

## 2. What this document can and cannot say

This machine is an Ubuntu 24.04 VM with an emulated display: no render node, no VAAPI, software
GL (Mesa llvmpipe) and software Vulkan (lavapipe). **Every number below is from software rendering
on a machine that other agents were loading heavily (load average 19 to 25 on 16 cores). None of
it is representative of GPU hardware.** The numbers prove that the code paths run and show the
CPU-side cost of each stage; they say nothing about whether the S1 criteria are met on a real
GPU. The zero-copy hardware routes (VAAPI decode, DMA-BUF export, EGL import, Vulkan import) are
**implemented but never executed**; they compile and are guarded by detection, and the GPU run
(`spikes/s1-slint-video/RUN_ON_GPU.md`) is the first time they will run.

## 3. Setup

| Item | Value |
|---|---|
| Slint | 1.19.0 (`=1.19.0`), Rust 1.95 or newer required, edition 2024 |
| Slint features | `backend-winit` (+ `-x11`, `-wayland`), `renderer-femtovg` (OpenGL), `renderer-femtovg-wgpu`, `unstable-wgpu-30`, `compat-1-2`; default features off |
| Slint license | GPL-3.0-only, or royalty-free, or commercial; GPLv3 is compatible with this repository's AGPL-3.0-or-later |
| wgpu | 30.0.2 (through `slint::wgpu_30`; Slint also offers `unstable-wgpu-29`) |
| FFmpeg | system 6.1.1 (libavcodec 60.31), via `ffmpeg-next` 7.1 and `ffmpeg-sys-next` 7.1 |
| Other crates | `glow` 0.16 (GL calls), `khronos-egl` 6 (dynamic libEGL), `ash` 0.38 (Vulkan, matches wgpu-hal 30), `clap`, `serde_json` |
| Clip | `gen-clip.sh`: 1920x1080, 60 fps, 30 s, H.264 Main, no B-frames, `-tune zerolatency`, keyint 120, testsrc2 plus two scrolling text bands and a clock; ~58 MB, git-ignored |
| Machine | Ubuntu 24.04 VM, 16 cores, 62 GB, `/dev/dri/card0` only (no render node), Mesa 25.2.8, llvmpipe (LLVM 20.1.2) and lavapipe |
| Display for runs | private Xvfb 1920x1080, GLX software rendering, X11 |
| Reference (decode only) | `ffmpeg -threads 1 -i clip -f null -`: 14.4 s CPU for 1800 frames, i.e. about 8 ms CPU per frame, about 0.5 core for 1080p60 software decode of this clip |

## 4. What was built

One standalone crate (`[workspace]` table, not part of the root workspace), about 2,300 lines (Rust plus Slint markup).

* `src/decode.rs`: libavcodec on a dedicated thread, paced to a 60 fps wall clock, looping the
  clip. VAAPI is attempted when `--decode auto|vaapi` and the reason for failure is reported
  (for example "no DRM render node"). Output is a latest-frame-wins mailbox of CPU RGBA (path c), CPU
  planes (software or download) or a VAAPI surface mapped to DRM PRIME with `av_hwframe_map`.
* `src/path_gl.rs` (path b): glow-based presenter. Creates its own GL objects in Slint's context
  from the rendering notifier, saves and restores the GL state it touches, renders a YUV (I420 or
  NV12, BT.709 limited range) pass into an RGBA8 texture and returns
  `BorrowedOpenGLTextureBuilder::new_gl_2d_rgba_texture`. DMA-BUF frames are imported per plane
  (R8 and GR88 fourcc, with modifiers) through `eglCreateImageKHR` and
  `glEGLImageTargetTexture2DOES`; CPU frames use `glTexSubImage2D`.
* `src/path_wgpu.rs` and `src/vk_import.rs` (path a): same YUV pass in WGSL, a ring of three
  `Rgba8Unorm` targets wrapped with `slint::Image::try_from`. For DMA-BUF, `vk_import` builds a wgpu
  device through wgpu-hal with `VK_EXT_external_memory_dma_buf`, `VK_EXT_image_drm_format_modifier`
  and friends enabled, hands it to Slint with `WGPUConfiguration::Manual`, and imports each frame
  as a `G8_B8R8_2PLANE_420_UNORM` `VkImage` wrapped as a wgpu NV12 texture (plane views feed the shader).
* Path c lives in `decode.rs` (swscale into the `SharedPixelBuffer`) and the event-loop handler in `main.rs`.
* `ui/app.slint`: video `Image`, stats overlay (fps, interval histogram, stage timings, dropped
  count) and a responsiveness probe: a button plus an animation-clock marker and a click-to-render latency readout.
* `--bench N`: warm-up, then N seconds measured, then one JSON document (percentiles p50/p95/p99,
  interval histogram and standard deviation, dropped frames, process and per-thread CPU, load
  average at start and end, a `representative_of_gpu_hardware` flag, and a verdict per S1 criterion).
  In bench mode a timer injects synthetic pointer clicks on the probe button every 250 ms.
* Scripts: `gen-clip.sh`, `run-local-bench.sh` (this VM), `run-gpu-bench.sh` (GPU PC, 11 cases,
  packs a tarball), `RUN_ON_GPU.md`.

### Timestamps

`decode_done` is taken in the decoder thread. `handed` is taken right after the Slint image
property is set (inside `BeforeRendering` for paths a and b, on the event loop for path c).
`rendered` is taken in `AfterRendering` of the first render that follows. The metrics are:

* `decode_to_render_ms` = rendered - decode_done (the decode-to-present proxy);
* `present_interval_ms` = time between consecutive new video frames being rendered (pacing);
* `frames_dropped` = decoded frames replaced in the mailbox before being rendered;
* `render_ms` = `BeforeRendering` to `AfterRendering`; `prepare_upload_ms` = our own upload,
  import and convert code; `event_to_render_ms` = synthetic click to next render; `event_loop_lag_ms` = lateness of a 5 ms timer.

Limit: the rendering notifier has no "presented" callback. `AfterRendering` runs before the buffer
swap, so swap, compositor and scanout time are not measured. Without `--sync` the GL and wgpu
timings also exclude GPU execution time (commands are queued, not completed); `--sync` waits for our pass
(and `glFinish` after Slint's render for GL) so the GPU work is included at the cost of a pipeline stall.

## 5. Numbers from this machine (software rendering, NOT representative of GPU hardware)

All rows: software H.264 decode (4 slice threads), llvmpipe or lavapipe rendering, 15 s measured
after 3 s warm-up, Xvfb. Load average 19 to 21 at the start of each run on 16 cores. Raw JSON in
`spikes/s1-slint-video/results/vm/`.

| Case | Presented fps | Dropped | Decode p50 / p95 (ms) | Our stage p50 (ms) | Slint render p50 (ms) | Decode-to-render p50 / p95 (ms) | Interval p50 / p95, sd (ms) | Click-to-render p50 / p95 (ms) | Process CPU (cores) |
|---|---|---|---|---|---|---|---|---|---|
| c, 1080p window, overlay | 18.2 | 64% | 11.5 / 23.4 | 5.3 (swscale) | 39.9 | 50.6 / 77.7 | 54.2 / 79.5, 13.7 | 43.6 / 76.6 | 3.0 |
| c, 720p window, overlay | 30.8 | 50% | 9.6 / 17.6 | 4.3 (swscale) | 20.9 | 30.2 / 47.9 | 31.5 / 46.2, 8.2 | 23.2 / 38.1 | 3.0 |
| c, 1080p, no overlay | 29.6 | 37% | 13.4 / 27.2 | 5.0 (swscale) | 9.5 | 23.8 / 42.3 | 31.9 / 50.4, 9.3 | not measured | 4.0 |
| b, 1080p window, overlay | 21.8 | 64% | 12.6 / 23.3 | 8.4 (CPU upload + YUV pass) | 23.3 | 31.2 / 47.8 | 43.9 / 62.9, 9.6 | 27.3 / 35.1 | 4.6 |
| b, 720p window, overlay | 24.5 | 59% | 12.1 / 23.9 | 6.6 | 22.0 | 30.0 / 52.2 | 38.5 / 64.8, 11.4 | 25.5 / 39.1 | 4.1 |
| b, 1080p, no overlay | 26.3 | 56% | 12.0 / 22.6 | 7.2 | 19.6 | 26.8 / 44.5 | 36.4 / 54.0, 9.3 | not measured | 5.2 |
| a, 1080p window, overlay | 14.0 | 77% | 11.7 / 23.3 | 2.3 (CPU upload + YUV pass, p95 29.9) | 38.2 | 46.1 / 70.9 | 69.0 / 113.0, 23.0 | 48.9 / 87.5 | 3.6 |
| a, 720p window, overlay | 18.5 | 69% | 11.2 / 21.2 | 4.7 | 32.3 | 39.7 / 60.6 | 51.1 / 84.2, 17.0 | 38.0 / 51.5 | 3.6 |
| a, 1080p, no overlay | 15.1 | 75% | 12.4 / 26.7 | 8.2 | 39.0 | 45.5 / 78.4 | 59.1 / 121.7, 27.8 | not measured | 3.9 |

Rendering: GL path `OpenGL ES 3.2 Mesa 25.2.8 / llvmpipe (LLVM 20.1.2, 256 bits)`; wgpu path
`llvmpipe (LLVM 20.1.2) (Cpu, Vulkan)` (lavapipe).

How to read this table:

* The decoder itself kept up (about 60 decoded fps) in all runs except path c, where swscale runs
  in the decoder thread and limits it to 47 to 62 fps under this load.
* What failed is **software rendering of the UI** (llvmpipe at 1080p, shared with the other
  workloads on the machine): Slint's render alone takes 10 to 40 ms, so presented fps is 14 to 31.
  A real GPU removes this term. The comparison between paths here is therefore a comparison of
  software rasterisers (GL llvmpipe versus lavapipe through wgpu), not of the presentation routes.
* Path a was slower than b on software rendering because femtovg-wgpu on lavapipe is slower than
  femtovg-GL on llvmpipe. This must not be generalised to GPUs.
* The overlay costs a lot under software rendering (path c: 9.5 ms to 39.9 ms render) because it
  forces a full-window repaint with translucency; on a GPU it should be negligible, and the GPU matrix includes `no-overlay` cases to check.
* Click-to-render latencies track the render time (the UI thread is saturated), not Slint's input path.
* CPU cost of stages that do not depend on rendering, useful for the CPU fallback (path c, from
  the runs above and the ffmpeg reference): software decode about 8 ms CPU per frame (about 0.5
  core at 60 fps), swscale YUV420P to RGBA at 1080p about 4 to 5 ms per frame (about 0.3 core at 60 fps).
  The upload of 8.3 MB per frame (about 500 MB/s) is paid inside Slint's render and cannot be
  separated from software rasterisation here.

## 6. S1 criteria

| Criterion | Result | Reason |
|---|---|---|
| Sustained 60 fps with even frame pacing | **UNVERIFIED** | Software rendering reached 14 to 31 fps; the limit is llvmpipe/lavapipe on a loaded VM, not the presentation route. Needs a GPU run. |
| Decode-to-present of 8 ms or less | **UNVERIFIED** | Software numbers (24 to 51 ms p50) are meaningless for GPU. Also see the definition caveat in section 8. |
| UI stays responsive during playback | **UNVERIFIED** | Probe works (synthetic click to render, timer lag, animation marker), but on software rendering the UI thread is saturated. Needs a GPU run. |
| Path a/b zero-copy from VAAPI (no CPU copy) | **UNVERIFIED** | Code written and compiled, never executed: no render node, no VAAPI here. `--decode vaapi` reports "no DRM render node ... VAAPI cannot be used" and exits with code 2 and a JSON `unavailable` record. |
| Every path runs or fails with a clear reason | **PASS** | c, b (GL, CPU upload) and a (wgpu on lavapipe) run end to end with correct colours (visually checked from Xvfb captures). VAAPI, DMA-BUF-on-GLX and CPU-adapter refusal each report a specific reason. |

## 7. Preliminary decision

Provisional, based on API maturity, risk and the facts found while building, **not on
performance data** (there is none for GPUs yet):

1. **Primary Linux presentation path: b** (VAAPI -> DMA-BUF -> EGLImage -> GL texture -> Slint
   `BorrowedOpenGLTexture` on the femtovg OpenGL renderer), run under Wayland/EGL.
   Reasons: the Slint API is stable (`BorrowedOpenGLTextureBuilder`, available since 1.2, no
   unstable feature flag); the EGL DMA-BUF import is the well-trodden route used by mpv and
   FFmpeg-based players; our code is small (about 370 lines) and needs no custom device creation.
2. **Always-available fallback: c** (CPU `SharedPixelBuffer`). Costs about 0.5 core for software
   decode plus about 0.3 core for swscale at 1080p60 (measured above), plus the per-frame texture
   upload; this is a plausible floor for machines without VAAPI.
3. **Path a is the alternative to keep open**, not the default: it depends on an unstable Slint
   feature tied to a wgpu major version (`unstable-wgpu-29` and `-30` exist side by side), needs
   a hand-built wgpu-hal Vulkan device and about 230 lines of mostly unsafe DMA-BUF import, and Slint
   accepts only `Rgba8Unorm`/`Rgba8UnormSrgb` render-target textures, so the YUV pass is needed
   here too. Its advantage is portability beyond Linux/OpenGL (Vulkan, later Metal and D3D12) and independence from the GLX/EGL question.
4. The architecture text ("through Slint's wgpu integration") should not be treated as decided
   until the GPU run is back; b first is the lower-risk reading.

### What the GPU run must confirm

* `b-vaapi-dmabuf`: `zero_copy_dmabuf: true`, 60 fps, interval sd under 1 ms on a 60 Hz display,
  decode-to-render p95 at or under 8 ms, CPU well under 1 core, click-to-render p95 under about 33 ms.
* `a-vaapi-dmabuf`: that the Vulkan import works at all (never run), and its numbers versus b.
  If it fails on both Intel and AMD, path a is out for now.
* `*-download` cases: how much of the cost is the import versus the presenter, and the cost of
  the CPU-copy alternative on real hardware.
* `c-vaapi-download` and `c-sw`: whether the fallback is good enough on a GPU PC (and what it costs in CPU).
* `*-sync` cases: GPU execution time of our pass and Slint's frame.
* `no-overlay` cases: the real cost of the overlay on a GPU.
* Wayland versus X11: path b needs EGL (see below). Run under Wayland first; if only X11 is available, the b dma-buf case is expected to report the GLX limitation.
* Intel versus AMD if possible, and the hybrid-GPU case on laptops.

## 8. API, stability and design risks

* **Unstable Slint feature.** Path a needs `unstable-wgpu-30`: documented as "may be removed or
  changed in future minor releases, as new major WGPU releases become available". Each wgpu
  major means a new feature (`unstable-wgpu-29` and `-30` coexist in 1.19). Pinning `=1.19.0` was necessary.
* **GLX versus EGL on X11 (path b).** Slint's winit backend asks glutin for `FallbackEgl`, which
  creates a **GLX** context on X11 and EGL on Wayland. DMA-BUF import into OpenGL needs EGL.
  Confirmed here: the presenter detects "Slint's OpenGL context is not an EGL context (it is GLX on
  X11)" and refuses DMA-BUF frames. Options for the real client: require Wayland for the zero-copy
  path and use c on X11; or implement a custom Slint `Platform` that creates its own EGL
  context (Slint exports `slint::platform::femtovg_renderer::{FemtoVGRenderer, OpenGLInterface}` for this; more work, not prototyped).
  This matters because XFCE-like Linux desktops often run X11.
* **GL context flavour.** Slint requests OpenGL ES 2.0 by default. The presenter needs ES 3.0 or
  GL 3.3 (R8/RG8 textures, `UNPACK_ROW_LENGTH`, `gl_VertexID`); the spike requests it through
  `BackendSelector::require_opengl_es_with_version(3, 0)` (`--gl gl33` for desktop GL). This ties
  the client to a backend selector call before window creation.
* **Borrowed textures are RGBA `GL_TEXTURE_2D` only** and the API is `unsafe`; there is no YUV or
  external-OES import, so a colour-conversion pass is unavoidable in both a and b. It is cheap on a GPU, but it is our code to maintain (BT.709 limited range assumed; colour space and range need to come from the stream metadata in production).
* **wgpu device ownership.** Slint's automatic wgpu setup cannot enable the Vulkan DMA-BUF
  extensions; zero-copy requires `WGPUConfiguration::Manual` with a device built through wgpu-hal.
  Slint refuses CPU adapters unless `SLINT_WGPU_CPU=1`. The imported image is declared to wgpu as
  already shader-readable (no UNDEFINED to SHADER_READ barrier, no queue-family-foreign acquire): fine in practice on Mesa, not spec-conformant.
* **Synchronisation and lifetime.** VAAPI surfaces and their DMA-BUF fds are kept alive for three
  frames after use; the GL path calls `glFinish` before destroying the `EGLImage`s. A production
  client should use explicit fences (EGL sync / Vulkan semaphores or dma-buf fences) instead of `glFinish`.
* **Decode-to-present definition.** The measured value is decode-complete to the end of Slint's render
  (`AfterRendering`). With vsync on a 60 Hz display a frame waits on average half a refresh
  (8.3 ms) before scanout, so a literal "decode to photon of 8 ms or less" cannot be met at 60 Hz regardless of the path. The criterion should be
  restated as decode-complete to render-complete (what we measure), or measured with an external camera or photodiode, before the GPU numbers are judged.
* **Hardware decode latency.** VAAPI decode time per frame is measured as send-packet to
  receive-frame plus `av_hwframe_map` (which syncs the surface). Driver queueing may add latency not visible here.
* **FFmpeg version.** Built against system FFmpeg 6.1 with `ffmpeg-next` 7.1 (works). The
  tech-stack decision "libavcodec" should pin which FFmpeg ABI the packaged client links
  (the newest `ffmpeg-next` 9.x targets newer FFmpeg).
* **Build weight.** The spike binary pulls about 560 crates (wgpu, naga, Slint); a release build
  from cold took several minutes on a loaded machine.

## 9. Follow-ups

1. Run `./run-gpu-bench.sh` on an Intel or AMD GPU PC (Wayland), send back the tarball, and fill
   in section 5 with GPU numbers (new section; keep these software numbers labelled as they are).
2. If path b is confirmed: decide the X11 story (Wayland-only zero-copy, custom EGL platform, or
   fall back to c); prototype the custom EGL `Platform` if X11 matters.
3. If path a is still of interest: replace `glFinish`-style syncing and the layout assumption with
   proper barriers; evaluate wgpu's own external-memory support when it lands.
4. Production presenter requirements to carry into Phase 1G: colour space and range from the
   stream, explicit fences, frame pacing against the display's actual refresh (a 59.94 Hz display
   against 60 fps content drops a frame every 17 s unless the client adapts), resize handling, and a
   software fallback chosen at runtime (the detection code is reusable).
5. Update `docs/architecture.md` §6.5 and `docs/tech-stack.md` after the GPU run with the chosen
   path, the Slint features and the pinned FFmpeg version (the Slint license note: GPL-3.0 option).
6. Optional: measure with an external latency probe (camera or photodiode) to settle the decode-to-present definition.
