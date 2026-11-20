# Running the S1 benchmark on a GPU PC

This spike was developed on a GPU-less VM, so the hardware paths (VAAPI decode, DMA-BUF import)
have **never been run**. This document is everything needed to run them on a Linux PC with an
Intel or AMD GPU and send the numbers back. Expect about 15 minutes plus the first build.

Target: Ubuntu 24.04 (other distros work, package names differ), a real desktop session,
**Wayland recommended** (the Ubuntu 24.04 default). On X11 Slint creates a GLX context, so path b
cannot import DMA-BUFs (see "Session type" below).

## 1. Install packages

```bash
sudo apt update
sudo apt install -y \
  build-essential pkg-config clang libclang-dev curl git \
  ffmpeg libavcodec-dev libavformat-dev libavutil-dev libswscale-dev libswresample-dev \
  libavdevice-dev libavfilter-dev libx264-dev \
  libva-dev vainfo \
  libxkbcommon-dev libxkbcommon-x11-dev libfontconfig1-dev libfreetype-dev \
  libx11-dev libxcb1-dev libwayland-dev \
  libegl1 libgl1 libgles2 libvulkan1 mesa-vulkan-drivers mesa-utils-bin vulkan-tools \
  python3
```

VAAPI driver (pick what matches the GPU; `lspci -k | grep -A3 VGA` shows it):

| GPU | Package |
|---|---|
| Intel, Broadwell (2014) or newer, incl. Arc | `intel-media-va-driver-non-free` (or `intel-media-va-driver`) |
| Intel older than Broadwell | `i965-va-driver` |
| AMD (radeonsi) | `mesa-va-drivers` (installed with Mesa by default) |
| NVIDIA | not supported for this spike (needs the community `nvidia-vaapi-driver`; skip) |

Rust: 1.95 or newer (Slint 1.19 needs it). `curl https://sh.rustup.rs -sSf | sh` then
`. "$HOME/.cargo/env"`. The repository pins a toolchain in `rust-toolchain.toml`; rustup picks it up
automatically when you are inside the repo.

## 2. Check that VAAPI works before building anything

```bash
ls -l /dev/dri/            # must contain renderD128 (or similar); your user must be in the "render" group
vainfo                     # must list VAProfileH264Main / VAProfileH264High with VAEntrypointVLD
```

If `vainfo` fails: install the driver above, check `groups` includes `render` (`sudo usermod -aG render $USER`,
then log out and in), and try `LIBVA_DRIVER_NAME=iHD vainfo` (Intel) or `LIBVA_DRIVER_NAME=radeonsi vainfo` (AMD).

Optional FFmpeg-level check (independent of this spike's code):

```bash
cd spikes/s1-slint-video && ./gen-clip.sh
ffmpeg -hwaccel vaapi -hwaccel_device /dev/dri/renderD128 -hwaccel_output_format vaapi \
       -i clip-1080p60.mp4 -f null - -benchmark   # should run far faster than 1x real time
```

## 3. Run the whole matrix (recommended)

```bash
cd spikes/s1-slint-video
./run-gpu-bench.sh                # builds, generates the clip, runs 11 cases of 20 s each (~6 min)
```

Options: `--secs 30`, `--window 2560x1440` (use your native resolution), `--no-build`, `--skip-clip`.

While it runs: do not touch the mouse or keyboard, keep the machine on AC power, close other
heavy applications. Windows will open and close; that is expected. The script prints a one-line
verdict per case and writes everything to `results/gpu-<host>-<timestamp>/` and
`results/gpu-<host>-<timestamp>.tar.gz`.

### Sending results back

Send the `.tar.gz` (it contains the per-case JSON, `system-info.txt` with `vainfo`, GPU,
`eglinfo` and Vulkan details, and `run.log`). Nothing in it identifies you beyond the hostname and
`lspci` output; open `system-info.txt` and delete any line you do not want to share before sending.
Also state: GPU model, driver (from `system-info.txt`), monitor refresh rate, Wayland or X11.

## 4. What each case is

| Case | What it measures |
|---|---|
| `c-sw` | CPU baseline: software decode, swscale to RGBA, `SharedPixelBuffer` per frame |
| `c-vaapi-download` | VAAPI decode, download to system memory, swscale, `SharedPixelBuffer` |
| `a-vaapi-dmabuf` | **Target path a**: VAAPI surface -> DMA-BUF -> Vulkan image -> wgpu NV12 texture -> YUV pass -> `slint::Image` |
| `a-vaapi-download` | wgpu presenter, but frames downloaded to CPU first (isolates wgpu from the import) |
| `b-vaapi-dmabuf` | **Target path b**: VAAPI surface -> DMA-BUF -> EGLImage -> GL texture -> YUV pass -> `BorrowedOpenGLTexture` |
| `b-vaapi-download` | GL presenter with CPU-downloaded frames (isolates GL from the import) |
| `b-vaapi-dmabuf-gl33` | Path b with a desktop OpenGL 3.3 context instead of GLES 3.0 |
| `*-sync` | Same, but waits for the GPU to finish after our pass and after Slint's render (timings include GPU work) |
| `*-no-overlay` | Same, without the stats overlay (pure video cost) |

A case that cannot run prints `UNAVAILABLE: <reason>` (for example "no DRM render node",
"Slint's OpenGL context is not an EGL context", or a Vulkan extension that is missing). That is a
useful result: send it back too.

## 5. Running a single case by hand

```bash
cargo build --release
./target/release/s1-slint-video --detect                         # VAAPI / session capability probe
./target/release/s1-slint-video --path b --decode vaapi          # interactive, with overlay
./target/release/s1-slint-video --path a --decode vaapi --bench 20 --json-out /tmp/a.json
```

Interactive keys: click "Probe click" to measure click-to-render latency; press `o` to hide/show the overlay.

Flags: `--path a|b|c`, `--decode auto|vaapi|software`, `--no-dmabuf`, `--sync`, `--gl es3|gl33`,
`--window WxH`, `--bench SECS`, `--warmup SECS`, `--no-overlay`, `--auto-probe`, `--unpaced`.

## 6. Reading the JSON

* `representative_of_gpu_hardware`: `true` only if the GL/wgpu renderer is not a software rasteriser
  (llvmpipe, lavapipe, softpipe). If it is `false` the numbers are not GPU numbers.
* `environment.zero_copy_dmabuf`: `true` means the frame really went VAAPI -> DMA-BUF -> GPU texture
  with no CPU copy. If it is `false` for an `a-vaapi-dmabuf` or `b-vaapi-dmabuf` case, the case fell
  back or failed; read `environment.presenter` and `status`.
* `decode_to_render_ms`: decode finished -> end of Slint's render of that frame (AfterRendering).
  Swap and scanout latency are not observable from the rendering notifier, so add up to one refresh
  interval for true photon latency. The S1 limit is 8 ms at p95.
* `present_interval_ms`: spacing between consecutive new video frames being rendered. On a 60 Hz
  display the p50 should be 16.7 ms with a small standard deviation. A 59.94 Hz display against a
  60.00 fps source produces an occasional dropped frame; that is real and expected (see
  `video.frames_dropped`).
* `cpu.process_cores`: CPU cores busy (user + system) over the measured window, with per-thread
  breakdown in `cpu.per_thread_cores` (`decoder` is the decode thread).
* `s1_criteria`: PASS / FAIL per S1 criterion against the thresholds listed next to it.

## 7. Session type (Wayland vs X11)

Slint's winit backend creates a **GLX** context on X11 and an **EGL** context on Wayland. DMA-BUF
import into OpenGL (path b) needs EGL, so on X11 `b-vaapi-dmabuf` will report "Slint's OpenGL
context is not an EGL context". Run from a Wayland session for the real answer. Path a (Vulkan)
is independent of GLX/EGL but is still best measured under Wayland. If you only have X11, still
run the matrix and send it back; additionally run it once under Wayland if possible.

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `error: package libavcodec was not found` | `sudo apt install libavcodec-dev ...` (list above) |
| `failed to run custom build command for ffmpeg-sys-next` / bindgen errors | `sudo apt install clang libclang-dev` |
| `VAAPI device creation failed ... Permission denied` | add yourself to the `render` group, re-login |
| `vaInitialize failed` | wrong or missing VAAPI driver; see table in section 1, try `LIBVA_DRIVER_NAME` |
| Windows do not appear / GL errors on Wayland | try `SLINT_BACKEND=winit ./target/release/s1-slint-video ...`; send `*.stderr` |
| Hybrid laptop (iGPU + dGPU) | run from the iGPU session, or set `DRI_PRIME=0`; state which GPU drove the display |
