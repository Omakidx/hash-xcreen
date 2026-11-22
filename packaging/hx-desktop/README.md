# hx-desktop packages

Builds the desktop app (`apps/hx-desktop`, binary `hx-desktop`) as a `.deb` per distro and as one AppImage. CI proves they build on every pull request that can change them (`.github/workflows/desktop-packages.yml`); the release workflow builds, signs, attests and attaches them to `v<version>` (`release/README.md`, section "Desktop packages").

App id: `io.github.omakidx.hashxcreen`. It names the desktop file, the metainfo, the icon files and (required, see "Needed from the app") the window's application id.

## Files

| File | What |
|---|---|
| `io.github.omakidx.hashxcreen.desktop` | Menu entry: `Name=hash-xcreen`, `Exec=hx-desktop`, `Categories=Network;RemoteAccess;`, `StartupWMClass=io.github.omakidx.hashxcreen` |
| `io.github.omakidx.hashxcreen.metainfo.xml.in` | AppStream metainfo template; the build fills `@VERSION@` and `@DATE@` (day of `SOURCE_DATE_EPOCH`). Validates with `appstreamcli validate --no-net` |
| `icons/hash-xcreen.svg`, `icons/png/hash-xcreen-<N>.png` | The brand mark of the mockups (accent square, hash sign), N = 16, 24, 32, 48, 64, 128, 256, 512. Installed as `<app id>.svg` / `<app id>.png` in `hicolor` |
| `copyright` | Debian copyright file (AGPL-3.0-or-later) |
| `common.sh` | Sourced: app id, version rules, `stage_payload` (the file layout both packages share) |
| `build-deb.sh` | `.deb` for one distro |
| `build-appimage.sh`, `fetch-appimage-tools.sh`, `appimage-tools.lock` | AppImage, and the pinned tools it needs |
| `smoke-run.sh`, `smoke-appimage.sh` | Headless run and AppImage checks used by CI and the release |

The icon is regenerated from the SVG with ImageMagick (`convert -background none -density <3N> hash-xcreen.svg -resize NxN -strip PNG32:hash-xcreen-N.png`); the PNGs are committed so a build needs no image tools.

## Build

```sh
cargo build --release --locked -p hx-desktop --bin hx-desktop

# .deb: run on the target distro (Depends are computed from this host's libraries)
packaging/hx-desktop/build-deb.sh --distro ubuntu-24.04 --bin target/release/hx-desktop \
    --out out/deb --source-date-epoch "$(git show -s --format=%ct HEAD)"

# AppImage: run on Ubuntu 24.04 (needs curl, to fetch the tools once)
packaging/hx-desktop/build-appimage.sh --bin target/release/hx-desktop \
    --out out/appimage --tools-dir ~/.cache/hx-appimage-tools --source-date-epoch "$(git show -s --format=%ct HEAD)"
```

`--version` defaults to the workspace version (release builds pass the gate's value). The version of the `.deb` has `-` replaced by `~`, so `0.2.0-rc.1` sorts before `0.2.0`. Both builds are reproducible: the same binary, version and `--source-date-epoch` give byte-identical files (CI builds each twice and compares). No sudo is needed. Needed on the build host: `dpkg-dev` and `binutils` (`.deb`), `curl` (AppImage tools).

## The `.deb`

Package `hx-desktop`, architecture `amd64`, built with `dpkg-deb --root-owner-group -Zxz`. Everything is `root:root`, no setuid files, no maintainer scripts (dpkg's triggers refresh the icon cache and the desktop database).

| Path | Mode |
|---|---|
| `/usr/bin/hx-desktop` (stripped) | 0755 |
| `/usr/share/applications/io.github.omakidx.hashxcreen.desktop` | 0644 |
| `/usr/share/icons/hicolor/{16,24,32,48,64,128,256,512}x<N>/apps/io.github.omakidx.hashxcreen.png`, `.../scalable/apps/io.github.omakidx.hashxcreen.svg` | 0644 |
| `/usr/share/metainfo/io.github.omakidx.hashxcreen.metainfo.xml` | 0644 |
| `/usr/share/doc/hx-desktop/copyright` | 0644 |

**Depends** is `dpkg-shlibdeps` over the binary (the libraries it links: `libavcodec`, `libavutil`, `libfontconfig1`, `libgcc-s1`, `libc6`) plus a fixed list of libraries the app opens with `dlopen`, which no tool can see: `libegl1, libgl1, libwayland-client0, libwayland-egl1, libx11-6, libx11-xcb1, libxcursor1, libxi6, libxkbcommon0, libxkbcommon-x11-0, libxrender1` (winit and Slint's renderer, checked with `strings` on the release binary; re-check when slint or winit is bumped). The FFmpeg packages are checked against the distro's expected sonames, as for `hx-session`. **Recommends**: a Secret Service provider (`gnome-keyring | keepassxc | kwalletmanager`; `keyring` stores the device key there and the app shows an error screen without one) and a font package.

| Distro | FFmpeg | Linked FFmpeg packages in Depends |
|---|---|---|
| Ubuntu 24.04 | 6.1 | `libavcodec60 (>= 7:6.0), libavutil58 (>= 7:6.0)` (computed, this host) |
| Debian 12 | 5.1 | `libavcodec59, libavutil57` (expected; computed in CI) |
| Debian 13 | 7.1 | `libavcodec61, libavutil59` (expected; computed in CI) |
| Ubuntu 26.04 | 8.0 | `libavcodec62, libavutil60`: **known gap, below** |

On Ubuntu 24.04 the whole Depends line is: `libavcodec60 (>= 7:6.0), libavutil58 (>= 7:6.0), libc6 (>= 2.39), libfontconfig1 (>= 2.12.6), libgcc-s1 (>= 4.2)` followed by the `dlopen` list. The other distros differ in the version constraints that `dpkg-shlibdeps` writes.

**Known gap: Ubuntu 26.04.** That release ships FFmpeg 8 and the workspace pins `ffmpeg-next` 7.1, which supports FFmpeg up to 7.1: the `cargo build` fails there (ffmpeg-sys-next's bindings want `libavcodec/avfft.h`, which FFmpeg 8 removed; seen in CI on PR #56). The pull-request workflow therefore has no 26.04 `.deb` cell, and the release keeps its 26.04 cell with `continue-on-error` and goes out without a 26.04 desktop package (a warning in the `assemble` job says so). The fix is a newer `ffmpeg-next`, or a distro-specific FFmpeg build; until then use the AppImage on 26.04, which bundles FFmpeg 6.1 and is smoke-tested on a clean 26.04. Add the cell back to `desktop-packages.yml` and remove `known_gap` from `release.yml` when it is closed.

## The AppImage

One file, `hx-desktop-<version>-x86_64.AppImage`, built on Ubuntu 24.04. It runs on any x86_64 distro whose glibc is 2.39 or newer (Ubuntu 24.04 and later, Debian 13, Fedora, Arch, openSUSE Tumbleweed). Debian 12 (glibc 2.36) cannot run it: use its `.deb`.

**Choice: FFmpeg is bundled.** The reasons:

- The `.deb` is per distro because FFmpeg's sonames differ on each (`libavcodec59` to `62`). An AppImage is one file for all of them, so it cannot link whichever FFmpeg the user has; relying on the system's would break on any distro that is not the build host's (Ubuntu 26.04's FFmpeg 8 is exactly the case the `.deb` cannot cover).
- The app needs FFmpeg only for software H.264 decoding, which any FFmpeg 6.1 does; there is no reason to chase the system's.
- Cost: the file is about 60 MB (81 libraries, FFmpeg's codec dependencies among them) and security fixes to FFmpeg arrive with a new hash-xcreen release, not with the distro's updates. The `.deb` is the choice for people who want the distro to patch FFmpeg.

How: `linuxdeploy` copies every library the binary links and everything those need into the AppDir (`usr/lib`) and sets `RUNPATH` to `$ORIGIN/../lib`, except its excludelist (glibc, OpenGL and EGL, `libdrm`, `libfontconfig`, X11 and similar libraries every desktop provides). `appimagetool` packs it with the pinned runtime into a zstd squashfs. The system must provide what the excludelist leaves out and what the app loads at run time: the graphics stack (EGL or GL, Wayland or X11 client libraries, `libxkbcommon`; any desktop has them), `libfontconfig`, `libharfbuzz` and `libfribidi` (also on the excludelist; every GTK desktop has them), and a Secret Service for saved servers.

The tools are downloaded only from their official GitHub releases, and only after their SHA-256 is verified against `appimage-tools.lock`; a mismatch deletes the file and fails the build:

| Tool | Version | SHA-256 |
|---|---|---|
| `linuxdeploy-x86_64.AppImage` | `1-alpha-20251107-1` | `c20cd71e3a4e3b80c3483cef793cda3f4e990aca14014d23c544ca3ce1270b4d` |
| `appimagetool-x86_64.AppImage` | `1.9.1` | `ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0` |
| `runtime-x86_64` (type2-runtime) | `20251108` | `2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d` |

Each digest was read from the release page, then the file was downloaded and hashed locally; both agreed. The runtime is pinned and passed with `--runtime-file`: `appimagetool` otherwise downloads whatever runtime is newest at build time. The tools run with `--appimage-extract-and-run` (no FUSE on CI runners). To bump a tool: change the lines of `appimage-tools.lock` and the table above together, and rebuild.

Using it: `chmod +x hx-desktop-*.AppImage && ./hx-desktop-*.AppImage`. Running an AppImage needs FUSE 3 (`fusermount3`) on the user's machine; without it, `APPIMAGE_EXTRACT_AND_RUN=1 ./hx-desktop-*.AppImage`. It carries no update information (no zsync): updating is downloading the next release. It is not integrated into the menu unless the user uses a tool such as AppImageLauncher.

## Smoke tests (CI and release)

| Check | Where |
|---|---|
| `dpkg-deb -I` and `-c`; the expected paths are there; all files `root/root`; no setuid or setgid file; the `.deb` of two builds is identical | `deb` job |
| `desktop-file-validate` and `appstreamcli validate --no-net` on the packaged files; `StartupWMClass` is the app id; the binary contains the app id | `deb` job, Ubuntu 24.04 |
| `apt-get install --no-install-recommends ./hx-desktop.deb` in a clean container of each distro; `ldd /usr/bin/hx-desktop` has no `not found`; then `smoke-run.sh` (`--version` prints `hx-desktop <version>`, `--demo` stays up 8 s under `xvfb-run` with the software renderer) | `deb-smoke` job |
| The AppImage of two builds is identical; `smoke-appimage.sh`: `--appimage-extract`, the binary, desktop file, metainfo, icons and `AppRun` are there, FFmpeg is bundled, `ldd` of the extracted binary resolves, then `smoke-run.sh` on the AppImage | `appimage` job |
| The AppImage on clean Ubuntu 24.04, Ubuntu 26.04 and Debian 13 containers that have only the display libraries a desktop provides (so FFmpeg must come from the bundle) | `appimage-smoke` job |

Not covered by any job: a real GPU or Wayland session, a Secret Service (`--demo` has none), and installing on a desktop with `dpkg`'s triggers (icon cache, `update-desktop-database`).

## Needed from the app (`apps/hx-desktop`, not changed here)

The window must set `slint::set_xdg_app_id("io.github.omakidx.hashxcreen")` before the first window is created (`hx-desktop` does not call it on the branch this was written against, so winit falls back to the executable name). Without it `StartupWMClass` and the Wayland app id do not match the desktop file: the launcher cannot group the window with its menu entry and shows the generic icon. The `deb` job fails until the binary contains the app id, on purpose.
