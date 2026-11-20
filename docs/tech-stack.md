# Tech stack

Every language, library, tool and external service hash-xcreen uses, and why. Items marked **(provisional)** were chosen in the Phase 0 spikes but still need the follow-up run listed in [execution-phase.md](execution-phase.md) §0.4 before we depend on them.

## Languages

| Language | Where | Why |
|---|---|---|
| Rust (stable, 2024 edition) | Everything: agent, session, clients, installer logic | Memory safety for internet-facing and root code, predictable performance for the media path, one language end to end |
| TypeScript | Thin shell of the web client (WebCodecs, WebTransport, canvas, input APIs) | Browser APIs not reachable cleanly from WASM; kept small |
| POSIX `sh` | `install.sh` bootstrap only | Runs on any host before Rust binaries exist; does preflight, download and signature check, then hands off |
| Slint markup (`.slint`) | Desktop client UI | Declarative UI compiled into the Rust binary |

## Server

| Area | Choice | Why |
|---|---|---|
| Desktop isolation | **Incus** system containers (unprivileged) | Real distro images with systemd, built-in snapshots and export, image server, VMs available later |
| Storage | **ZFS** or **btrfs** pool (spare disk or loop file) | Instant copy-on-write snapshots for consistent backups |
| Desktop (v1) | **XFCE** on headless **Xorg** with the `dummy` driver | Lightest desktop, simplest and most efficient capture path |
| Audio in the desktop | **PipeWire** | Standard on current Ubuntu/Debian; capture for streaming |
| Docker (opt-in) | Docker Engine from Docker's apt repository, Incus `security.nesting` **(provisional: failing on Incus 6.0, see architecture §4.3)** | Official packages |
| Host tuning | `/etc/sysctl.d/90-hx-incus.conf` (inotify limits, `vm.max_map_count`) | All unprivileged containers share one inotify budget; the default (128) blocks a second desktop |
| Provisioning recipes | TOML fragments (`include`, `[vars]`, add-ons, `post` stage) applied by `hx-provision` | Same recipe drives prebuilt images and building on the server |
| Process management | **systemd** units with sandboxing, `systemd-creds` for secrets | Hardening and TPM-sealed secrets without extra software |
| Firewall | ufw or nftables, whichever the host uses | Avoid fighting the host's existing setup |
| Async runtime | **tokio** (networking only) | Standard for quinn and HTTP; kept out of the media hot path |
| Incus API client | Incus REST API over its unix socket (`hyper` + `serde`) | No CLI scraping; typed requests from `hx-privd` |

## Streaming

| Area | Choice | Why |
|---|---|---|
| X11 capture | **XDamage**, **XShm**, **XFixes** (cursor), **RandR** (resize), via `x11rb` | Change-driven, copy-free capture; pure-Rust X11 bindings |
| Input injection | **XTest** (X11); **libei** later for Wayland desktops | Standard injection APIs per display stack |
| Colour conversion | `yuvutils-rs` (SIMD) | Fast RGB→YUV without a C dependency |
| Codec framework | **libavcodec** (FFmpeg) via `ffmpeg-next` / `ffmpeg-sys-next` (7.1 against Ubuntu 24.04's FFmpeg 6.1; newer FFmpeg needs a newer `ffmpeg-next`) | One API for every encoder and decoder, software and hardware |
| Software encoder | **x264** (`ultrafast`, `zerolatency`, `crf=23`, one-frame VBV, bitrate ladder ≤ 20 Mbps, sliced threads, intra refresh) | Best low-latency software H.264 (4–8 ms encode in S2); GPL is fine because we are AGPL |
| Media pipeline threads | Dedicated OS threads joined by bounded `crossbeam-channel` queues, pooled buffers | Keeps the hot path off the async runtime (S2) |
| Later encoders | **SVT-AV1** (real-time presets), **VAAPI**, **NVENC** | Screen-content AV1; hardware encoding when a GPU exists |
| Audio codec | **Opus** (10 ms frames, in-band FEC) via `audiopus` | Low latency, loss-tolerant |
| Client hardware decode | libavcodec with **VAAPI** (Linux) | Hardware decode on Intel/AMD; NVIDIA through VAAPI drivers or NVDEC later |

## Networking and protocol

| Area | Choice | Why |
|---|---|---|
| Native transport | **QUIC** via `quinn`, BBR congestion control | Independent streams (no head-of-line blocking), datagrams, built-in TLS 1.3 |
| Browser transport | **WebTransport** over HTTP/3 via `wtransport` running on our own quinn endpoint, dispatched by ALPN (`h3` / `hx/1`); `h3` + `h3-webtransport` as the fallback library | Same QUIC and the same port for both clients (proven in S5) |
| Fallback | WebSocket over TLS (`tokio-tungstenite`) on the same port number over TCP | Networks that block UDP, and Safari until it is tested |
| TLS | `rustls` | Pure Rust, no OpenSSL; supports pinned raw keys |
| Control messages | **Protocol Buffers** via `prost` | Schema evolution, language-neutral for future mobile clients |
| Media framing | Fixed little-endian binary header | No parsing cost on the hot path |
| Web certificates | Let's Encrypt via ACME (`instant-acme`); short-lived IP-address certificates when there is no domain **(provisional: not yet issued for real)**; fallback: self-signed ECDSA P-256 certificate from `rcgen`, pinned with `serverCertificateHashes` | Real HTTPS for the browser without a domain |

## Security

| Area | Choice | Why |
|---|---|---|
| Pairing | **SPAKE2** (`spake2` crate) | Safe with both long tokens and short human codes; resists man-in-the-middle |
| Keys | Ed25519 identities (`ed25519-dalek`), pinned in TLS | No certificate authority needed for the native client |
| PIN hashing | **Argon2id** (`argon2`) | Memory-hard; server-side verification with lockout |
| Linux password | System shadow hash (yescrypt) | Standard login, sudo and lock screen |
| Web login | **WebAuthn passkeys** (`webauthn-rs`) | Phishing-resistant browser login |
| Client key storage | Secret Service / libsecret via `keyring` | System keyring on Linux |
| Syscall filtering | seccomp allowlist (`seccompiler`) plus systemd hardening | Contain `hx-gatewayd` if exploited |
| Fuzzing | `cargo-fuzz` (libFuzzer); OSS-Fuzz later | Pre-auth and container-supplied parsers |

## Backups

| Area | Choice | Why |
|---|---|---|
| Backup engine | **`rustic_core`** (Rust implementation of the restic format), zstd level 3; versions pinned because its API is still unstable | Content-defined chunking, deduplication, compression, authenticated encryption; restic-compatible format; full round trip proven locally in S4 |
| Google Drive access | **OpenDAL** `gdrive` service through `rustic_backend`, with only that service enabled (all services made a 43 MB binary), wrapped by hash-xcreen for 429/403 rate limits and the daily cap; rclone backend as fallback **(provisional: untested against Drive)** | Native Rust Drive backend for rustic |
| Google auth | OAuth 2.0 for installed apps (PKCE, loopback redirect) via `oauth2`; scope `drive.file` | Sign-in happens in the client's browser; least-privilege scope with light verification |
| Scheduling | In-agent scheduler (wall-clock times, catch-up, no overlap) | Needs knowledge of sessions (upload cap) and quotas |
| Alerts | **ntfy** HTTP API, generic **webhooks** (`reqwest`) | Push to phones and chat tools without a central service |

## Clients

| Area | Choice | Why |
|---|---|---|
| Desktop UI | **Slint** | Native Rust UI with a declarative language, small runtime |
| Video presentation | VAAPI → DMA-BUF → EGL image → OpenGL texture (`khronos-egl`, `glow`) → Slint `BorrowedOpenGLTextureBuilder`; fallback: CPU upload into `SharedPixelBuffer`; Slint's wgpu integration kept as an option **(provisional: awaiting the S1 GPU run)** | No CPU copy per frame using a stable Slint API; needs an EGL context (Wayland, or a custom Slint platform on X11) |
| SSH setup from the app | `russh` | Pure-Rust SSH client with host-key verification |
| Web client | Rust → **WASM** (`wasm-bindgen`) for protocol and logic; **WebCodecs** decode; **WebGL/WebGPU** canvas; Pointer Lock, Keyboard Lock, Clipboard API | Shared protocol code with hardware decode in the browser |
| Web UI hosting | Served by `hx-gatewayd` (`axum`) | No separate web server |

## Build, test and release

| Area | Choice |
|---|---|
| Workspace | One Cargo workspace; `--locked` builds; one semver version for all components |
| Test runner | `cargo nextest`; `proptest` for property tests; `criterion` for microbenchmarks |
| UI tests | Slint testing backend; screenshot comparison; **Playwright** for the web client |
| Network simulation | `tc netem` profiles in CI |
| CI | GitHub Actions (Incus on Linux runners, KVM for installer VMs); a dedicated self-hosted runner for performance |
| Supply chain | `cargo-deny`, `cargo-audit`, Renovate |
| Release tooling | `dist` (formerly cargo-dist), Conventional Commits, `git-cliff` |
| Signing | **minisign** (current and next key embedded in `install.sh`); GitHub build provenance attestations |
| Packaging | `hx-agent`: static musl binary + `.deb`; `hx-session`: `.deb` per guest distro; desktop app: `.deb` + AppImage (Flatpak later); desktop images: signed Incus images, weekly |
| Hosting | GitHub Releases and GitHub Pages for docs (custom domain later) |

## External services

| Service | Used for | Notes |
|---|---|---|
| Google Drive API | Backup storage | OAuth app must be published to production before release (Testing-status tokens expire after 7 days) |
| Let's Encrypt | Web client certificates | Only when web access is enabled |
| images.linuxcontainers.org | Base images when building on the server | `debootstrap` from distro mirrors as last resort |
| GitHub | Code, CI, releases, prebuilt images, docs | Only project-run infrastructure |

## Licensing

- Project licence: **AGPL-3.0**; contributions under the **DCO**.
- All dependencies must be AGPL-compatible; `cargo-deny` enforces the allowed licence list. x264 (GPL-2.0+) and FFmpeg built with GPL components are allowed.
- Slint is used under its GPL-3.0 option, which is compatible with AGPL-3.0-or-later.
