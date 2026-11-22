# Tech stack

Every language, library, tool and external service hash-xcreen uses, and why. Items marked **(provisional)** were chosen in the Phase 0 spikes but still need the follow-up run listed in [execution-phase.md](execution-phase.md) §0.4 before we depend on them (only the desktop client's video path, pending the S1 GPU run).

## Languages

| Language | Where | Why |
|---|---|---|
| Rust (stable, 2024 edition) | Everything: agent, session, clients, installer logic | Memory safety for internet-facing and root code, predictable performance for the media path, one language end to end |
| TypeScript | Thin shell of the web client (WebCodecs, WebTransport, canvas, input APIs) | Browser APIs not reachable cleanly from WASM; kept small |
| POSIX `sh` | `install.sh` bootstrap only, with `openssl` 3 or newer (Ed25519 and BLAKE2b-512 for the minisign check), `curl`, `sha256sum`, `tar`, `gzip`, `flock`, `base64`, `od` and `dd` | Runs on any host before Rust binaries exist; does preflight, download and signature check, then hands off to `hx-agent install`. No logic beyond that lives in the script |
| Slint markup (`.slint`) | Desktop client UI | Declarative UI compiled into the Rust binary |

## Server

| Area | Choice | Why |
|---|---|---|
| Desktop isolation | **Incus** system containers (unprivileged), 6.0.0 or newer, 6.0.5 or newer for Docker (an existing install is adopted; otherwise the distro package, otherwise the Zabbly `lts-6.0` repository with a pinned key, architecture §4.2) | Real distro images with systemd, built-in snapshots and export, image server, VMs available later |
| Storage | **btrfs** pool (spare disk or loop file); btrfs only in v1 | Instant copy-on-write snapshots for consistent backups |
| Desktop (v1) | **XFCE** on headless **Xorg** with the `dummy` driver | Lightest desktop, simplest and most efficient capture path |
| Audio in the desktop | **PipeWire** | Standard on current Ubuntu/Debian; capture for streaming |
| Docker (opt-in) | Docker Engine from Docker's apt repository, Incus `security.nesting` with `mknod`/`setxattr` interception, Incus ≥ 6.0.5, installer self-test with fallbacks (architecture §4.3) | Official packages; nested Docker on the default bridge proven in S3 on a VPS |
| Host tuning | `/etc/sysctl.d/90-hx-incus.conf` (inotify limits, `vm.max_map_count`) | All unprivileged containers share one inotify budget; the default (128) blocks a second desktop |
| Provisioning recipes | TOML fragments (`include`, `[vars]`, add-ons, `post` stage) applied by `hx-provision` | Same recipe drives prebuilt images and building on the server |
| Process management | **systemd** 250 or newer: units with sandboxing, `systemd-creds` and `LoadCredentialEncrypted=` for secrets, socket activation for every listener | Hardening and TPM-sealed secrets without extra software; 250 is the first release with credentials, which is why Ubuntu 22.04 (249) is not a host |
| Firewall | ufw or nftables, whichever the host uses | Avoid fighting the host's existing setup |
| Async runtime | **tokio** (networking only) | Standard for quinn and HTTP; kept out of the media hot path |
| Incus API client | Incus REST API over its unix socket (`hyper` 1.x with `hyper-util`, `http-body-util` and `bytes`; `serde` + `serde_json`; `tokio` for the socket and timeouts). Image import is a **streaming upload**: `Transport::send_file` reads a staged `std::fs::File` with `pread` in 1 MiB frames, because request bodies are otherwise in memory and responses are capped at 32 MiB (`POST /1.0/images` with `X-Incus-fingerprint`, `X-Incus-public`) | No CLI scraping; typed requests from `hx-privd`; a 1 to 2.5 GB image cannot be an in-memory body |
| Host packages (installed by the `packages` stage, architecture §5.3) | `btrfs-progs`, `nftables`, `ca-certificates`, `dnsmasq-base`, **`zstd`** | `zstd` because Incus decodes the zstd-compressed prebuilt image on the host (architecture §4.3); the manifest's `compression` field makes a fall back to `gzip` a data change |
| Recipe engine | `toml` 0.8 + `serde` (unknown keys rejected), `sha2` (file hashes in the equivalence manifest), `thiserror` (typed errors), `zeroize` (the desktop password in `hx_provision::Secret` is zeroized on drop and not `Clone`) | Pure, deterministic parsing and resolution in `hx-provision` |
| Root daemon (`hx-privd`) | `rustix` (`mm`, `process`, `fs`, `net`: `mlockall`, `PR_SET_DUMPABLE`, `RLIMIT_CORE`, `statvfs`, socket-activation checks, with one audited `unsafe` block to adopt the `sd_listen_fds` descriptor), `hmac`, `hkdf`, `sha2`, `subtle`, `getrandom` (pepper verifiers, constant-time compare), `serde` + `serde_json` (state files, `ip -j` output), `prost` (recovering the request id of a rejected request), `bytes`, `zeroize`; fixed-argv `nft`, `sysctl`, `iptables`, `ip`, `blkid` through a closed `Tool` set with a cleared environment; units hardened with systemd sandboxing | Typed command set over a socket-activated unix socket, secrets in `Zeroizing` buffers read without an intermediate copy; no shell, no caller-supplied program, path or Incus parameter (docs/ipc.md Part 1) |
| Self-update (`hx-privd`, `hx-update-fetcher`) | `minisign-verify` (verification only; key generation and signing stay in the release pipeline), `flate2` with the pure-Rust `miniz_oxide` backend (the artifact is a `.tar.gz`), `tar` without default features (header parsing only; privd creates every file itself with `openat2`), `rustls` (`ring`, no `tls12`) and `rustls-native-certs` for the fetcher's HTTPS, `sha2`; dev only: `minisign` (signs test releases with a key generated at test time) and `rcgen` (the local HTTPS test server) | A root daemon verifies and unpacks signed releases in process with no C decoder; the only networked code is a separate, sandboxed binary with a small hand-written HTTP/1.1 `GET` client (docs/ipc.md 6.12) |
| Image tooling (`hx-imagectl`, `apps/hx-imagectl`, `publish = false`) | `hx-provision` (build, seal, equivalence and the manifest types), `tokio`, `serde_json`, `sha2`, `minisign-verify` (verifies its own output with the image public key), a hand-written argument parser (no CLI crate, like `hx-agent`); subcommands `digest`, `build-image`, `desktop`, `compare`, `manifest`, `verify`. Signing itself uses the minisign CLI in the `image-signing` job, as the release job does | CI-only tool that builds, seals, compares and signs the weekly desktop images; shares `hx_provision::images` with `hx-privd`, so the publisher and the verifier cannot disagree on the manifest rules (docs/ipc.md 6.12) |
| Gateway process (`hx-gatewayd`) | `toml` 0.8 + `serde` (configuration file, unknown keys rejected), `tracing-subscriber` (`fmt` only, no `env-filter`: logs to stderr, so the journal), `listenfd` (systemd socket activation for the admin socket: the unprivileged gateway cannot create a root-owned socket in `/run/hx`), `argon2` (the PIN's Argon2id step, the same parameters as `hx-crypto`; the pepper step stays in privd), `getrandom`, `libc` (syscall and address-family numbers for the seccomp allowlist only), `rustix` (`mlockall`, `PR_SET_DUMPABLE` and rlimits as safe calls); the post-pairing setup of the one-liner path (1G, docs/ipc.md 5.5) reuses `argon2`, `hx-crypto`, `hx-proto` and `hx-ipc` and **needs no new dependency**; both listeners are socket-activated and selected by `LISTEN_FDNAMES` (`admin`, `public`), with TCP told from UDP by `SO_TYPE` | Everything the gateway needs beyond the transport, with no `unsafe` in our code |
| Admin CLI (`hx-agent`) | A hand-written argument parser (no CLI crate: the accepted surface is exactly what is written), blocking `std` unix sockets read only through `hx_ipc::recv::NoCmsgReader`, `rustix` with the `termios` feature (hidden prompts on `/dev/tty`: echo and `ISIG` off, restored on every exit; `pty` as a dev-dependency to test it on a real pseudo-terminal), `argon2` with its `zeroize` feature and `rustix` `rand` (verifiers for `pin set` and `desktop password`, the same format as the gateway's), `libc` `pthread_sigmask` in one small audited `unsafe` module (`cli/sigblock.rs`: termination signals are held back while a prompt has echo off; no handler), `serde_json` (`--json`), `zeroize`, `subtle` (comparing the two entries of a secret); `install` and `uninstall` run programs only from a closed, fixed-argv `Tool` set with a cleared environment (`apt-get`, `dpkg-query`, `apt-cache`, `systemctl`, `systemd-creds`, `systemd-sysusers`, `systemd-tmpfiles`, `ufw`, `nft`, `userdel`, `ip`), and `logs` runs `journalctl` the same way | Root-only, on demand; also the installer engine (`hx-agent install`, architecture §5), which reuses privd's update code to verify and unpack the first release; talks to the gatewayd admin socket and to privd as Admin (docs/ipc.md section 9 and Part 1); secrets only from the tty or a secret frame, every peer string sanitized, no environment read at all (`apps/hx-agent/src/cli/README.md`) |
| Password checker (`hx-pwcheck`) | libxcrypt's `crypt_rn` through one audited FFI block (links `libcrypt1`, which is Essential on every supported guest), `subtle` for the constant-time compare; reads `/etc/shadow` with `O_NOFOLLOW` | Verifies the current password inside the desktop for `SetUserPassword` and handles every hash scheme the distro writes (yescrypt, sha512); dynamically linked, which departs from ipc.md's earlier "static" wording |

## Streaming

| Area | Choice | Why |
|---|---|---|
| X11 capture | **XDamage**, **XShm**, **XFixes** (cursor), **RandR** (resize), via `x11rb` | Change-driven, copy-free capture; pure-Rust X11 bindings |
| Input injection | **XTest** (X11) via `x11rb`, keys as USB HID usage → evdev → X keycode; **libei** later for Wayland desktops | Standard injection APIs per display stack; layout-independent physical keys |
| Clipboard | X11 selections (CLIPBOARD; PRIMARY opt-in) via `x11rb` with **XFixes** owner notifications and ICCCM `INCR`; worker woken by `rustix` `eventfd` | No extra dependency; text, PNG images and `text/uri-list` files both ways |
| Colour conversion | `yuvutils-rs` (SIMD) | Fast RGB→YUV without a C dependency |
| Codec framework | **libavcodec** (FFmpeg) via `ffmpeg-next` / `ffmpeg-sys-next` (7.1 against Ubuntu 24.04's FFmpeg 6.1; newer FFmpeg needs a newer `ffmpeg-next`; Ubuntu 26.04's FFmpeg version, and so the `ffmpeg-next` it needs, is still to be verified in 1E) | One API for every encoder and decoder, software and hardware |
| Software encoder | **x264** (`ultrafast`, `zerolatency`, `crf=23`, VBV of a few frames, bitrate ladder ≤ 20 Mbps, sliced threads, intra refresh, BT.709 limited-range VUI tags) | Best low-latency software H.264 (4–8 ms encode, 11–17 ms p95 end to end on a quiet VPS in S2); GPL is fine because we are AGPL |
| Media pipeline threads | Dedicated OS threads joined by bounded `crossbeam-channel` queues, pooled buffers | Keeps the hot path off the async runtime (S2) |
| Linux system calls | `rustix` (safe wrappers: `poll`, `memfd`, `mmap`, clocks, `recvmsg`, `sockopt`) | Keeps `unsafe` in our code to one read-only shared-memory mapping, one FFmpeg rate-control field, the adoption of the systemd-passed socket and the removal of `LISTEN_*` after it (`OwnedFd::from_raw_fd` and `env::remove_var`, once per process, after checking `LISTEN_PID`, the descriptor count and that fd 3 is a listening unix stream socket) |
| Session link, session end (`hx-session`) | Plain OS threads with blocking `std` unix sockets, read only through `hx_ipc::recv::NoCmsgReader`; socket activation implemented in `hx-session` itself (`sd_listen_fds`, no crate); `hx-ipc` with only the `link` feature | The session is off the async runtime like the media pipeline (S2); the daemon never creates or binds the socket path (ipc.md section 11) |
| Session link, gateway end (`hx-agent`) | `tokio` (`UnixStream` with `try_io` around `recv_no_cmsg`, timers, `sync`), `bytes`, a hand-written bounded H.264 Annex B / SPS check (no parser crate), `rustix` `rand` for the `link_id` | The internet-facing process must bound every hostile byte itself (ipc.md section 19); no new heavy dependency. Tests use `prost` and `rustix` `net` (descriptor-passing attacks) as dev-dependencies |
| Error types | `thiserror` 2 | Typed errors for libraries; no panics on display or codec failures |
| Streaming build and test dependencies | FFmpeg dev libraries (`libavcodec`, `libavformat`, `libavutil`, `libswresample`, 6.1), `libx264`, `libclang` and `pkg-config` (bindings); **Xvfb** (integration tests, `HX_REQUIRE_XVFB=1` in CI) | `ffmpeg-sys-next` links the system FFmpeg and generates bindings with bindgen; installed by the CI clippy and test jobs |
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
| Control messages | **Protocol Buffers** via `prost`; schema compiled in `build.rs` with the pure-Rust `protox` + `prost-build` (no `protoc` binary needed on CI or developer machines, no generated code to keep in sync) | Schema evolution, language-neutral for future mobile clients |
| Media framing | Fixed little-endian binary header | No parsing cost on the hot path |
| Internal IPC (`hx-ipc`) | `prost` + `protox` (same build-time pipeline as `hx-proto`, schemas `hx.privd.v1`, `hx.gatewayd_admin.v1`, `hx.link.v1`), `bytes`, `thiserror`, `zeroize` (the non-`Clone`, redacting `Secret` buffer), `rustix` with the `net` feature (`recvmsg` that refuses descriptors, `SO_PEERCRED`), `proptest` (round trips and totality) | Length-prefixed frames with a kind byte so that secrets bypass the protobuf decoder; features `privd` and `link` keep the privd messages out of `hx-session`; no network dependency, so nothing pulls in `quinn` |
| Protocol and transport support crates | `bytes` (zero-copy buffers), `thiserror` (typed errors), `tracing` (diagnostics, no payloads or secrets), `futures-util` (WebSocket sink/stream split), `tokio-rustls` (TLS under the WebSocket fallback), `proptest` (round-trip and totality tests) | Small, widely used crates behind `hx-proto` and `hx-transport` |
| Web certificates | Let's Encrypt via ACME (`instant-acme` 0.8 with `ring`, default features off so `aws-lc-rs` stays out); short-lived IP-address certificates when there is no domain, renewed by ACME Renewal Information; `rcgen` for keys and CSRs, `x509-parser` for the renewal ID; fallback: self-signed ECDSA P-256 certificate from `rcgen`, pinned with `serverCertificateHashes` | Real HTTPS for the browser without a domain (issued and renewed in production in S5) |

## Security

| Area | Choice | Why |
|---|---|---|
| Pairing | **SPAKE2** (`spake2` crate) | Safe with both long tokens and short human codes; resists man-in-the-middle |
| Keys | Ed25519 identities (`ed25519-dalek`), pinned in TLS 1.3 as **raw public keys** (RFC 7250, `rustls` with `ring`) | No certificate authority and no X.509 parsing before authentication; one config for QUIC and WebSocket (protocol §11.1) |
| Pairing and PIN primitives | `sha2`, `hmac` (transcript and confirmation MACs), `argon2` parameters in protocol §11.4, `getrandom`, `subtle` (constant-time compare), `zeroize` | Small RustCrypto building blocks; secrets are zeroized and never printed |
| PIN hashing | **Argon2id** (`argon2`) | Memory-hard; server-side verification with lockout |
| Linux password | System shadow hash (yescrypt) | Standard login, sudo and lock screen |
| Web login | **WebAuthn passkeys** (`webauthn-rs`) | Phishing-resistant browser login |
| Client key storage | Secret Service / libsecret via `keyring` | System keyring on Linux |
| Syscall filtering | seccomp allowlist (`seccompiler`) plus systemd hardening | Contain `hx-gatewayd` if exploited |
| Fuzzing | `cargo-fuzz` (libFuzzer, via `libfuzzer-sys`) on a dated nightly toolchain, in the `fuzz/` crate that is excluded from the product workspace; AddressSanitizer; nightly GitHub workflow; OSS-Fuzz later. The crates expose their entry points behind a `fuzzing` Cargo feature that no product build enables. Seed generation reuses `spake2` and `tar` (already approved) | Pre-auth and container-supplied parsers; the toolchain, sanitizer flags and `libfuzzer-sys` stay out of the product build and its `Cargo.lock` |

## Backups

| Area | Choice | Why |
|---|---|---|
| Backup engine | **`rustic_core`** (Rust implementation of the restic format), zstd level 3; versions pinned because its API is still unstable | Content-defined chunking, deduplication, compression, authenticated encryption; restic-compatible format; full round trip proven locally in S4 |
| Google Drive access | **OpenDAL** (`opendal` used directly with only `services-gdrive`, not `rustic_backend`'s `opendal` feature: 20 MB binary instead of 43 MB), behind hash-xcreen's own backend for rate limits, the daily cap, timeouts, listing errors and permanent deletes; rclone backend as fallback for very large packs or slow uplinks | Native Rust Drive backend for rustic; `drive.file` proven on real Drive in S4 |
| Google auth | OAuth 2.0 for installed apps (PKCE, loopback redirect) via `oauth2`; scope `drive.file`; one fixed OAuth client for all installs | Sign-in happens in the client's browser; least-privilege scope with light verification; `drive.file` only sees files from the same client |
| Scheduling | In-agent scheduler (wall-clock times, catch-up, no overlap) | Needs knowledge of sessions (upload cap) and quotas |
| Alerts | **ntfy** HTTP API, generic **webhooks** (`reqwest`) | Push to phones and chat tools without a central service |

## Clients

| Area | Choice | Why |
|---|---|---|
| Desktop UI | **Slint**, following the approved mockups (`design/mockups/`: `tokens.css` maps one to one to a Slint `global Tokens`); the theme follows the system theme, a system title bar, 900 x 600 minimum window | Native Rust UI with a declarative language, small runtime. No password-strength library is approved: the wizard's advisory meter is hand-written (length and character classes), and any estimator crate needs a row here first |
| Video presentation | **Built first on the CPU-upload path** (decision 2026-11-22): software decode in `hx-codec`/FFmpeg to RGBA, then a `SharedPixelBuffer` as a Slint image. The GPU path is detected at runtime later: VAAPI → DMA-BUF → EGL image → OpenGL texture (`khronos-egl`, `glow`) → Slint `BorrowedOpenGLTextureBuilder`; Slint's wgpu integration kept as an option **(provisional: awaiting the S1 GPU run, which the maintainer runs later)** | No CPU copy per frame using a stable Slint API; needs an EGL context (Wayland, or a custom Slint platform on X11) |
| SSH setup from the app | `russh` | Pure-Rust SSH client with host-key verification |
| Web client | Rust → **WASM** (`wasm-bindgen`) for protocol and logic; **WebCodecs** decode; **WebGL/WebGPU** canvas; Pointer Lock, Keyboard Lock, Clipboard API | Shared protocol code with hardware decode in the browser |
| Web UI hosting | Served by `hx-gatewayd` (`axum`) | No separate web server |

## Build, test and release

| Area | Choice |
|---|---|
| Workspace | One Cargo workspace; `--locked` builds; one semver version for all components |
| Test runner | `cargo nextest`; `proptest` for property tests; `criterion` for microbenchmarks; `cargo-fuzz` for the fuzz targets (`fuzz/README.md`) |
| Gateway test support | `tempfile`, `hmac` + `sha2` (a fake `hx-privd` that derives its own pepper), `quinn` + `rustls` (a raw QUIC client that can announce protocol 1.0, for the takeover fallback), `strace` as an optional development aid for deriving the seccomp allowlist | Tests of `hx-gatewayd` against a privd written from `docs/ipc.md` alone |
| UI tests | Slint testing backend; screenshot comparison; **Playwright** for the web client |
| Network simulation | `tc netem` profiles in CI, made unprivileged: two network namespaces in a user namespace (`unshare -rn`, `nsenter`) joined by a veth pair, `netem` on both ends, `ip`, `tc` and `ping` from iproute2 and iputils (docs/testing.md) |
| Performance suite | `criterion` microbenchmarks (default features off, so no plotting stack); the macro run is the LAN end-to-end test repeated; `perf/check.py` compares with the committed `perf/baseline.json` (Python 3, standard library only, no pip packages) |
| CI | GitHub Actions (Incus on Linux runners, KVM Incus VMs for the installer matrix); a local nested-container harness (an unprivileged Incus container with its own Incus) for the installer; a dedicated self-hosted runner for performance |
| Supply chain | `cargo-deny`, `cargo-audit`, Renovate |
| Release tooling | `.github/workflows/release.yml` (not `dist`: its archive layouts and lack of a signed manifest conflict with the release contract); the `x86_64-unknown-linux-musl` target with `musl-tools` for the agent binaries; `dpkg-deb` and `dpkg-shlibdeps` (native to the distro, exact sonames) for the `hx-session` packages, built in per-distro job containers; Conventional Commits, `git-cliff` |
| Signing | **minisign** (the minisign CLI in the release job, signing key in the protected GitHub environment `release-signing`; current and next key both required and embedded in `install.sh`). **Desktop images use a separate key pair** (current and next, `apps/hx-agent/image-keys/`, embedded in `hx-privd`) whose secret key lives in the GitHub environment `image-signing`: `main` branch only, no per-run approval, secrets `IMAGE_MINISIGN_SECRET_KEY` and `IMAGE_MINISIGN_KEY_PASSWORD`, so that a leaked image key cannot sign agent releases; both pairs stay `UNPROVISIONED` until the maintainer supplies them (architecture §13). `actions/attest-build-provenance` attestations, for audit only |
| Packaging | `hx-agent`: static musl binaries in one release tarball, no `.deb` in v1 (dpkg would own files that privd rewrites); `hx-session`: `.deb` per guest distro inside that tarball; desktop app: `.deb` + AppImage (Flatpak later); desktop images: one **unified Incus tarball compressed with zstd** per recipe (`incus publish --compression zstd`; the SHA-256 is the Incus fingerprint), at most 4 GiB, byte-split into at most 4 parts under 2 GiB (GitHub's per-file limit) only when needed, with a signed manifest, weekly (the immutable release `images-<build_id>` plus the moving release `images`, newest 4 kept) |
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
