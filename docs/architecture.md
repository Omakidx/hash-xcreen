# hash-xcreen architecture

Status: draft v0.2 (2026-11-20), updated with the Phase 0 spike results; items still marked **provisional** wait for the follow-up runs in execution-phase.md §0.4. Libraries and tools are in [tech-stack.md](tech-stack.md), the user experience in [userflow.md](userflow.md), and the phased plan we follow, including the Phase 0 spikes, in [execution-phase.md](execution-phase.md).

## 1. What hash-xcreen is

hash-xcreen is a self-hosted remote desktop. A user starts the app, points it at a server they control, and a full Linux desktop is set up on that server automatically. They then use the desktop from the native app or a browser, and it is backed up to their Google Drive every 12 or 24 hours. A backup restores the whole desktop, to the same server or a new one.

Everything is written in Rust. The desktop client uses Slint.

### Goals for v1

- A server goes from bare to a working desktop with one action in the app, or one pasted command.
- Streaming feels local: at most ~40 ms added on top of the network round trip at 1080p60, on a 4 vCPU server with no GPU.
- Backups are automatic, incremental, encrypted on the server, and restore to a desktop that boots with everything in place, including AI and chat app history and logins.
- Nothing secret ever appears in a command line, and nothing on the internet can reach the server's privileged code.

### Not in v1

- Live-process restore (CRIU). Backups capture everything on disk; open apps reopen through the desktop's own session restore.
- Desktops other than XFCE; guest distros other than Ubuntu and Debian.
- Windows and macOS clients, mobile clients (the protocol is kept ready for them).
- 120 fps, multi-monitor, microphone input, GPU passthrough into the desktop.
- Backup targets other than Google Drive.
- A central hosted service. There are no accounts, relays or cloud components run by the project.

## 2. Components

```
 client machine                         server (Ubuntu/Debian host)
┌──────────────────────┐               ┌──────────────────────────────────────────────┐
│ hx-desktop (Slint)   │  QUIC / TLS   │ hx-gatewayd  (unprivileged, sandboxed)        │
│  or                  │◄─────────────►│   QUIC + WebTransport + WebSocket endpoint,   │
│ hx-web (browser,     │   one port    │   pairing, login, protocol parsing, web UI    │
│  WASM + TS shell)    │               │        │ fixed command set (unix socket)      │
└──────────────────────┘               │        ▼                                      │
                                       │ hx-privd  (root, small)                       │
                                       │   Incus API, snapshots, mounts, restore,      │
                                       │   spawns the backup worker                    │
                                       │        │                                      │
                                       │        ▼                                      │
                                       │ Incus ── unprivileged system container ────┐  │
                                       │          │ XFCE on headless Xorg            │  │
                                       │          │ hx-session (runs as the user):   │  │
                                       │          │  capture, encode, audio, input   │  │
                                       │          └── unix socket to hx-gatewayd ────┘  │
                                       └──────────────────────────────────────────────┘
```

| Component | Runs as | Responsibility |
|---|---|---|
| `hx-gatewayd` | Dedicated unprivileged user, systemd-sandboxed | The only internet-facing process. TLS/QUIC, pairing, login (PIN, password, passkeys), protocol parsing, web client hosting, relaying media between client and `hx-session`. |
| `hx-privd` | root | A narrow, typed command set: create/start/stop container, snapshot, mount snapshot read-only, restore, resource limits, Docker toggle. Owns the Incus socket. |
| backup worker | Spawned by `hx-privd`, sandboxed | Reads a mounted snapshot read-only and uploads to Google Drive with `rustic_core`. Holds the Drive token and backup key only while running. |
| `hx-session` | The desktop user, inside the container | Screen capture, encoding, cursor, audio, clipboard, input injection. Holds no secrets. |
| `hx-agent` CLI | root, on demand | Local administration: status, devices list/revoke, uninstall, logs. |
| `hx-desktop` | User, client machine | Slint app: servers, setup wizard over SSH, streaming view, backups, security. |
| `hx-web` | Browser | Served by `hx-gatewayd`; login plus streaming and server settings for that one server. |
| `install.sh` | root, server | Bootstrap only: preflight checks, download and verify the agent, start it. Everything after that is done by the agent. |

## 3. Repository layout

```
crates/
  hx-proto      protobuf control messages, binary media headers, versioning
  hx-transport  QUIC (quinn), WebTransport, WebSocket fallback behind one interface
  hx-crypto     identity keys, SPAKE2 pairing, PIN/password hashing helpers
  hx-capture    capture + input backends (X11 first; KWin and Mutter later)
  hx-codec      libavcodec encode/decode wrappers, colour conversion
  hx-provision  declarative desktop recipe, Incus orchestration, image import/build
  hx-backup     rustic_core + Google Drive backend, scheduling, retention, verification
apps/
  hx-agent      hx-gatewayd, hx-privd, backup worker and the hx-agent CLI
  hx-session    in-container session daemon
  hx-desktop    Slint client
  hx-web        browser client (Rust to WASM + small TypeScript shell)
installer/      install.sh
recipes/        desktop recipes (distro × desktop × preset)
docs/           this document, decisions, spikes, protocol spec
```

One Cargo workspace; one semver version for every component.

## 4. Server side

### 4.1 Supported hosts and guests

- Host OS: Ubuntu 22.04 / 24.04 / 26.04, Debian 12 / 13; x86_64; systemd. arm64 later.
- Guest distros (inside the desktop): Ubuntu 24.04 / 26.04 LTS, Debian 12 / 13.
- Minimum: 2 vCPU, 4 GB RAM, 30 GB disk (enforced by preflight). Recommended: 4 vCPU, 8 GB.
- One desktop per server in v1. The data model (desktop IDs, per-desktop settings and backup repositories) allows several.

### 4.2 Incus and storage

- Incus from the distro repositories where new enough (Debian 13, Ubuntu 24.04+), otherwise the Zabbly repository.
- Storage pool on btrfs by default (ZFS when the host already uses it), on a spare disk (`--storage-device`) or a sparse loop file sized at about 60% of free disk, bounded to 12–200 GiB. Copy-on-write snapshots are what make backups consistent and cheap: S3 measured 0.2–0.5 s per snapshot, with space growing only by data that changes afterwards.
- The desktop is an **unprivileged** system container. Privileged containers are never used.
- Resource limits on CPU, memory and disk from the setup wizard.
- Container networking: the desktop joins a dedicated hash-xcreen bridge network. Incus network ACLs on that bridge allow internet access but drop the host's agent ports and `169.254.169.254` (cloud metadata). Incus 6.0 rejects ACLs on the container's own network interface, which is why the bridge is ours; an nftables rule set is the fallback where ACLs can't cover every host address. Blocking the host was verified in S3; the metadata rule still needs a VPS test.
- **Host kernel limits:** all unprivileged containers on a host share one inotify budget (default 128 instances), and one idle XFCE desktop uses about 23. The installer writes `/etc/sysctl.d/90-hx-incus.conf` (`fs.inotify.max_queued_events`, `max_user_instances` and `max_user_watches` = 1048576; `vm.max_map_count` = 262144) and preflight checks it. Without it, new containers failed to boot in S3 with "Too many open files".
- **Docker on the host:** Docker's firewall rules can block forwarding from the Incus bridge (S3 saw containers lose IPv4; inferred, not verified). The installer detects a host Docker and adds `DOCKER-USER` accept rules for our bridge.

### 4.3 Desktop provisioning

One declarative **recipe** per distro × desktop × preset, executed by `hx-provision`. The same recipe is used in two ways:

- **Prebuilt image**: CI runs the recipe weekly and publishes a signed Incus image.
- **Build on the server**: the recipe runs on the server, starting from the official Incus base image (or `debootstrap` if the image server is unreachable).

`--image auto` (the default) picks per server:

1. If a matching prebuilt image exists, check reachability of the release host, free disk, and download speed against the server's apt mirror.
2. Prebuilt path: download, verify signature and checksum, import, then apply security updates and any extra packages.
3. On any failure or a worse speed estimate, build on the server instead.
4. Report the chosen path and the reason in the app.

Overrides: `--image prebuilt`, `--image build`, `--image-file <path>` (offline servers).

CI builds the desktop both ways and compares package lists, config files and enabled services so the two paths cannot drift.

**Recipe format** (from S3): TOML fragments combined with `include`, `[vars]` for per-distro values, add-ons such as Docker, apt repositories pinned by key fingerprint, and a separate `post` stage that runs after a prebuilt import (user creation, security updates). Secrets come from the environment at run time, never from recipes. Every apt operation runs with a timeout and retries: in S3, `apt-get update` hung for over 9 minutes twice.

S3 timings (local, indicative): prebuilt import, launch and post-steps took 56–76 s, plus an estimated 34–84 s of download at 100 Mbps; building on the server took 213–308 s. Both are well inside the 5-minute and 20-minute targets.

**Presets**

| Preset | Contents |
|---|---|
| basic | XFCE, browser, file manager, text editor |
| developer | basic + VS Code, git, build tools, Claude Code, Codex CLI (vendors' native installers; they self-update) |

**Docker (opt-in)**: enables `security.nesting` and syscall interception for `mknod` and `setxattr` on the container, installs Docker Engine from Docker's apt repository, adds the user to the `docker` group, and restarts the desktop. The app warns that nesting enlarges the attack surface for container escapes. Later option: run the desktop as an Incus VM for full isolation, where the VPS supports nested virtualisation.

**Status (S3): not working as specified.** On Incus 6.0.0 with Ubuntu 24.04 and Debian 13 guests, image pulls work, but starting any container on Docker's default bridge fails: runc can't set `net.ipv4.ip_unprivileged_port_start` under the container's AppArmor profile. `--network host` works, and so does unconfining AppArmor, which is not acceptable as a default. Docker 29 also uses the containerd image store (overlayfs snapshotter) rather than classic overlay2. Next step: re-test on a VPS with newer Incus (Zabbly) and classic overlay2. If it still fails, choose between host-network-only Docker, running the desktop as an Incus VM when Docker is on, or a targeted AppArmor change. Tracked in execution-phase.md §0.4.

## 5. Install and setup

### 5.1 Entry points

- **From the app over SSH** (main path): address, port, user, SSH key (preferred) or a one-time password that is never stored; confirm the SSH host-key fingerprint; fill in the wizard; the app runs the installer over SSH and shows progress.
- **Copy the one-liner**: the wizard produces a command containing a one-time token and non-secret options; the app waits for the agent to come up at the given address and pairs.
- **Interactive** (`--interactive`): no app needed; the installer prompts for settings (hidden input for secrets) and prints a pairing code.
- **Restore from backup**: like the SSH path, but restores a backup instead of creating a fresh desktop (see 9.8).

```bash
curl -fsSL https://<release-host>/install.sh | sudo sh -s -- --token hx1_… --distro ubuntu-24.04 --desktop xfce --user alex --backup 12h --docker
```

Passwords and PINs are never in the command. The wizard collects them and the app sends them over the encrypted channel immediately after pairing, so the user still enters them once.

### 5.2 Installer options

| Option | Values |
|---|---|
| `--distro` | `ubuntu-24.04`, `ubuntu-26.04`, `debian-12`, `debian-13` |
| `--desktop` | `xfce` |
| `--user` | Linux username inside the desktop |
| `--hostname`, `--timezone`, `--locale`, `--keyboard` | Defaults from the client machine |
| `--apps` | `basic`, `developer` |
| `--docker` | Opt-in Docker |
| `--backup`, `--backup-keep` | `off`, `12h`, `24h`; retention override |
| `--cpu`, `--memory`, `--disk` | Container limits |
| `--storage-device` | Spare disk for the pool |
| `--image` | `auto`, `prebuilt`, `build`; `--image-file` |
| `--port` | QUIC/HTTPS port, default 443 |
| `--domain` | Domain for the web certificate (otherwise an IP certificate) |
| `--token` | One-time pairing token |
| `--interactive` | Prompt for everything |

### 5.3 Stages

1. Preflight: host OS, arch, systemd, RAM, disk, port free, unprivileged-container kernel support, inotify limits, a host Docker install. Fail with a clear message before changing anything.
2. Download the agent, verify its minisign signature against keys embedded in the script, install the systemd units.
3. Pair with the app (SPAKE2, see 8.2). From here the app shows progress over the encrypted channel.
4. Install Incus and write the kernel limits (`/etc/sysctl.d/90-hx-incus.conf`, applied with `sysctl --system`).
5. Create the storage pool and the hash-xcreen bridge network with its ACLs; add `DOCKER-USER` rules if Docker runs on the host.
6. Open the agent port in ufw or nftables, whichever is present.
7. Create the desktop (4.3), including Docker if chosen.
8. Receive secrets: set the Linux password, store the PIN hash, store the Drive token (5.4).
9. Schedule backups, start the first one in the background, open the desktop in the app.

Every stage is idempotent; re-running the command resumes a failed install. `hx-agent uninstall` removes everything, asking whether to keep the desktop.

### 5.4 Google Drive during setup

The app performs Google OAuth for installed apps (PKCE, loopback redirect) in the user's normal browser, requesting only `drive.file`, and sends the refresh token to the agent over the paired channel. It can be skipped and connected later. The OAuth client must be **published to production** before release: tokens issued by an app in "Testing" status expire after 7 days.

### 5.5 Updates

- Agent: self-update from signed releases on the stable or beta channel, with automatic rollback when the new version fails its health check.
- `hx-session`: pushed into the container by the agent; only the streaming process restarts, user apps keep running.
- The desktop's own packages are the user's responsibility (`apt upgrade`).

## 6. Streaming

### 6.1 Capture (`hx-capture`)

One trait, one backend per display stack:

- **X11** (v1, XFCE; later MATE and Cinnamon): headless Xorg with the dummy driver; XDamage for changed regions; XShm for copy-free reads; XTest for input; RandR for resizing to the client window.
- **KDE Plasma** (later): KWin virtual output, screencast through PipeWire, libei for input.
- **GNOME** (later): Mutter headless mode with its RemoteDesktop and ScreenCast D-Bus APIs.

No damage means no capture, no encode and no traffic.

### 6.2 Encode (`hx-codec`)

- All encoders through libavcodec, so one code path covers them.
- Software default: **x264** with `ultrafast`, `zerolatency`, `crf=23`, a one-frame VBV, a bitrate ladder up to 20 Mbps, sliced threads equal to the number of encode cores, `keyint=120`, gradual intra refresh, and IDR frames only on connect and resync. In S2 this encoded in 4–8 ms (p50) and used 0.5–0.6 cores while typing or scrolling at 1080p. Intra refresh cost 15–25% more bitrate with no latency gain on a LAN; it stays on until it is measured on a lossy link. x264 is allowed because the project is AGPL.
- **Pacing:** capture as soon as the pipeline is free after damage arrives; 60 fps is a ceiling, not a clock. Holding damage to a fixed 60 fps grid added 5–13 ms at p95 in S2.
- Changing bitrate currently reopens the encoder and forces an IDR (12–17 reopens in S2's lossy runs); production should reconfigure the rate without reopening.
- **SVT-AV1** real-time presets where CPU and client allow (later phase); AV1 has screen-content coding tools.
- Hardware when present: VAAPI (Intel/AMD), NVENC (NVIDIA).
- Colour conversion with SIMD (`yuvutils-rs`).
- **Sharp-text refinement** (later phase): when a region stops changing, re-encode it at near-lossless quality.
- 60 fps maximum in v1; 120 fps later.

### 6.3 Cursor

Sent separately as shape (cached by hash) and position, and drawn by the client, so pointer movement never waits for video.

### 6.4 Audio, clipboard, files

- Audio: PipeWire capture in the container, Opus 10 ms frames with in-band FEC, sent as datagrams.
- Clipboard: both directions for text, images and files; can be switched off per paired device.
- Files: copy and paste or drag and drop; each transfer on its own low-priority stream with progress.

### 6.5 Clients

- **Desktop (Slint)** **(provisional until the S1 GPU run)**: libavcodec hardware decode (VAAPI on Linux), exported as a DMA-BUF, imported as an EGL image into an OpenGL texture, and shown with Slint's stable borrowed-OpenGL-texture API, with no CPU copy. This is the route mpv and other FFmpeg-based players use.
  - Fallback: copy each frame into a Slint pixel buffer (software decode costs about 0.5 core at 1080p60, plus about 0.3 core for colour conversion).
  - The wgpu route stays an option, but depends on an unstable Slint feature tied to a wgpu major version and on unsafe Vulkan import code.
  - Copy-free display needs an EGL context. Slint's winit backend creates one on Wayland but a GLX context on X11, so X11 needs a custom Slint platform that creates its own EGL context.
  - Decoded colour must use the stream's colour space and range, not a fixed BT.709 assumption, and frame hand-off needs explicit GPU fences rather than `glFinish`.
- **Web**: WebCodecs hardware decode into a WebGL/WebGPU canvas; Pointer Lock and Keyboard Lock; protocol code shared as WASM.
- Keyboard input is sent as physical scancodes so every layout works.
- Remote resolution follows the client window (RandR); HiDPI scaling supported.

## 7. Wire protocol

### 7.1 Transport

- QUIC with TLS 1.3 for the native client (`quinn`), WebTransport over HTTP/3 for the browser, both on the same port. WebSocket over TLS on TCP as a fallback where UDP is blocked.
- One `quinn` endpoint offers ALPN `h3` and `hx/1` and the accept loop dispatches on the negotiated value: `hx/1` goes to native code, `h3` to `wtransport` running on the same endpoint. The WebSocket fallback listens on the same port number over TCP. All three were proven in S5.
- Safari uses the WebSocket fallback until WebTransport (reportedly shipped in Safari 26.4) and certificate hashes are tested on a Mac.
- BBR congestion control.
- ALPN `hx/1`.

### 7.2 Channels

| Channel | QUIC transport | Priority |
|---|---|---|
| Control (hello, version, capabilities, settings, stats) | One bidirectional stream | High |
| Keys and mouse buttons | Reliable stream | Highest |
| Mouse movement | Datagrams (latest wins) | Highest |
| Cursor shape and position | Reliable stream | High |
| Video | One unidirectional stream per frame | Normal |
| Audio | Datagrams | High |
| Clipboard, files | Reliable streams | Lowest |

### 7.3 Encoding

- Control messages: Protocol Buffers (`prost`). A written protocol spec lives in `docs/protocol.md`, so mobile and third-party clients can be built later.
- Media: a fixed little-endian header (frame number, capture timestamp, codec, flags, payload length) followed by the encoded payload.

### 7.4 Congestion handling

- Control at the source: when frames queue, encode fewer frames and lower the bitrate; never drop already-encoded frames mid-chain.
- Gradual intra refresh instead of large keyframes.
- When frames fall more than ~100 ms behind: cancel queued frame streams and send a fresh full image.
- The completion of each frame's stream is the per-frame acknowledgement that drives the sender's controller, which steps a bitrate ladder. In S2, with a 150 ms round trip, 10 Mbps and 1% loss, video settled at about 3.5 Mbps and 29 fps; without the controller, frames queued to a 1.4 s median delay. Follow-ups: a jitter-adaptive lag threshold (the fixed 40 ms threshold over-reacts on jittery links), faster ramp-up after congestion, and starting below the top of the ladder.
- Frames can arrive out of order across streams. The client keeps a small reorder window and drops any frame older than the newest one it has decoded (S5).
- Per-device bandwidth cap: Auto, 5, 10, 25, 50 Mbps.

### 7.5 Versioning

- The hello exchange carries protocol `major.minor` plus capability flags (codecs, features).
- Different major: refuse with an "update required" message. Different minor: disable newer features.
- The agent supports the current and previous protocol major. The web client always matches its agent.

## 8. Security

### 8.1 Threat model

| Attacker | Defence |
|---|---|
| Internet scanners, network attackers | Unpaired peers can only attempt pairing while a token is valid; all else is refused at the TLS handshake. Pre-auth parsers are fuzzed. |
| Someone who sees the one-liner | Token is single-use and expires after 15 minutes. |
| Stolen client device | Device key alone is not enough: the server checks the PIN, revoking the device after 5 failures. Devices can be revoked from any other device or the CLI. |
| Malware inside the desktop | Unprivileged container; `hx-session` holds no secrets; the agent treats all container input as untrusted; metadata endpoint and agent ports blocked. |
| Google or a compromised Google account | Backups are encrypted and authenticated before upload. |
| Tampered installer or update | minisign signatures verified against embedded keys; build provenance attestations. |

Out of scope: the VPS provider, or anyone with root on the host.

### 8.2 Identity and pairing

- The agent generates a long-term identity key at install; each client device generates a device key.
- Pairing uses **SPAKE2**, with either the long random token from the app or a short code printed by an interactive install. Neither side reveals the secret, and a man in the middle learns nothing.
- After pairing, every connection is TLS 1.3 with both keys pinned (mutual authentication, no certificate authority).

### 8.3 Credentials

- **Password**: the Linux account password inside the desktop (login, sudo, lock screen); stored only as the system's shadow hash. Sent once during setup over the paired channel.
- **PIN**: required to connect. Verified by the server (Argon2id hash), five failures revoke the device; re-pairing needs the password.
- **Passkeys (WebAuthn)**: registered for the web client in v1.

### 8.4 Web client

- Off by default; enabled from the desktop app.
- First login: password + PIN, then register a passkey; afterwards passkey + PIN.
- Rate limiting with exponential backoff and IP lockouts; short-lived sessions bound to the browser.
- Certificate from Let's Encrypt for `--domain`.
- With no domain **(provisional: not yet issued for real)**: a Let's Encrypt short-lived certificate for the server's IP address (`shortlived` profile, about 160 hours, validated by `http-01` or `tls-alpn-01`), renewed automatically. `instant-acme` supports IP identifiers and ACME profiles.
- Fallback: a self-signed ECDSA P-256 certificate valid for under 14 days, pinned by the page through WebTransport's `serverCertificateHashes` (works in Chrome and Firefox, S5). Rotation needs an overlap window offering two hashes. Because the browser won't trust that certificate for loading the page itself, this fallback needs the web client served from a trusted HTTPS origin (for example the project's GitHub Pages), which then connects to the server by IP and pins the hash it got from the desktop app.

### 8.5 Privilege separation

- `hx-gatewayd` runs unprivileged with systemd hardening (`NoNewPrivileges`, `ProtectSystem=strict`, private tmp, capability bounding) and a seccomp allowlist.
- `hx-privd` accepts only a fixed set of typed commands over a unix socket.
- The host reads container files only through the Incus API, never by following paths into the container filesystem.

### 8.6 Secrets on the server

- Drive refresh token, backup repository key and agent identity key are stored root-only, outside the container, sealed with `systemd-creds` (TPM-backed where available).
- `hx-gatewayd` never sees the Drive token or backup key.
- Because unattended backups need the backup key, root on the server can read the backups. The **recovery key** is shown once at setup and is the only way to restore if the server is lost.
- Root on the server could delete backups using the Drive token; the desktop app checks regularly that recent backups exist and warns if they disappear.

### 8.7 Client side

- Device key in the system keyring (Secret Service on Linux); server keys pinned.
- The remote side can never execute anything locally; links open only after confirmation.

## 9. Backup and restore

### 9.1 Scope

Everything on disk in the desktop container: system, installed apps, configuration, home directory, Docker data (when enabled). Open apps reopen through XFCE's session restore after a restore.

### 9.2 Excludes and protected paths

- Excludes target exact cache locations only: `~/.cache/`, Electron `Cache/`, `Code Cache/`, `GPUCache/`, `DawnCache/`, package manager caches, `/tmp`, `/var/tmp`, trash, logs, Docker BuildKit cache; user-editable.
- A protected list always overrides general excludes: `~/.claude/`, `~/.claude.json`, `~/.codex/`, `~/.gemini/`, `~/.cursor/`, `~/.config/*/Local Storage`, `~/.config/*/IndexedDB`, `~/.config/*/Session Storage`, `~/.config/Code/User/`, app data under `~/.local/share/<app>/`, and the data parts of browser profiles (cookies, logins, history, local and IndexedDB storage).
- Protected paths are resolved to concrete sub-paths, and named cache directories inside them are still excluded (`~/.local/share/Trash`, a browser profile's `Cache*` folders). S4 found that protecting whole profiles and all of `~/.local/share` pulled Trash and about 30 MB of browser cache per day into backups. This "protected wins, except named caches" rule is evaluated by hx, because rustic's glob overrides can't express it.
- Credential files inside these paths (for example `~/.claude/.credentials.json`, `~/.codex/auth.json`) are backed up so a restored desktop is still signed in.
- A CI test installs these apps, creates sessions, backs up, restores into a fresh container and checks the history survived.

### 9.3 Docker backup modes

- **Complete** (default): all of `/var/lib/docker` except the BuildKit cache.
- **Light**: volumes, container configuration and Compose files only; images are pulled again on restore.

### 9.4 Backup run

0. Take hash-xcreen's own single-writer lock on the repository (`rustic_core` has no lock files) and run `repair index`. Without the repair, retrying an interrupted backup re-uploaded everything in S4 (3.2 GB instead of the 138 MB actually missing).
1. Take an Incus snapshot (crash-consistent; SQLite, LevelDB and database containers recover from it as from a power cut; S4 confirmed `PRAGMA integrity_check` = ok on a database written to during the snapshot).
2. Attach the snapshot read-only to the backup worker with ownership mapped (an idmapped mount, as S4 did with an Incus disk device and `shift=true`) and run the worker: `rustic_core`, **zstd level 3**, content-defined chunking, encryption and authentication, Google Drive backend. Level 9 cost about 70% more CPU for 4% smaller output.

S4 sizes (synthetic data): a 2.24 GB desktop became a 906 MB repository; a simulated day of use added 98 MB.
3. Record a manifest: distro, desktop, preset, container configuration, agent version, backup format version.
4. Delete the snapshot.

### 9.5 Scheduling

- Fixed wall-clock times chosen by the user (for example 03:00 and 15:00), in the server's timezone, with a few minutes of random offset.
- Missed runs (server off, agent down) run shortly after start-up if the last success is older than the interval.
- Never overlapping: a run that would start while one is active is skipped and logged.
- Low CPU and I/O priority. Upload capped at ~50% of measured upstream while a client is connected; full speed otherwise.

### 9.6 Failures

| Failure | Handling |
|---|---|
| Network errors, Google 5xx, rate limiting | Retry with exponential backoff and jitter; content addressing means only missing data is uploaded on retry. OpenDAL's `gdrive` backend retries only 5xx, 405 and one specific message, so hash-xcreen's wrapper must handle HTTP 429 and 403 `rateLimitExceeded`. Each pack is one multipart upload, so an interrupted upload resumes per pack, not mid-pack. |
| Daily upload limit (750 GB per account) | Pause and resume the next day. |
| Token revoked or expired | Stop; mark "Action needed: reconnect Google Drive". |
| Server disk too full for a snapshot | Do not start; notify. |
| Agent crash mid-run | On start-up, remove tagged leftover snapshots and stale repository locks; retry. |
| No success for twice the interval | Red badge in the app regardless of cause. |

### 9.7 Quota, retention and verification

- Free Google storage (15 GB) is shared with Gmail and Photos. The wizard estimates the first backup and typical increments before enabling backups.
- Before each run, compare free Drive space with the estimated new data. Warnings at 80% and 95%.
- **Drive full**: prune oldest backups automatically, never below the two most recent successful ones; if still short, stop and notify.
- Retention defaults: every 12h keeps the latest 14 + 4 weekly + 6 monthly; every 24h keeps 7 daily + 4 weekly + 6 monthly. Editable per server.
- Pruning runs weekly.
- Verification: weekly metadata check; monthly download of a random 5% sample. The app shows a "Last verified" date.

### 9.8 Restore

1. Restore into a new container under a temporary name; the current desktop is untouched.
2. Interrupted restores resume, skipping files already restored and verified.
3. The restored desktop must boot and start `hx-session` before it replaces the old one.
4. The old desktop is kept as a pre-restore snapshot until the user confirms, or for 7 days.
5. Restoring onto a newer agent is supported; the manifest records versions.
6. Restore details found in S4: keep numeric owner IDs; restore sparse files as sparse; recreate the mount-point directories that backups skip (`/proc`, `/sys`, `/dev`, `/run`, `/tmp`); on a new server, generate a new hostname and `/etc/machine-id`, which otherwise stay identical to the original's. S4 restored 81,065 entries with 0 differences in contents, owners, permissions, extended attributes or hard links, and an interrupted restore resumed by restoring only the missing files.
7. **Restore onto a new server**: the app signs in to Drive, the user picks a backup and enters the recovery key, and the installer restores instead of creating a fresh desktop.

### 9.9 Alerts

In-app badges and desktop notifications, plus optional server-side alerts in v1: **ntfy** push and **webhooks**. Email (SMTP) later.

## 10. Performance targets

| Metric | Target (1080p60, 4 vCPU, no GPU) |
|---|---|
| Added latency (LAN, p95) | ≤ 40 ms; expected 15–25 ms |
| Encode CPU while typing or scrolling | ≤ 1.5 cores |
| Idle desktop | ~0% CPU, ~0 bandwidth |

Latency budget: capture ≤ 2 ms, colour conversion 1–2 ms, encode 4–8 ms, send < 1 ms, hardware decode 2–4 ms, present 0–8 ms.

S2 measured (damage to decode complete, p95, LAN, 4 pinned cores, presentation excluded): typing 24.6 ms, scrolling 34.6 ms, window drag 30.2 ms, video 40.5 ms (28.6 ms with lower pacing). The server used 0.48–0.60 cores while typing or scrolling, and 0.01 cores with 0 bytes sent while idle. The 40 ms target holds only with CPU headroom: under heavy shared-host load, scrolling and dragging reached 37–61 ms at p95.

Hot path rules: encode only on damage; buffer pools, no per-frame allocation; dedicated threads joined by lock-free queues for capture, conversion and encode; the async runtime is used only for networking.

## 11. Client apps

### 11.1 Desktop app

- **Home**: server cards with status, last-screen thumbnail, last backup result, warnings (failed backup, Drive almost full, backups missing), Connect, Add server.
- **Add server wizard**: method (SSH, one-liner, pairing code, restore from backup) → connection → desktop (distro, desktop, preset, Docker) → account (username, password, PIN) → backups (Drive, schedule, retention, recovery key confirmation) → resources (limits, port, domain, web access) → review and install with live progress.
- **Connect**: PIN, then the desktop; a "Reconnecting…" overlay on network loss.
- **Desktop view**: hidden toolbar (default `Ctrl+Alt+Shift`) with display mode, quality (Auto, Sharp, Smooth), stats overlay, keyboard capture and key combinations, transfers, disconnect.
- **Server details**: Overview (resources, uptime, version), Backups (timeline, back up now, restore, schedule, retention, Drive usage, last verified), Security (devices, PIN and password, web access, passkeys), Desktop (Docker, limits, restart, update), Danger zone (uninstall).
- **App settings**: theme, shortcuts, default quality, start at login, clipboard settings for this device, bandwidth cap.
- Visual design: dark-first with a light theme, to be proposed as mockups before building.

### 11.2 Web client

Login (passkey + PIN; password + PIN the first time), desktop view with the same toolbar, server details. No SSH setup and no restore-to-new-server.

## 12. Testing

| Layer | Approach |
|---|---|
| Unit and property | `cargo nextest`; `proptest` for protocol round-trips, exclude/protected-path rules, retention (never deletes the two latest successes) |
| Fuzzing | `cargo-fuzz` on all pre-auth parsers and all container-supplied input; nightly; OSS-Fuzz later |
| Provisioning | Incus on GitHub Linux runners; matrix of guest distros; prebuilt vs built equivalence check |
| Installer | Fresh Incus VM per host OS (KVM on GitHub runners); both image paths |
| Backup | In-memory/local backend on every PR; real Google Drive test account nightly, including the chat-app history restore test |
| Streaming end to end | Agent + desktop container + headless test client under `tc netem` profiles |
| UI | Slint testing backend and screenshot comparisons; Playwright for the web client (Chromium, Firefox) |
| Performance | Dedicated runner; scenario suite (idle, typing, scrolling, video, window drag); regressions fail the build |
| Upgrade | Previous release → new release: old backups restore; old client ↔ new agent and new client ↔ old agent connect |
| Failure | Kill agent mid-backup, network loss mid-restore, full disk, revoked token |

## 13. Releases

- One semver version for all components; protocol version separate.
- Channels: stable and beta; nightly builds for testers.
- `hx-agent`: static musl binary and `.deb`. `hx-session`: `.deb` per guest distro. Desktop app: `.deb` and AppImage (Flatpak later). Desktop images: weekly, signed.
- `dist` for GitHub Releases; conventional commits and `git-cliff` for changelogs; `--locked` builds.
- minisign signing (current and next key embedded in `install.sh`); signing key in a protected GitHub environment; GitHub build provenance attestations.
- `cargo-deny`, `cargo-audit`, Renovate; `SECURITY.md` with private vulnerability reporting.
- Hosting: GitHub only for now (releases, install script, docs).
- Licence: AGPL-3.0. Contributions under the DCO (`Signed-off-by`).

## 14. Roadmap

| Phase | Scope |
|---|---|
| 0. Spikes | Foundations and spikes S1–S5 in [execution-phase.md](execution-phase.md) |
| 1. Core | Installer, Incus + Ubuntu/Debian + XFCE (both image paths), `hx-privd`/`hx-gatewayd`/`hx-session`, pairing and PIN, desktop client with video, input, cursor, clipboard |
| 2. Backups | Schedule, encryption, retention, quota handling, verification, restore (including to a new server), alerts, backup screens |
| 3. Web client | WebTransport + WebCodecs, passkeys, certificates |
| 4. Polish | AV1, sharp-text refinement, audio, file transfer, GPU encode, SSH setup from the app, Docker toggle UI, more desktops |

## 15. Risks and assumptions to verify

Status after the Phase 0 spikes (details in `docs/spikes/`; follow-up runs in execution-phase.md §0.4):

| Item | Status |
|---|---|
| Slint can display GPU-decoded frames without CPU copies | Open: code built, untested without a GPU (S1 GPU run) |
| x264 1080p60 within the CPU and latency budget on 4 vCPU | Confirmed locally (S2); re-measure on a quiet VPS |
| XFCE fits the 2 vCPU / 4 GB minimum | Confirmed locally (S3); VPS overhead still to measure |
| Docker nested in the desktop | **Failing** on Incus 6.0 (S3); decision pending |
| Full-desktop backup and restore with `rustic_core` | Confirmed with a local repository (S4) |
| OpenDAL's Google Drive backend, `drive.file` scope, rate limits | Open: compiles and fits, untested against Drive (S4 Drive run) |
| WebTransport and native QUIC on one port | Confirmed (S5) |
| Let's Encrypt IP-address certificates; Safari support | Open (S5 public-server run) |
| Google OAuth app verification for `drive.file` stays light | Release checklist |
