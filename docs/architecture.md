# hash-xcreen architecture

Status: draft v0.1 (2026-11-20). Libraries and tools are in [tech-stack.md](tech-stack.md), the user experience in [userflow.md](userflow.md), and the phased plan we follow, including the Phase 0 spikes, in [execution-phase.md](execution-phase.md).

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
- Storage pool on ZFS or btrfs, on a spare disk (`--storage-device`) or a loop file. Copy-on-write snapshots are what make backups consistent and cheap.
- The desktop is an **unprivileged** system container. Privileged containers are never used.
- Resource limits on CPU, memory and disk from the setup wizard.
- Container networking: internet access allowed; the host's agent ports and `169.254.169.254` (cloud metadata) blocked.

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

**Presets**

| Preset | Contents |
|---|---|
| basic | XFCE, browser, file manager, text editor |
| developer | basic + VS Code, git, build tools, Claude Code, Codex CLI (vendors' native installers; they self-update) |

**Docker (opt-in)**: enables `security.nesting` and syscall interception for `mknod` and `setxattr` on the container, installs Docker Engine from Docker's apt repository, adds the user to the `docker` group, and restarts the desktop. The app warns that nesting enlarges the attack surface for container escapes. Later option: run the desktop as an Incus VM for full isolation, where the VPS supports nested virtualisation.

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

1. Preflight: host OS, arch, systemd, RAM, disk, port free, unprivileged-container kernel support. Fail with a clear message before changing anything.
2. Download the agent, verify its minisign signature against keys embedded in the script, install the systemd units.
3. Pair with the app (SPAKE2, see 8.2). From here the app shows progress over the encrypted channel.
4. Install Incus.
5. Create the storage pool.
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
- Software default: **x264** (`ultrafast`, `zerolatency`, sliced threads, one-frame VBV, gradual intra refresh). x264 is allowed because the project is AGPL.
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

- **Desktop (Slint)**: libavcodec hardware decode (VAAPI on Linux) into a GPU texture, displayed through Slint's wgpu integration without CPU copies. This is spike S1; fallbacks are an OpenGL underlay or a CPU upload path.
- **Web**: WebCodecs hardware decode into a WebGL/WebGPU canvas; Pointer Lock and Keyboard Lock; protocol code shared as WASM.
- Keyboard input is sent as physical scancodes so every layout works.
- Remote resolution follows the client window (RandR); HiDPI scaling supported.

## 7. Wire protocol

### 7.1 Transport

- QUIC with TLS 1.3 for the native client (`quinn`), WebTransport over HTTP/3 for the browser, both on the same port. WebSocket over TLS on TCP as a fallback where UDP is blocked.
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
- Certificate from Let's Encrypt for `--domain`, or a short-lived IP-address certificate when there is no domain (to be confirmed in spike S5).

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
- A protected list always overrides excludes: `~/.claude/`, `~/.claude.json`, `~/.codex/`, `~/.gemini/`, `~/.cursor/`, `~/.config/*/Local Storage`, `~/.config/*/IndexedDB`, `~/.config/*/Session Storage`, `~/.config/Code/User/`, `~/.local/share/` app data, browser profiles.
- Credential files inside these paths (for example `~/.claude/.credentials.json`, `~/.codex/auth.json`) are backed up so a restored desktop is still signed in.
- A CI test installs these apps, creates sessions, backs up, restores into a fresh container and checks the history survived.

### 9.3 Docker backup modes

- **Complete** (default): all of `/var/lib/docker` except the BuildKit cache.
- **Light**: volumes, container configuration and Compose files only; images are pulled again on restore.

### 9.4 Backup run

1. Take an Incus snapshot (crash-consistent; SQLite, LevelDB and database containers recover from it as from a power cut).
2. Mount it read-only and run the backup worker: `rustic_core`, zstd compression, content-defined chunking, encryption and authentication, Google Drive backend.
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
| Network errors, Google 5xx, rate limiting | Retry with exponential backoff and jitter; content addressing means only missing data is uploaded on retry. |
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
6. **Restore onto a new server**: the app signs in to Drive, the user picks a backup and enters the recovery key, and the installer restores instead of creating a fresh desktop.

### 9.9 Alerts

In-app badges and desktop notifications, plus optional server-side alerts in v1: **ntfy** push and **webhooks**. Email (SMTP) later.

## 10. Performance targets

| Metric | Target (1080p60, 4 vCPU, no GPU) |
|---|---|
| Added latency (LAN, p95) | ≤ 40 ms; expected 15–25 ms |
| Encode CPU while typing or scrolling | ≤ 1.5 cores |
| Idle desktop | ~0% CPU, ~0 bandwidth |

Latency budget: capture ≤ 2 ms, colour conversion 1–2 ms, encode 4–8 ms, send < 1 ms, hardware decode 2–4 ms, present 0–8 ms.

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

| Item | Verified by |
|---|---|
| Slint can display GPU-decoded frames without CPU copies (wgpu integration is behind an unstable feature) | S1 |
| x264 1080p60 within the CPU and latency budget on 4 vCPU | S2 |
| XFCE + Docker nesting fits the 2 vCPU / 4 GB minimum | S3 |
| OpenDAL's Google Drive backend is mature enough for `rustic_core` (fallback: rclone backend) | S4 |
| Let's Encrypt IP-address certificates for the no-domain web client; WebTransport support per browser (Safari) | S5 |
| Google OAuth app verification for `drive.file` stays light | Release checklist |
