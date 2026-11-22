# hash-xcreen architecture

Status: draft v0.3 (2026-11-20), updated with the Phase 0 spike results and their follow-up runs on a real server and real Google Drive; the only item still marked **provisional** is the desktop client's video path, which waits for the S1 GPU run (execution-phase.md §0.4). Libraries and tools are in [tech-stack.md](tech-stack.md), the user experience in [userflow.md](userflow.md), the internal IPC contracts between the server processes in [ipc.md](ipc.md), and the phased plan we follow, including the Phase 0 spikes, in [execution-phase.md](execution-phase.md).

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
                                       │          └── unix socket (Incus proxy) ─────┘  │
                                       └──────────────────────────────────────────────┘
```

| Component | Runs as | Responsibility |
|---|---|---|
| `hx-gatewayd` | Dedicated unprivileged user, systemd-sandboxed | The only internet-facing process. TLS/QUIC, pairing, login (PIN, password, passkeys), protocol parsing, web client hosting, relaying media between client and `hx-session`. |
| `hx-privd` | root | A narrow, typed command set: create/start/stop container, snapshot, mount snapshot read-only, restore, resource limits, Docker toggle. Owns the Incus socket. Command set and authorization in [ipc.md](ipc.md) Part 1. |
| backup worker | Spawned by `hx-privd`, sandboxed | Reads a mounted snapshot read-only and uploads to Google Drive with `rustic_core`. Holds the Drive token and backup key only while running. |
| `hx-session` | The desktop user, inside the container | Screen capture, encoding, cursor, audio, clipboard, input injection. Holds no secrets. Talks only to `hx-gatewayd`, over the session link ([ipc.md](ipc.md) Part 2). |
| `hx-agent` CLI | root, on demand | Local administration: status, devices list/revoke, logs, and the installer (`hx-agent install`, `hx-agent uninstall`, §5). |
| `hx-desktop` | User, client machine | Slint app: servers, setup wizard over SSH, streaming view, backups, security. |
| `hx-web` | Browser | Served by `hx-gatewayd`; login plus streaming and server settings for that one server. |
| `install.sh` | root, server | Bootstrap only: preflight, download, openssl minisign check, hand-off to `hx-agent install` (§5.6). Everything after that is done by `hx-agent install`, which calls `hx-privd` for the privileged desktop work. |

## 3. Repository layout

```
crates/
  hx-proto      protobuf control messages, binary media headers, versioning
  hx-ipc        internal IPC: framing and schemas for hx-privd, the gatewayd admin socket and the session link
  hx-transport  QUIC (quinn), WebTransport, WebSocket fallback behind one interface
  hx-crypto     identity keys, SPAKE2 pairing, PIN/password hashing helpers
  hx-capture    capture + input backends (X11 first; KWin and Mutter later)
  hx-codec      libavcodec encode/decode wrappers, colour conversion
  hx-provision  declarative desktop recipe, Incus orchestration, image import/build
  hx-backup     rustic_core + Google Drive backend, scheduling, retention, verification
apps/
  hx-agent      hx-gatewayd, hx-privd, backup worker, the hx-agent CLI and the installer engine (`hx-agent install`, `hx-privd-rescue`)
  hx-session    in-container session daemon
  hx-pwcheck    in-container current-password checker (dynamically linked, ships in the `hx-session` package)
  hx-desktop    Slint client
  hx-web        browser client (Rust to WASM + small TypeScript shell)
installer/      install.sh
packaging/      the `hx-session` .deb assembly (§13)
release/        release assembly: tarball, canonical manifest (§13)
recipes/        desktop recipes (distro × desktop × preset)
docs/           this document, decisions, spikes, protocol spec
```

One Cargo workspace; one semver version for every component.

## 4. Server side

### 4.1 Supported hosts and guests

- Host OS: Ubuntu 24.04 / 26.04, Debian 12 / 13; x86_64; systemd 250 or newer. arm64 later.
  - **Ubuntu 22.04 is not supported.** It ships systemd 249, which has neither `systemd-creds` nor `LoadCredentialEncrypted=` (both arrived in 250), and every secret in §8.6 is sealed with them. Preflight refuses it with a message saying so. It also has no Incus in its repositories.
- Guest distros (inside the desktop): Ubuntu 24.04 / 26.04 LTS, Debian 12 / 13.
- Minimum: 2 vCPU, 4 GB RAM, 30 GB disk. Recommended: 4 vCPU, 8 GB. Preflight enforces `MemTotal` of at least 3584 MiB, at least 2 CPUs and at least 30 GiB free where the pool will live (§5.2). It also refuses to run **inside a container** (`systemd-detect-virt -c`): nested Incus hosts are not a supported target.
- One desktop per server in v1. The data model (desktop IDs, per-desktop settings and backup repositories) allows several.

### 4.2 Incus and storage

- **Incus source** (the installer's `incus` stage, §5.3):
  - An Incus already on the host, version 6.0.0 or newer, is adopted and **never upgraded**. With `--docker`, an existing Incus older than 6.0.5 fails preflight with the reason (§4.3).
  - Otherwise the distro package, if its candidate (`apt-cache policy incus`, after `apt-get update`) is 6.0.0 or newer, and 6.0.5 or newer when `--docker` is given.
  - Otherwise the Zabbly `lts-6.0` repository: its armored key is embedded in `hx-agent` with a pinned fingerprint, written to `/etc/apt/keyrings/hx-zabbly.asc`, and referenced from a deb822 source file with `Signed-By`.
  - Expected results (to be verified in the installer matrix, §12): Debian 12 uses Zabbly (bookworm has Incus only in backports); Ubuntu 24.04 and Debian 13 use the distro package, or Zabbly with `--docker`; Ubuntu 26.04 uses the distro package, subject to its version and to whether Zabbly publishes a 26.04 suite.
  - `incus admin init` is never run: `hx-provision` creates its own profiles and never uses `default`.
- Storage pool on btrfs only in v1 (`hx_provision::HostSpec` always creates a btrfs pool; ZFS is not implemented), on a spare disk (`--storage-device`) or a sparse loop file sized at about 60% of free disk, bounded to 12–200 GiB. Copy-on-write snapshots are what make backups consistent and cheap: S3 measured 0.2–0.5 s per snapshot, with space growing only by data that changes afterwards.
- The desktop is an **unprivileged** system container. Privileged containers are never used.
- Resource limits on CPU, memory and disk from the setup wizard, plus `limits.processes` (default 8192, never unlimited, so a fork bomb cannot exhaust the host). Every desktop also gets `security.guestapi=false` (no `/dev/incus` socket inside), `security.idmap.isolated=true` (its own uid/gid range on the host) and `boot.autostart=true`. Isolated idmaps mean file ids on the host are shifted per desktop; see the restore note in §9.8.
- Container networking: the desktop joins a dedicated hash-xcreen bridge network (IPv4 only, NAT; an existing bridge with IPv6 or NAT differing is reconciled). Incus 6.0 rejects ACLs on the container's own network interface, which is why the bridge is ours. Isolation has two layers:
  1. **Incus network ACL on the bridge** (created by `hx-provision`). Egress drops all of `169.254.0.0/16` (link-local: AWS, GCP, Azure, Oracle metadata at `169.254.169.254`, Tencent `169.254.0.23`, AWS ECS and Time Sync), `100.100.100.200` (Alibaba), `168.63.129.16` (Azure WireServer), `fd00:ec2::/32`, the bridge gateway and every host address the installer passes in, then allows the rest (internet, DNS and DHCP to the gateway are permitted by Incus itself). Ingress admits only connections whose source is the bridge gateway (the host, where the agent runs) and the default ingress action is drop; ACLs are stateful, so replies to the desktop's own connections arrive. Verified in S3 on a VPS (metadata and host-address rules) and in Phase 1 on a real Incus (host listener blocked, host-initiated connection into the desktop works, other host source addresses refused, with controls that the same probes pass when the ACL is detached).
  2. **nftables ruleset, generated by `hx-provision` and loaded and persisted by `hx-privd` / the installer.** This is not a fallback: the ACL only knows unicast host addresses, so a host service bound to `0.0.0.0` stays reachable by broadcast, multicast, link-local and later-added addresses, and traffic the host forwards (masqueraded as the host) could reach host Docker bridges, other Incus bridges, VPN or tailnet interfaces, VPC private ranges and DNAT'd host ports. The ruleset (`table inet hx`) acts only on packets entering from our bridge. `input`: accept established/related, DHCP (udp 67-68) and DNS (udp and tcp 53) to the gateway, drop everything else, both families. `forward`: accept established/related, drop DNAT'd connections, keep the bridge's own subnet, drop `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`, `fc00::/7` and `fe80::/10`; the internet via NAT passes. Reaching the LAN or a VPN from the desktop is an explicit installer opt-in (`allow_private_networks`, default off). The installer verifies the ruleset at runtime (checklist in `crates/hx-provision/README.md`).
  Known limit: Incus 6.0 network ACLs do not filter traffic between two instances on the same bridge (observed on 6.0.0). With one desktop per server (v1) nothing else lives on the bridge; a design with several desktops must not rely on the ACL for desktop-to-desktop isolation.
- **Host kernel limits:** all unprivileged containers on a host share one inotify budget (default 128 instances), and one idle XFCE desktop uses about 23. The installer writes `/etc/sysctl.d/90-hx-incus.conf` (`fs.inotify.max_queued_events`, `max_user_instances` and `max_user_watches` = 1048576; `vm.max_map_count` = 262144) and preflight checks it. Without it, new containers failed to boot in S3 with "Too many open files" (on the VPS, the sixth desktop failed with the default limit; eight ran with ours).
- **Docker on the host:** Docker's firewall rules block forwarding from the Incus bridge, so containers lose IPv4 (confirmed on the VPS in S3). The installer detects a host Docker and adds two `DOCKER-USER` accept rules for our bridge (in on the bridge; out to it when related or established), **made persistent across reboots** (Docker recreates the chain on start, so the rules are re-applied by a unit ordered after `docker.service`). Reboot persistence is still to be tested.
- **Guest compatibility rules:** on the VPS kernel (7.0, Incus 6.0.5), Debian 13 desktops hang at boot unless the container's AppArmor profile allows `signal` (`raw.apparmor "signal,"`); Ubuntu guests don't need it. The rule lives in a hash-xcreen Incus profile (prebuilt images carry no instance config), and the installer checks that every new desktop reaches `systemctl is-system-running` = `running` before going on.

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

Format decisions made in Phase 1 (`recipes/README.md` has the full format): includes are relative to the recipes root and may not leave it; add-ons are merged at resolve time and may only add content (`[user].groups`, packages, repositories, files, services, `incus_config`); unknown keys are errors; recipes may set only `security.nesting`, `security.syscalls.intercept.mknod` and `security.syscalls.intercept.setxattr` as instance config (enforced when parsing, when creating the container and when enabling Docker; never `security.privileged`, `raw.*` or other intercepts); an apt key file must contain exactly the pinned primary key and only that key is exported into the keyring; every download uses https only. The post stage runs after both paths, so vendor installers (Claude Code, Codex CLI) run there as the desktop user and are `optional` (a vendor outage becomes a warning). **The desktop username** is chosen in the wizard and is validated user input (`Username`: `^[a-z_][a-z0-9_-]{0,31}$`, reserved system names refused); it is the only user-derived value that reaches a recipe. Prebuilt images are built with `desk`; when the chosen name differs, the post stage renames the account (home directory, group and lingering move with it) before the password is set, and the account step refuses to adopt a system account or a different uid. Nothing in the X server unit refers to the name (it uses the numeric uid). **Exec output** never goes through Incus's `record-output` (the host would write unbounded files for a possibly hostile container): output is captured through size-capped files inside the container. The user password reaches the container only as the stdin of `chpasswd`, delivered through a 0600 file in a 0700 directory that is removed afterwards (the REST exec API only offers stdin over a websocket).

S3 timings: on a real 4 vCPU VPS, prebuilt import, launch and post-steps took 16–29 s, plus an estimated 1–2 minutes of download at 100 Mbps, and building on the server took 86–206 s (locally 56–76 s and 213–308 s). Both are well inside the 5-minute and 20-minute targets. Incus plus one idle desktop cost the host 0.1–0.35 GB of RAM, leaving 3.45–3.93 GB free at 2 vCPU / 4 GB.

**Presets**

| Preset | Contents |
|---|---|
| basic | XFCE, browser, file manager, text editor |
| developer | basic + VS Code, git, build tools, Claude Code, Codex CLI (vendors' native installers; they self-update) |

**Docker (opt-in)**: enables `security.nesting` and syscall interception for `mknod` and `setxattr` on the container, installs Docker Engine from Docker's apt repository, adds the user to the `docker` group, and restarts the desktop. Requires **Incus 6.0.5 or newer**.

- **Warning shown when the user turns it on:** with nesting, Incus drops the container's AppArmor denials for `/proc/sys` and `/sys` and allows `mount`, `pivot_root`, `ptrace` and `signal`, which enlarges the attack surface for container escapes. That is why Docker is opt-in.
- **Rollback:** if the install fails or the self-test fails, nesting and the syscall interception are switched back off and the desktop restarted, so a desktop without working Docker does not keep the reduced isolation (the result says whether the rollback worked).
- **Self-test:** the version number isn't trusted. After enabling Docker, the installer runs `docker run --rm hello-world` (with a pull) on Docker's default bridge.
- **If the self-test fails** (as on Incus 6.0.0, where runc can't set `net.ipv4.ip_unprivileged_port_start`), the app says so and offers, in order:
  1. upgrade Incus from the Zabbly repository;
  2. **host-network-only Docker**, which worked on every version tested, with no port isolation inside the desktop and `network_mode: host` needed in Compose files;
  3. run the desktop as an Incus VM, where the server has `/dev/kvm`. Not for v1: it boots in about 31 s instead of 2 s, uses 1–1.8 GB of RAM instead of about 0.2 GB, and S4's file-level backups don't apply to VM disks.
- A custom AppArmor profile or `unconfined` is not used: it was never needed on a good Incus version and would need maintenance against every Incus update.

S3 evidence: on the VPS (Ubuntu 26.04 host, Incus 6.0.5), `hello-world` and a Compose app with a volume ran on Docker's default bridge in Ubuntu 24.04 and Debian 13 desktops, for about 85 MiB and no boot penalty, keeping btrfs snapshots. On Incus 6.0.0 (local) the same setup failed. Which release between them fixed it is unknown, hence the self-test.

## 5. Install and setup

### 5.1 Entry points

- **From the app over SSH** (main path): address, port, user, SSH key (preferred) or a one-time password that is never stored; confirm the SSH host-key fingerprint; fill in the wizard; the app runs `install.sh --ssh` over SSH, **as a file, not through `curl | sh`**, and shows progress. The secrets (password, PIN, optionally the app's own pairing token) go to the installer on its stdin in the framing of [ipc.md](ipc.md) §5.4, never in argv; progress comes back as JSON Lines (§5.8).
- **Copy the one-liner**: the wizard produces a command containing **no token** and only non-secret options. The installer asks for the one-time token at a hidden `/dev/tty` prompt, installs the agent, opens the port and installs the token, then **stops**. The app shows the token separately (with **Copy**), waits for the agent at the given address and pairs. Everything after pairing (password, PIN, creating the desktop from the app) needs post-pairing setup messages that are not specified yet; they are designed in 1G (execution-phase.md), so in 1E the one-liner ends at pairing (§5.3).
- **Interactive** (`--interactive`): no app needed; the installer prompts for settings (hidden input for secrets) and prints a pairing code.
- **Restore from backup**: like the SSH path, but restores a backup instead of creating a fresh desktop (see 9.8).

```bash
curl -fsSL https://github.com/Omakidx/hash-xcreen/releases/download/channel-stable/install.sh | sudo sh -s -- --pair --distro ubuntu-24.04 --desktop xfce --user alex --backup 12h --docker
```

Passwords and PINs are never in the command, and neither is the token (decision 14, [ipc.md](ipc.md) §22): `sudo` writes argv to the auth log and the journal and the shell keeps it in its history. The token is typed at the installer's own prompt, which reads `/dev/tty` because stdin is the pipe. `--token <t>` exists for unattended use only and prints a warning that it is weaker.

### 5.2 Installer options

`install.sh` consumes `--channel`, `--release-dir`, `--allow-old-release` (accept a manifest older than 90 days, with a warning; never forwarded) and `--progress text|json` (forwarded to the agent as the global `--json`) and passes every other argument to `hx-agent install` unchanged. The interface of `hx-agent install`:

```
hx-agent [--json] install [MODE] [OPTIONS] [--bootstrap-dir <abs>] [--lock-fd <n>]
MODE (at most one):
  --interactive   prompts on /dev/tty; ends with a pairing code
  --pair          one-liner: token prompted on /dev/tty (hidden) right after preflight,
                  installed at stage pairing-token; the installer ends there
  --token <t>     unattended; weaker; warning printed; otherwise like --pair:
                  installed at stage pairing-token; the installer ends there
  --ssh           secrets from stdin (ipc.md §5.4); stdin must not be a tty; --json implied
  (none)          resume or reconcile an existing install with its recorded mode and
                  options; refused on a fresh host (exit 2)
```

The agent reads no environment variable; its children get a cleared environment and a fixed `PATH`. It runs with `umask 0077`, `PR_SET_DUMPABLE=0` and `mlockall`, and refuses to run unless both real and effective uid are 0.

| Option | Values and validation | Default | On a re-run |
|---|---|---|---|
| `--distro` | `ubuntu-24.04`, `ubuntu-26.04`, `debian-12`, `debian-13` | `ubuntu-24.04` | fixed once the desktop is ready |
| `--desktop` | `xfce` | `xfce` | fixed |
| `--user` | `hx_provision::Username` | required (prompted in `--interactive`) | fixed |
| `--hostname` | RFC 1123 label | unset (the app passes the client's) | fixed |
| `--timezone` | a name present in `/usr/share/zoneinfo` | unset; `--interactive` defaults to the host's | fixed |
| `--locale` | privd's pattern and allowlist | unset; interactive: the host's | fixed |
| `--keyboard` | `^[a-z]{2}(\+[a-z0-9_-]{1,16})?$` | unset; interactive: the host's | fixed |
| `--apps` | `basic`, `developer` | `basic` | fixed |
| `--docker` | flag; counts as the isolation acknowledgement (interactive: a typed `yes` after the §4.3 warning); also decides the Incus source (§4.2) | off | after the desktop is ready: refused, use `hx-agent docker enable` or `disable` |
| `--backup`, `--backup-keep` | `off`, `12h`, `24h`; integer 1 to 1000 | `off` | recorded only: stage `backup` is `deferred` (Phase 2, `SetBackupSchedule` is `UNIMPLEMENTED`); reconcilable |
| `--cpu`, `--memory`, `--disk` | cpu 1 to the host's CPUs; memory in MiB or `NG`/`NM`, at least 1024 and at most RAM − max(1536 MiB, 25%); disk in GiB, at least 8 | privd defaults | reconcilable (`SetLimits` once the desktop is ready) |
| `--storage-device` | whole, unmounted block device with no signature (read-only pre-check; privd checks again) | loop file | fixed once stage `host` is done |
| `--image` | `auto`, `build`, `prebuilt` | `auto` (privd then builds and says why) | fixed. `prebuilt` and `--image-file`: exit 6 at preflight, "not in this release" (privd answers `UNIMPLEMENTED`; prebuilt images wait for 1D's image CI) |
| `--port` | 1 to 65535, not 22 or 80; free for TCP and UDP (or held by our own socket) | 443 | reconcilable: the firewall rule is moved and the socket restarted |
| `--domain` | FQDN | none | recorded only (Phase 3 consumes it; the gateway configuration has no `domain` key yet); reconcilable |
| `--token <t>` | `hxt1-…` pairing token | n/a | n/a; unattended and weaker (§5.1) |
| `--interactive`, `--pair`, `--ssh` | modes; at most one of them, and none together with `--token` | n/a | the mode may change between runs |
| `--channel` | `stable`, `beta` | `stable` | reconcilable. Chooses the manifest `install.sh` fetches and sets `[update] channel` in `/etc/hx/privd.toml` |
| `--allow-private-networks` | flag (interactive: a typed `yes`); the opt-in promised in §4.2 | off | reconcilable (`SetupHost` converges) |
| `--release-dir` (`install.sh` only) | absolute, root-owned directory holding a manifest, signature and tarball, **still verified** | none | n/a |
| `--allow-old-release` (`install.sh` only) | flag: accept a signed manifest older than 90 days, with a warning | off | n/a |
| `--progress` (`install.sh` only) | `text`, `json` | `text` | n/a |

Fixed options may change freely while the desktop is not ready: `CreateDesktop` destroys a `creating` or `failed` instance and starts again ([ipc.md](ipc.md) §6.5).

**Exit codes** (0 to 8 are the CLI's own):

| Exit | Meaning |
|---|---|
| 0 | ok |
| 1 | a stage failed; run the same command again to resume |
| 2 | usage, or missing secrets |
| 3 | daemon unavailable |
| 4 | refused by privd or gatewayd |
| 6 | not in this release |
| 7 | not root |
| 8 | declined |
| 9 | preflight failed (nothing changed) |
| 10 | verification failed (signature, digest, version) |
| 11 | another install or uninstall is running |
| 12 | options conflict with the existing install |

**Preflight** (read-only; `install.sh` runs a reduced form first, §5.6): `ID` and `VERSION_ID` in the supported set (§4.1); `x86_64`; `/run/systemd/system` exists and systemd is 250 or newer; cgroup2 mounted; `user.max_user_namespaces` above 0; not inside a container (the test-hook build excepted, §12); `MemTotal` at least 3584 MiB and at least 2 CPUs; at least 30 GiB free on the filesystem of `/var/lib/incus` (or `/var/lib`), and with `--storage-device` the device at least 30 GiB and the root filesystem at least 5 GiB free; the port free for TCP and UDP; the Incus rules of §4.2; `--image prebuilt` and `--image-file` refused (exit 6). A host Docker is reported, for information only.

### 5.3 Stages

Every stage has a `check()` and a `run()`. It is skipped only when it is recorded as done **and** `check()` still passes; otherwise it converges. Who does the work:

| # | Stage | Owner | What it does |
|---|---|---|---|
| 1 | `preflight` | installer | Read-only checks (§5.2). Fails with a clear message before anything changes. `install.sh` has already done the bootstrap checks (§5.6). |
| 2 | `packages` | installer | `btrfs-progs`, `nftables`, `ca-certificates`, `dnsmasq-base` (Incus only recommends it, and a managed bridge needs it) |
| 3 | `incus` | installer | Install or adopt Incus (§4.2), `systemctl enable --now incus.socket`, wait for its socket |
| 4 | `release` | installer | Unpack the verified release into `/usr/lib/hx/<version>` and create `current` (§5.6) |
| 5 | `system-files` | installer | sysusers, tmpfiles, logrotate, the rescue helper (§5.5, §5.7) |
| 6 | `credentials` | installer | Seal `pepper.cred` and `identity.cred` with `systemd-creds` (§5.7) |
| 7 | `config` | installer | `gatewayd.toml`, `privd.toml`, unit drop-ins (port, resolvers) |
| 8 | `units` | installer | Install the units, enable and start them |
| 9 | `setup-window` | privd | `BeginSetup`, called by the installer |
| 10 | `host` | privd | `SetupHost`: pool, bridge, ACL, profiles, `inet hx` ruleset, sysctl file, `DOCKER-USER` rules ([ipc.md](ipc.md) §6.4) |
| 11 | `firewall-port` | installer | Open the agent port before pairing (below) |
| 12 | `pairing-token` | installer, gatewayd | `--pair` and `--token` only: install the pairing token through the gatewayd admin socket |
| 13 | `desktop` | privd | `CreateDesktop` ([ipc.md](ipc.md) §6.5) |
| 14 | `verifiers` | installer, gatewayd, privd | Argon2id in the installer, the pepper step through privd's `PepperEnrol`, stored by gatewayd (`SetPasswordVerifier`, `SetPinVerifier`) |
| 15 | `owner-key` | privd | `EnrolOwnerKey` when the app supplied a key (Phase 2 shape) |
| 16 | `backup` | n/a | Phase 2: recorded only, state `deferred` |
| 17 | `pairing` | installer, gatewayd | `--interactive`: `CreatePairingCode` with a 15-minute life, printed with the global addresses, the port and the expiry. `--ssh`: the app's own token, if sent |
| 18 | `finish` | privd, gatewayd | `FinishSetup` and `SetupWindow{close}` |
| 19 | `done` | installer | Mark the install complete |

- **The port is opened before pairing** (stage 11 comes before every pairing step), because in the one-liner path the app must reach the agent before anything else exists. In the `--pair` and `--token` paths the installer **ends after `pairing-token`** (neither carries a password or PIN) (stages 13 to 18 do not run in 1E): the setup window stays open, and the app creates the desktop through gatewayd during `SETUP_OPEN` once the post-pairing setup messages exist (1G; the dependency is noted in execution-phase.md). In the `--ssh` and `--interactive` paths every stage runs, as `Admin`; the token or code is issued **last**, so its 15-minute life starts after the desktop build.
- **How port 443 reaches gatewayd.** A socket unit, `hx-gatewayd-public.socket`, listens on `[::]:<port>` for TCP and UDP (`BindIPv6Only=both`) and hands both sockets to gatewayd by socket activation; the port comes from an installer drop-in (`--port`). The unprivileged gatewayd binds nothing and keeps an empty capability set, no sysctl is changed and no NAT is added ([ipc.md](ipc.md) §6.12).
- **The port rule** (stage 11): if ufw is active, `ufw allow <p>/tcp` and `/udp` with the comment `hash-xcreen`. Otherwise, if native nftables has an input base chain that drops (policy drop, or a drop or reject rule without an interface qualifier, ignoring tables `inet hx`, `inet incus` and Docker's), the rule `meta l4proto { tcp, udp } th dport <p> accept comment "hx-agent-port"` is inserted at the top of that chain, so it is evaluated before the administrator's own rules for that port (a fail2ban or crowdsec drop set on the same port does not apply to it), and re-applied at boot by `hx-agent-port.service` (ordered after `nftables.service`); a ruleset **reload** drops the rule, and the installer says so. The planned rule is recorded in the install state **before** it is inserted, so a partial failure is still removed; uninstall looks for the comment `hx-agent-port` in **every** input-hook chain, not only those that still drop, and with an unreadable state it falls back to that search and warns. A ufw rule that already existed before the install is recorded as adopted and left in place at uninstall. (Security review L4, 1E.) Otherwise, if iptables-legacy or firewalld is blocking, the stage state is `manual`: the exact command is printed and the result carries a warning. Otherwise `none`.
- **Re-runs.** The same command resumes; a complete install is re-verified and drift repaired, and the output says "already installed". Different options are classified by the table in §5.2: reconcilable ones are applied, and a fixed option changed after its stage is done ends with exit 12, naming each option and the command that changes it (`hx-agent desktop limits`, `hx-agent docker enable`, `hx-agent uninstall --destroy-desktop`). Concurrent runs fail with exit 11 (§5.6).
- **State and failures.** One state file, `/var/lib/hx/install-state.json` (§5.7), and one lock shared by install and uninstall. A failure records the stage, a code, a sanitized message and `retryable`; the installer prints `stage 'X' failed: …; run the same command again; completed stages are skipped`, emits a `result` line in `--json` mode (§5.8) and logs tool argv and exit codes, never secrets, to `/var/log/hx-install.log` (0600). **Secrets are never persisted**: a resumed run that needs the password must receive it again.
- **Uninstall.** `hx-agent uninstall` removes everything, asking whether to keep the desktop. It is split between the CLI and privd's narrowed `Uninstall`, because privd's own sandbox cannot remove units, binaries or `/var/lib/hx-gatewayd` (order and rules in [ipc.md](ipc.md) §6.13). Incus and the Zabbly repository stay installed; the CLI says so and prints how to remove the repository. **Keep mode, then reinstall:** `--keep-desktop` leaves the desktop instance, but privd's registry and the session link are removed; the next `hx-agent install` with the same distro, preset and user **adopts** the kept desktop (`CreateDesktop` registers it again, sets the password of that install and re-links the session, [ipc.md](ipc.md) §6.5), so the desktop's data survives an uninstall and reinstall.

### 5.4 Google Drive during setup

The app performs Google OAuth for installed apps (PKCE, loopback redirect) in the user's normal browser, requesting only `drive.file`, and sends the refresh token to the agent over the paired channel, sealed to a key only `hx-privd` holds so that `hx-gatewayd` only relays ciphertext ([ipc.md](ipc.md) §5.2). It can be skipped and connected later. The OAuth client must be **published to production** before release: tokens issued by an app in "Testing" status expire after 7 days.

hash-xcreen ships **one fixed OAuth client** for every install. With `drive.file`, an app sees only the files its own OAuth client created (S4), so "restore onto a new server" works only when the new install uses the same client as the backup; per-user client IDs would break it.

### 5.5 Updates

- Agent: self-update from signed releases on the stable or beta channel, with automatic rollback when the new version fails its health check. The mechanics are in [ipc.md](ipc.md) §6.12; in short:
  - **Release.** A signed manifest (minisign: version, channel, arch, artifact name, size, SHA-256, signing time, minimum previous version) and a `hx-<version>-<arch>.tar.gz` of the agent binaries plus the per-distro `hx-session` packages. The signature is checked against two public keys compiled into `hx-privd` (the current key and the next, §13); a build with no key refuses updates.
  - **Fetch.** `hx-privd` never speaks HTTP. A sandboxed `hx-update-fetcher@<job>.service` (dynamic user, no capabilities, IP sockets only, release hosts only) downloads bytes into a directory privd treats as hostile: read once through a directory descriptor with `openat2`, digest and signature checked over the copy, manifest timestamp never older than the highest seen, version strictly newer than the running one.
  - **Layout.** `/usr/lib/hx/<version>/` per release, with `current` and `previous` symlinks that privd switches atomically (`symlinkat` + `renameat`); the units run `/usr/lib/hx/current/<binary>`; two versions are kept. A `preupdate` snapshot of the desktop is taken first.
  - **Switch and check.** privd records the pending update, switches `current`, answers, restarts gatewayd and re-execs itself (the socket unit keeps the socket). The new process judges within 90 s: privd answers, gatewayd has a stable `MainPID` for 30 s, gatewayd's admin socket answers `Status`. Failure restores the version recorded before the switch (explicitly, never a blind flip) and flags `UPDATE_ROLLED_BACK`; the release is offered again but never re-applied automatically, and Gateway may not re-apply it for 24 h. The fetch directory is a size-capped tmpfs and the fetcher unit denies directory creation, links and renames, so a compromised fetcher can neither fill the disk nor plant what root cannot remove. What the installer and release pipeline owe this mechanism is listed in the privd README ("What 1E must provide").
  - **Rescue.** A new `hx-privd` that cannot start at all (a missing library, a bad ELF) never reaches its own health check, and systemd would retry the same binary. `hx-privd.service` therefore has `OnFailure=hx-privd-rescue.service`, a oneshot that runs `/usr/lib/hx-rescue/hx-privd-rescue`. The helper lives **outside** `/usr/lib/hx`, so pruning never touches it. If an update is `pending`, it restores the recorded previous version and restarts privd, which then rolls back through its normal path and flags `UPDATE_ROLLED_BACK`; with nothing pending it does nothing ([ipc.md](ipc.md) §6.12).
  - **Units are not part of a release.** They are embedded in `hx-agent` and written by the installer (§5.7); a self-update replaces binaries only.
- `hx-session`: pushed into the container by the agent; only the streaming process restarts, user apps keep running.
- The desktop's own packages are the user's responsibility (`apt upgrade`).

### 5.6 Bootstrap and hand-off

`install.sh` is POSIX `sh`, wrapped in `main "$@"` on its last line so a truncated download never runs, and reads no environment variable (curl honours the `*_proxy` variables on its own). It needs `curl`, `openssl` 3 or newer, `sha256sum`, `tar`, `gzip`, `flock`, `base64`, `od` and `dd`. In order:

1. **Bootstrap preflight:** root, `x86_64`, systemd, a supported `os-release`, the tools above, and a self-test of the signature check against embedded known answers (a valid vector must pass, a tampered one must fail; otherwise exit 9).
2. **Lock:** `exec 9>>/run/hx-install.lock; flock -n 9 || exit 11`.
3. **Manifest and signature:** fetched over HTTPS only (or read from `--release-dir`) and verified against the two embedded keys with `openssl` (Ed25519 over the BLAKE2b-512 of the manifest, then the global signature). The exact rules are in [ipc.md](ipc.md) §6.12 ("Installer verification").
4. **Artifact:** downloaded, size and SHA-256 checked, and only `./hx-agent` extracted into a root-only `mktemp -d /var/lib/hx-bootstrap.XXXXXX` (not under `/run`, which Ubuntu and Debian mount `noexec`; found by the first KVM VM run) that also holds the manifest, signature and tarball.
5. **Hand-off:** `exec "$dir/hx-agent" [--json] install --bootstrap-dir "$dir" --lock-fd 9 "$@"`. If `/usr/lib/hx/current/hx-agent` already exists, the download is skipped and that binary is exec'd with `--lock-fd 9`: `install.sh` never upgrades or downgrades an installed agent, because updates go through privd.

`hx-agent install` takes the handed-over lock after checking that the descriptor is the regular, root-owned `/run/hx-install.lock` (without `--lock-fd` it opens and locks the file itself). Given `--bootstrap-dir` (a root-only directory, not a symlink, files opened `O_NOFOLLOW`), it **verifies everything again** with the keys compiled into the agent (signature, manifest fields, size, SHA-256, and `version == CARGO_PKG_VERSION`), reusing privd's own update code (`privd::update::{keys, manifest, extract}` and `switch::Layout`): it unpacks into `/usr/lib/hx/.incoming-*`, renames to `/usr/lib/hx/<version>`, creates the relative `current` link (there is no `previous` yet) and removes the bootstrap directory. The first install thus uses the same verification and extraction as an update. The shell script is only the first, replaceable link in the chain.

### 5.7 Installer state, files and credentials

```json
{"schema":1,"install_id":"…","agent_version":"…","mode":"ssh|pair|token|interactive",
 "options":{"…":"normalized §5.2 values, no secrets"},"server_public_key":"…",
 "stages":{"<id>":{"state":"done|failed|deferred|manual","at":0,
                   "error":{"code":"…","message":"…","retryable":true}}},
 "created":{"files":[],"dropins":[],"packages":[],
            "incus":{"by_installer":true,"source":"distro|zabbly","version":"…"},
            "apt":["/etc/apt/keyrings/hx-zabbly.asc","/etc/apt/sources.list.d/hx-zabbly-incus.sources"],
            "port_rule":{"backend":"ufw|nft|manual|none","port":443},"user":true},
 "complete":false,"updated_unix":0}
```

The file is root 0600, written atomically (`privd::state::write_atomic`). The installer never writes privd's own state files, and uninstall needs `created` to know what the installer made. A separate resume file for uninstall, `/var/lib/hx-uninstall.json`, lives outside `/var/lib/hx` because uninstall removes that directory.

**Where the installer puts things** (the full list of paths is in [ipc.md](ipc.md) §2):

- Units: `/usr/local/lib/systemd/system/`, outside the namespace dpkg manages. Installer drop-ins: `/etc/systemd/system/<unit>.d/50-hx-*.conf`, plus `hx-update-fetcher@.service.d/resolvers.conf`.
- `/usr/local/lib/sysusers.d/hx-gatewayd.conf`, `/usr/local/lib/tmpfiles.d/hx.conf`, `/etc/logrotate.d/hx-audit`, `/usr/lib/hx-rescue/hx-privd-rescue`.
- The units are embedded in `hx-agent` with `include_str!`; a test asserts that every file under `apps/hx-agent/systemd/` is embedded.
- **Not installed by the installer:** `hx-session`'s own units. They stay in the desktop recipe (`recipes/fragments/xfce-desktop.toml`) and reach the container with the rest of the recipe; the `hx-session` `.deb` carries binaries only (§13).

**Done-checks** (what `check()` verifies before a recorded stage is skipped):

| Stage | Done when |
|---|---|
| `packages` | `dpkg-query` reports the packages installed |
| `release` | `current` resolves to a complete directory whose `VERSION` equals the agent's version |
| `system-files`, `config` | content hashes equal |
| `credentials` | both `.cred` files exist and decrypt to 32 bytes (decrypted into a pipe that is read and zeroized), and no `pepper.key` remains |
| `units` | `is-enabled`, `is-active`, and privd answers `Hello` and `GetHostInfo` |
| `incus` | the version reported by `GetHostInfo` |
| `setup-window`, `host` | always called (they converge), then `GetHostInfo` (`pool`, `host_firewall_loaded`, `sysctl_ok`) |
| `desktop` | `GetDesktop` reports `ready` |
| `pairing-token`, `pairing`, `finish` | never skipped on resume: a code or token must be fresh, so a re-run of `--pair` asks for a new token |

**Credentials.** The installer generates each secret with `getrandom`, pipes it to `systemd-creds encrypt --name=<name> - <tmp>` and renames the result to 0600; `pepper.cred` and `identity.cred` are made this way, so every supported host has sealed credentials. A host that ran privd on the plaintext `/var/lib/hx/pepper.key` fallback is **migrated without invalidating its verifiers**:

1. `PepperEnrol(PIN, a fixed test input)` as Admin gives `mac1`.
2. `systemd-creds encrypt --name=pepper /var/lib/hx/pepper.key …` seals the existing key.
3. privd is restarted.
4. `PepperEnrol` again gives `mac2`.
5. If they are equal, `pepper.key` is overwritten with zeros, synced and unlinked. If not, the new `.cred` is removed, the key is kept and the stage fails.

If both files exist and the decrypted value equals the key, the key is deleted; if it differs, the key is renamed `pepper.key.orphaned-<ts>` with a warning.

**Resolvers drop-in.** The update fetcher's kernel egress filter denies local and private ranges ([ipc.md](ipc.md) §6.12), and `IPAddressAllow=` cannot be limited to a port, so an allowed address is open to the fetcher on every port. For every `nameserver` in `/etc/resolv.conf`, other than 127.0.0.53 and 127.0.0.54 (already allowed by the unit), that falls inside a **private** range (RFC 1918, `100.64.0.0/10`, `fc00::/7`), the installer writes `IPAddressAllow=<addr>/32` (or `/128`) into `hx-update-fetcher@.service.d/resolvers.conf`, and removes the drop-in when the list is empty; the accepted cost is that a compromised fetcher can reach that resolver host on any port. It **never** allows loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`, which includes the cloud metadata service at 169.254.169.254 used as a resolver on Google Cloud and Oracle Cloud) or multicast: such a nameserver is skipped with a warning that updates need systemd-resolved (whose stub forwards to it) or a private resolver. The install does not fail. (Security review M2, 1E.)

### 5.8 Machine-readable progress

With the global `--json`, stdout carries only JSON Lines; human text goes to stderr, and every string is sanitized with `hx_ipc::text::sanitize_text`.

```
{"v":1,"t":"stage","id":"<stage-id>","n":7,"of":19,"state":"start|done|skip|fail|deferred|manual","ms":123}
{"v":1,"t":"step","id":"desktop","privd_stage":"BUILD","index":3,"total":12,"step":"…","percent":255}
{"v":1,"t":"warn","id":"<stage-id>","message":"…"}
{"v":1,"t":"result","ok":true,"exit":0,"install_id":"<32 hex>","agent_version":"x.y.z",
 "server_public_key":"<64 hex Ed25519>","addresses":["…"],"port":443,
 "desktop":{"id":"main","path_taken":"BUILD","reason":"…","warnings":["…"]},
 "pairing":{"kind":"code|token|none","expires_at_unix_s":0},"port_rule":"ufw|nft|manual|none"}
{"v":1,"t":"result","ok":false,"exit":1,"stage":"incus","code":"UNAVAILABLE|TOOL|VERIFY|PREFLIGHT|…","message":"…","retryable":true}
```

- A `step` line is a privd `Progress` frame relayed one to one ([ipc.md](ipc.md) §4); `percent` 255 means unknown.
- `install.sh` emits `stage` lines with the ids `bootstrap-preflight`, `bootstrap-download` and `bootstrap-verify`, built from constant strings only.
- `server_public_key` is derived when the identity seed is generated and kept in the state file. It lets the SSH app cross-check, over the SSH-authenticated channel, the key it will pin while pairing.

## 6. Streaming

### 6.1 Capture (`hx-capture`)

One trait, one backend per display stack:

- **X11** (v1, XFCE; later MATE and Cinnamon): headless Xorg with the dummy driver; XDamage for changed regions; XShm for copy-free reads; XTest for input; RandR for resizing to the client window.
- **KDE Plasma** (later): KWin virtual output, screencast through PipeWire, libei for input.
- **GNOME** (later): Mutter headless mode with its RemoteDesktop and ScreenCast D-Bus APIs.

No damage means no capture, no encode and no traffic.

### 6.2 Encode (`hx-codec`)

- All encoders through libavcodec, so one code path covers them.
- Software default: **x264** with `ultrafast`, `zerolatency`, `crf=23`, a VBV of a few frames (a tunable; S2 used one frame, and 2–4 is the provisional default until a worst-frame test settles it), a bitrate ladder up to 20 Mbps, sliced threads equal to the number of encode cores (4 on a 4 vCPU server; one thread added 3.5–7 ms at p95), `keyint=120`, gradual intra refresh, and IDR frames only on connect and resync. In S2 this encoded in 4–8 ms (p50) and used 0.45–0.75 cores at 1080p. Intra refresh had no latency cost on the VPS and saved bitrate in scrolling but cost it elsewhere; it stays on until it is measured on a lossy link. x264 is allowed because the project is AGPL.
- **Colour tags:** the stream always carries BT.709 limited-range VUI tags (`colorprim`, `transfer`, `colormatrix` = bt709, `fullrange=off`). Untagged, a client has to guess, and in S2 reading the same frames as BT.601 cost 10 dB and as full range 10–25 dB.
- **Pacing:** capture as soon as the pipeline is free after damage arrives; 60 fps is a ceiling, not a clock. Holding damage to a fixed 60 fps grid added 5–13 ms at p95 in S2 locally and 7–14 ms on the VPS, so relaxed pacing is required.
- **Known quality gap:** the first frame after a large change (scroll reversal, window drag) can be visibly blocky (15–24 dB) because it hits the VBV budget; a larger VBV did not fix it. Sharp-text refinement (below) and per-frame QP control are the planned fixes.
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
- Clipboard: both directions for text, images and files; can be switched off per paired device. X11 side: XFixes owner notifications, `TARGETS` probed lazily, data read only when the other side asks, `INCR` both ways, 64 MiB limit, text must be UTF-8 and images PNG, PRIMARY off by default. Files are a transfer list (validated names, sizes, race-safe open); client files are staged in a session-owned 0700 directory when a local application pastes, and the paste receives `file://` URIs (also as `x-special/gnome-copied-files`).
- Files: copy and paste or drag and drop; each transfer on its own low-priority stream with progress.

### 6.5 Clients

- **Desktop (Slint)** **(provisional until the S1 GPU run)**: libavcodec hardware decode (VAAPI on Linux), exported as a DMA-BUF, imported as an EGL image into an OpenGL texture, and shown with Slint's stable borrowed-OpenGL-texture API, with no CPU copy. This is the route mpv and other FFmpeg-based players use.
  - Fallback: copy each frame into a Slint pixel buffer (software decode costs about 0.5 core at 1080p60, plus about 0.3 core for colour conversion).
  - The wgpu route stays an option, but depends on an unstable Slint feature tied to a wgpu major version and on unsafe Vulkan import code.
  - Copy-free display needs an EGL context. Slint's winit backend creates one on Wayland but a GLX context on X11, so X11 needs a custom Slint platform that creates its own EGL context.
  - Decoded colour must use the stream's colour space and range, not a fixed BT.709 assumption, and frame hand-off needs explicit GPU fences rather than `glFinish`.
- **Web**: WebCodecs hardware decode into a WebGL/WebGPU canvas; Pointer Lock and Keyboard Lock; protocol code shared as WASM.
- Keyboard input is sent as physical scancodes so every layout works. The session maps HID usage → evdev → X keycode (`+ 8`) and injects through XTest; held keys and buttons are released on focus loss, disconnect and drop, pointer coordinates are clamped to the screen, scroll arrives in 1/120 notches and becomes wheel clicks, and untrusted input is rate-limited (key/button/scroll and pointer motion separately; releases exempt).
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
- **Implemented (`apps/hx-session::congestion`, pure logic):** queueing excess = ack delay minus a 10 s windowed minimum minus the frame's time at the target rate; the controller reacts to the median of the last 9 acks and to a stall term (time since the later of the oldest unacked send and the last ack), so one retransmission behind a healthy stream is not congestion. Thresholds scale with a smoothed jitter estimate (step down at 30 ms + 4 × jitter, at most 120 ms; stale at 100 ms + 3 × jitter, at most 300 ms). Ladder 0.5 to 20 Mbps (to the cap when higher), start at 4 Mbps; a step down jumps below the measured delivery rate when the link, not the source, was the limit; failed levels back off 0.5 s doubling to 4 s; recovery climbs 1–2 steps per 150 ms back to the proven level, then probes slowly and only when at least 40 % of the rate is in use. The fps ceiling follows the rate (about 30 kbit per frame, 10–60). Stale: every unacked frame is cancelled, two levels down, an IDR is requested, frames encoded before it are dropped unsent and the IDR is flagged `RESYNC`.

### 7.5 Versioning

- The hello exchange carries protocol `major.minor` plus capability flags (codecs, features).
- Different major: refuse with an "update required" message. Different minor: disable newer features.
- The agent supports the current and previous protocol major. The web client always matches its agent.

## 8. Security

### 8.1 Threat model

| Attacker | Defence |
|---|---|
| Internet scanners, network attackers | Unpaired peers can only attempt pairing while a token or code is valid. An unknown key still completes the TLS 1.3 handshake (the server accepts any well-formed Ed25519 client key, protocol §11.1) and is refused at the application's `PendingSession` step, after the `Hello` and a registry lookup. That keeps the refusal reasons precise but widens the pre-authentication surface to TLS, the `Hello` parser and the registry lookup, all bounded by the transport's per-address and global limits and all targets for the 1H fuzzers. Pre-auth parsers are fuzzed. |
| Someone who sees the one-liner | Token is single-use and expires after 15 minutes. |
| Stolen client device | Device key alone is not enough: the server checks the PIN, revoking the device after 5 failures. Devices can be revoked from any other device or the CLI. |
| Malware inside the desktop | Unprivileged container; `hx-session` holds no secrets; the agent treats all container input as untrusted; metadata endpoint and agent ports blocked. |
| Google or a compromised Google account | Backups are encrypted and authenticated before upload. |
| Tampered installer or update | minisign signatures verified against embedded keys: by `install.sh` with `openssl`, then again by `hx-agent install` and later by `hx-privd` (§5.6). Build provenance attestations are for audit only: no server verifies them, because a host has no `gh` or Sigstore client. |

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
- With no domain: a Let's Encrypt short-lived certificate for the server's IP addresses (`shortlived` profile, 160 hours, validated by `http-01` on TCP 80), issued with `instant-acme`. S5 issued and renewed real ones for IPv4 and IPv6 in 6.5–7.4 s, and Chrome and Firefox used them for WebTransport over the internet.
  - The CSR has an empty subject (Let's Encrypt rejects a common name for IP certificates).
  - Renewal follows ACME Renewal Information (about half the lifetime, so roughly every 3 days) with `replaces`, backs off on errors, and keeps the previous certificate until the new one is live. A fallback timer renews well inside 160 hours. Let's Encrypt's duplicate-certificate limits make a retry loop dangerous.
  - The certificate is **hot-reloaded** into the QUIC endpoint, HTTPS and WebSocket listeners without dropping sessions.
  - Port 80 must be reachable from several vantage points; where the provider blocks it, the self-signed fallback below is used.
  - Chrome rejects WebTransport to an **IPv6 address literal** with a CA certificate that it accepts over TCP (Chrome 158; cause unknown). IPv6-only servers therefore use the WebSocket fallback in Chrome.
- Fallback: a self-signed ECDSA P-256 certificate valid for under 14 days, pinned by the page through WebTransport's `serverCertificateHashes` (works in Chrome and Firefox, S5). Rotation needs an overlap window offering two hashes. Because the browser won't trust that certificate for loading the page itself, this fallback needs the web client served from a trusted HTTPS origin (for example the project's GitHub Pages), which then connects to the server by IP and pins the hash it got from the desktop app.

### 8.5 Privilege separation

- `hx-gatewayd` runs unprivileged with systemd hardening (`NoNewPrivileges`, `ProtectSystem=strict`, private tmp, capability bounding) and a seccomp allowlist.
- `hx-privd` accepts only a fixed set of typed commands over a unix socket (`/run/hx/privd.sock`, root:`hx-gatewayd` 0660). The peer is authenticated with `SO_PEERCRED`: only the `hx-gatewayd` uid and root are served, and the role follows from the uid. Every instance, path, device and URL is chosen by privd, never by the caller; desktop and host setup from `hx-gatewayd` is accepted only while a root-opened setup window is open; privileged options (a pool device, private-network access, offline images, uninstall, enabling Docker after setup, updates to an unverified version) are root-only. privd and root tools never open paths inside a directory that `hx-gatewayd` can write. The full command set, the refusal rules and the limits are in [ipc.md](ipc.md) Part 1, and they implement the caller obligations in `crates/hx-provision/README.md`.
- `hx-gatewayd` reaches `hx-session` through one Incus proxy device per desktop that privd adds: a unix socket on the host that only `hx-gatewayd` can use, connected to a systemd-created socket in a root-owned directory inside the container that only the desktop user can use. It is a byte pipe: no descriptor passing, no secrets, and everything `hx-session` sends is parsed by `hx-gatewayd` as untrusted input with explicit limits ([ipc.md](ipc.md) Part 2).
- The device registry (paired devices, revocation state, PIN and password verifiers and failure counters) belongs to `hx-gatewayd` and is administered by the CLI through gatewayd's admin socket; it holds nothing that grants root, and the verifiers are peppered with a key only `hx-privd` holds, so they can only be guessed online, through failure-capped verification in privd ([ipc.md](ipc.md) §5.3).
- The host reads container files only through the Incus API, never by following paths into the container filesystem.

### 8.6 Secrets on the server

- Drive refresh token, backup repository key, agent identity key and the ACME account key are stored root-only, outside the container, sealed with `systemd-creds` (TPM-backed where available).
- `hx-gatewayd` cannot read the Drive token or backup key. Where a client must hand one to the server, it is sealed to `hx-privd`'s key and authenticated by an owner key that privd enrols outside gatewayd's control, so gatewayd relays only ciphertext and cannot substitute its own ([ipc.md](ipc.md) §5.2; in the SSH install path the secrets go to the root installer directly).
- A gatewayd compromise that stays in memory can add devices to the registry; the identity-key rotation and re-pinning procedure is in [ipc.md](ipc.md) §2.1.
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

S4 sizes (synthetic data): a 2.24 GB desktop became a 906 MB repository locally; on real Google Drive a 2.44 GB desktop became 1.0 GB, uploaded in 125 s, and a simulated day of use added 98 MB in 28 s.

The Drive backend is hash-xcreen's own wrapper over OpenDAL's `gdrive` service (S4's `HxDrive`). It owns every retry decision (OpenDAL's retry layer is off), passes listing errors up instead of dropping them, bounds every request with a timeout (60 s plus 4 s per MiB), and creates the repository's 256 `data/xx` folders lazily, when a pack is first written to them, instead of at `init` (534 API calls). The worker never holds Google credentials: `hx-privd` gives it a repository handle, as S4's REST bridge did.
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
| Network errors, Google 5xx, 408, 405, rate limiting (429, 403 `rateLimitExceeded` / `userRateLimitExceeded`) | Retry with exponential backoff (1 s doubling to 64 s, equal jitter, `Retry-After` honoured), at most 8 retries, then fail the run and reschedule. Content addressing means only missing data is uploaded on retry. Each pack is one multipart upload, so an interrupted upload resumes per pack, not mid-pack (a killed upload leaves no partial object on Drive). Tested by fault injection on real Drive; real rate-limit replies have not been seen yet, so the nightly Drive test records every non-2xx reply to confirm the classifier. |
| Daily upload limit (750 GB per account), 403 `dailyLimitExceeded` | A gate shared by all upload threads pauses for an hour and probes again, for up to about a day. |
| Drive storage quota exceeded | No retry; "Drive full" handling (9.7). |
| Token revoked or expired | Stop; mark "Action needed: reconnect Google Drive". |
| Server disk too full for a snapshot | Do not start; notify. |
| Agent crash mid-run | On start-up, remove tagged leftover snapshots and stale repository locks; retry. |
| No success for twice the interval | Red badge in the app regardless of cause. |

### 9.7 Quota, retention and verification

- Free Google storage (15 GB) is shared with Gmail and Photos. The wizard estimates the first backup and typical increments before enabling backups.
- Before each run, compare free Drive space with the estimated new data. Free space comes from Drive's `about.storageQuota`, which counts the trash, not from the sum of the repository's pack sizes. Warnings at 80% and 95%.
- **Deleting on Drive is permanent.** A Drive delete through OpenDAL only moves the file to the trash, which still counts against the quota (S4: 2.8 GB pruned, quota unchanged). hash-xcreen's backend therefore ends every removal with `DELETE files/{id}` on its own files, which `drive.file` allows. It never calls `files.emptyTrash`, which would delete the user's other trashed files. Folders are deleted leaves first: Drive refuses a recursive delete of a folder with children (403 `appNotAuthorizedToChild`).
- Pruning uses `--instant`; otherwise rustic keeps removed packs for 23 hours.
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
6. Restore details found in S4: keep numeric owner IDs; restore sparse files as sparse; recreate the mount-point directories that backups skip (`/proc`, `/sys`, `/dev`, `/run`, `/tmp`); on a new server, generate a new hostname and `/etc/machine-id`, which otherwise stay identical to the original's. S4 restored 81,065 entries locally and 81,070 from real Google Drive with 0 differences in contents, owners, permissions, extended attributes or hard links, and an interrupted restore resumed by restoring only the missing files. The same 1.06 GB restore from Drive took 367 s once and 19 s the next time, with no error or retry logged, so the app shows restore progress by bytes and never promises a duration.
7. **Isolated idmaps (Phase 2 note):** desktops use `security.idmap.isolated=true`, so each desktop has its own uid/gid range on the host and the owner ids visible on the host are shifted. Backups must be read through the idmapped mount (as S4 did, so ids inside the archive are the container's own), and a restore must write into the new container through Incus (its own idmap), never as a plain file copy of host ids, or ownership will be wrong.
8. **Restore onto a new server**: the app signs in to Drive, the user picks a backup and enters the recovery key, and the installer restores instead of creating a fresh desktop.

### 9.9 Alerts

In-app badges and desktop notifications, plus optional server-side alerts in v1: **ntfy** push and **webhooks**. Email (SMTP) later.

## 10. Performance targets

| Metric | Target (1080p60, 4 vCPU, no GPU) |
|---|---|
| Added latency (LAN, p95) | ≤ 40 ms; expected 15–25 ms |
| Encode CPU while typing or scrolling | ≤ 1.5 cores |
| Idle desktop | ~0% CPU, ~0 bandwidth |

Latency budget: capture ≤ 2 ms, colour conversion 1–2 ms, encode 4–8 ms, send < 1 ms, hardware decode 2–4 ms, present 0–8 ms.

S2 measured on a quiet 4 vCPU VPS (damage to decode complete, p95, presentation excluded, 3 repeats, relaxed pacing):

| Scenario | Same host (LAN) | Over the internet (14 ms RTT) | Server cores |
|---|---|---|---|
| Typing | 10.7 ms | 24.8 ms | 0.45–0.49 |
| Scrolling | 13.9 ms | 21.6 ms | 0.47–0.49 |
| Window drag | 11.7 ms | 20.4 ms | 0.69–0.75 |
| Video | 16.5 ms | 23.8 ms | 0.54–0.64 |
| Idle | 0 frames | 1–2 tiny frames per 30 s | 0.01–0.02 |

Over the internet, about 8 ms of the total is the network (half the round trip). Decoded frames matched the source at 47 dB PSNR while typing (text fully legible), 34–44 dB in the moving scenarios. The 40 ms target needs CPU headroom: in the first local run on a heavily shared host, scrolling and dragging reached 37–61 ms at p95. Not yet measured on a lossy real link: on the VPS, `tc netem` had no effect through the Incus proxy device used.

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
| Installer | CI: a fresh Incus VM per host OS (KVM on GitHub runners) running the real `install.sh --release-dir` with a per-run test key, for the `build` image path in 1E (`prebuilt` cells assert the clean refusal until 1D's image CI lands), plus a reboot, canary scans for the password, PIN and token in `/proc` and the journal, failure injection with resume, and uninstall in both modes. Locally: a nested-Incus harness (an unprivileged container with its own Incus, every object named `hx1e-*`) that covers the units, credentials, firewall rules in the container's own network namespace, pairing, resume, lock contention, the rescue path and uninstall, but not desktop creation, TPM sealing or real reboots. Both use only compile-time test hooks (`install-test-hooks`, `privd-test-hooks`, `test-release-key`), which the release gate forbids in release builds (§13) |
| Backup | In-memory/local backend on every PR; real Google Drive test account nightly, including the chat-app history restore test |
| Streaming end to end | Agent + desktop container + headless test client under `tc netem` profiles |
| UI | Slint testing backend and screenshot comparisons; Playwright for the web client (Chromium, Firefox) |
| Performance | Dedicated runner; scenario suite (idle, typing, scrolling, video, window drag); regressions fail the build |
| Upgrade | Previous release → new release: old backups restore; old client ↔ new agent and new client ↔ old agent connect |
| Failure | Kill agent mid-backup, network loss mid-restore, full disk, revoked token |

## 13. Releases

- One semver version for all components; protocol version separate.
- Channels: stable and beta; nightly builds for testers.
- `hx-agent`: static musl binaries in one release tarball, **no `.deb`** in v1 (dpkg would own files that privd rewrites in `/usr/lib/hx`). `hx-session`: one `.deb` per guest distro, carried inside that tarball. Desktop app: `.deb` and AppImage (Flatpak later). Desktop images: weekly, signed.
- Conventional commits and `git-cliff` for changelogs; `--locked` builds. A release is built by `.github/workflows/release.yml` on tags `v*` (the version rule of [ipc.md](ipc.md) §6.12), not by `dist`: its archive layouts and installers and its lack of a signed manifest conflict with §5.5.
- minisign signing: **both** the current and the next public key are required for a release and are embedded in `install.sh` and in `hx-agent` (`apps/hx-agent/release-keys/{current,next}.pub`, `UNPROVISIONED` until the maintainer supplies them). The secret key lives in the protected GitHub environment `release-signing` (manual approval per run, secrets `MINISIGN_SECRET_KEY` and `MINISIGN_KEY_PASSWORD`); no agent generates or sees it. GitHub build provenance attestations.

**Release pipeline** (jobs, in order):

1. `gate`: the tag equals `v` plus the workspace version; both key files are provisioned and parse; the keys embedded in `install.sh` equal those files (also a normal CI test); `cargo deny` and `cargo audit`; the `release-build` feature is on and cannot be combined with `test-support`, `test-release-key` or the other test-hook features (a compile-time assertion that `CURRENT` is not `UNPROVISIONED`).
2. `agent`: `cargo build -p hx-agent --bins --release --locked --target x86_64-unknown-linux-musl --features release-build` (never `--workspace`), then a check that every output is statically linked. All binaries are bins of one crate, so they share one version by construction.
3. `session`: a matrix over `ubuntu:24.04`, `ubuntu:26.04`, `debian:12` and `debian:13` job containers builds `hx-session` and `hx-pwcheck` against that distro's FFmpeg, assembles the `.deb`, computes `Depends` with `dpkg-shlibdeps`, asserts the expected `libavcodec`/`libavutil` packages are listed, and smoke-tests `apt-get install ./hx-session.deb` followed by `ldd` showing no unresolved library.
4. `assemble`: the deterministic ustar tarball and the canonical manifest ([ipc.md](ipc.md) §6.12), at most 256 MiB.
5. `sign` (environment `release-signing`): a prehashed signature over `manifest-x86_64.json` with the trusted comment `hx-manifest v<ver> channel=<c> arch=x86_64`, and one over `install.sh` for manual checks; then `install.sh`'s own verification function must accept the result, which proves the shipped script accepts the shipped signature.
6. `attest`: `actions/attest-build-provenance` for the tarball, the `.deb`s, the manifest and `install.sh` (audit only, §8.1).
7. `publish`: first the release `v<ver>` with the tarball, `install.sh` and the signatures; then, with `--clobber`, the manifest, its signature and `install.sh` on the moving release `channel-stable` (or `channel-beta` for `-alpha`, `-beta` and `-rc` versions). The version release goes first so a manifest never points at a missing artifact. The one-liner URL (§5.1) is the `channel-stable` copy of `install.sh`, on a host the update fetcher already allows.

**The `hx-session` package** (`packaging/hx-session/`): package `hx-session`, architecture `amd64`, version equal to the release version with `-` replaced by `~` (so `1.4.2~rc.1` sorts before `1.4.2`). It holds `/usr/lib/hx-session/{hx-session,hx-pwcheck}` (0755), `/usr/share/doc/hx-session/copyright`, **no units and no maintainer scripts**, and `Depends` computed by `dpkg-shlibdeps` plus `libc6`, `libgcc-s1` and `libcrypt1`. Expected FFmpeg dependencies: Ubuntu 24.04 `libavcodec60` and `libavutil58` (verified in the spike); Debian 12 `libavcodec59` and `libavutil57`; Debian 13 `libavcodec61` and `libavutil59` (both from memory); Ubuntu 26.04 `libavcodec61`/`libavutil59` or `libavcodec62`/`libavutil60`, **to be verified** (FFmpeg 8 needs a newer `ffmpeg-next`, tech-stack.md). Because privd installs the package with `dpkg -i`, which resolves no dependencies, the desktop recipes must pre-install the FFmpeg runtime libraries per distro (a recipe variable such as `ffmpeg_runtime`, owned by the release packaging work), and CI checks that the variable covers the `.deb`'s `Depends`.
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
| x264 1080p60 within the CPU and latency budget on 4 vCPU | Confirmed on a quiet VPS, same host and over the internet (S2); behaviour on a lossy real link still to measure |
| XFCE fits the 2 vCPU / 4 GB minimum | Confirmed on a VPS (S3); a real 4 GB server and Ubuntu 24.04 / Debian 13 hosts still untested |
| Docker nested in the desktop | Works on Incus 6.0.5 (S3 VPS), fails on 6.0.0; installer self-test with fallbacks (4.3) |
| Full-desktop backup and restore with `rustic_core` | Confirmed locally and on real Google Drive (S4) |
| OpenDAL's Google Drive backend, `drive.file` scope, rate limits | `drive.file` confirmed on real Drive; wrapper tested by fault injection; real rate-limit replies, packs ≥ 128 MB, slow uplinks and token revocation still unseen (S4) |
| WebTransport and native QUIC on one port | Confirmed, including over the internet (S5) |
| Let's Encrypt IP-address certificates | Confirmed: issued and renewed in production (S5); Chrome fails to IPv6 literals |
| Safari WebTransport | Open: needs a Mac (Phase 3); WebSocket fallback meanwhile |
| Process control inside the desktop | On the VPS kernel, processes started by one `incus exec` could not be signalled from another (AppArmor). `hx-session` must own the processes it manages (S2) |
| Google OAuth app verification for `drive.file` stays light | Release checklist |
