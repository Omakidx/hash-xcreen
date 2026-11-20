# Spike S3: Incus desktop on a VPS

Status: local run complete (2026-11-20); **real-VPS run complete (2026-11-20), see section 15**, which supersedes the Docker FAIL and the UNVERIFIED items of sections 7, 10, 11 and 13. Branches `spike/s3-incus-desktop` and `spike/s3-vps-run`. Code and raw logs: [spikes/s3-incus-desktop/](../../spikes/s3-incus-desktop/).

## 1. Goal

Confirm that an XFCE desktop fits the minimum server (2 vCPU, 4 GB) inside an **unprivileged Incus system container**, that Docker works nested inside it, that the prebuilt-image and build-on-server paths both meet their time limits, and settle the recipe format, pool defaults and network-isolation approach. Pass criteria from [execution-phase.md](../execution-phase.md):

- Desktop idle with at least 1.5 GB RAM free on 2 vCPU / 4 GB.
- Docker `hello-world` runs nested.
- Prebuilt path under 5 min; build path under 20 min.

**Deviation from the plan.** Real VPSs were replaced, by the user's choice, with local containers capped by cgroup limits (`limits.cpu`, `limits.memory`) at 2 vCPU / 4 GB and 4 vCPU / 8 GB. Everything that depends on a real server's disk, network, CPU steal or host overhead is marked UNVERIFIED and is covered by `run-on-vps.sh` (section 10).

## 2. Setup

| Item | Value |
|---|---|
| Host | Ubuntu 24.04 VM, kernel 6.8.0-151, 16 cores, 62 GB RAM, no KVM, no sudo (Incus access through the `incus-admin` group) |
| Incus | 6.0.0 (client and server), Ubuntu 24.04 package |
| Pool | `default`, btrfs on a 60 GB **loop file** (`/var/lib/incus/disks/default.img`), shared with other agents' containers |
| Network | `incusbr0` (NAT). IPv4 egress from containers did not work on this host (likely the host's Docker `FORWARD` policy, not verifiable without root); **IPv6 egress worked**, so every download below went over IPv6 |
| Guests | `images:ubuntu/24.04`, `images:debian/13` |
| Limits | 2 vCPU / 4 GiB and 4 vCPU / 8 GiB via cgroup limits; the host stayed at 16 cores |
| Load | The machine was shared with other agents. `/proc/loadavg` is recorded with every timing; it ranged from 4 to 37 |
| Tools | `hx-recipe` runner (Rust 1.100.0, spike code), shell scripts in the spike directory |

## 3. Recipe format

One TOML document per distro x desktop x preset, assembled from **fragments** with `include` and extended with **add-ons**. The runner merges them (tables merge recursively, arrays concatenate in order, later scalars win), substitutes `{{var}}` in every string, then applies the stages in a fixed order. The same merged recipe drives both paths:

- **Build on the server / image build:** `hx-recipe apply <recipe> <container> [--addon docker.toml]` runs everything. CI publishes the container with `incus publish`.
- **Prebuilt import:** `hx-recipe post <recipe> <container>` runs only the post stage (user exists, password from `HX_PASSWORD`, security updates, `post_step`s). The password never enters a recipe or an image.

Stage order of `apply`: `incus_config` (then restart) -> wait for network -> apt bootstrap -> `apt_repo` (key fingerprint is checked, the run fails on mismatch) -> `pre_step` -> `apt.packages` -> `user` -> `file` -> `services` -> `step`.

| Section | Meaning |
|---|---|
| `[recipe]` | `name`, `base_image` |
| `[vars]` | Substitution variables (`distro`, `codename`, `preset`; `user` is implicit) |
| `[incus_config]` | Instance config keys set before install (Docker add-on: nesting, syscall interception) |
| `[[apt_repo]]` | `name`, `key_url`, `key_fingerprint`, `uri`, `suite`, `components`, optional `pin` |
| `[apt] packages` | Installed with `--no-install-recommends` |
| `[user]` | `name`, `uid`, `shell`, `groups` (concatenated across fragments), `linger` |
| `[[file]]` | `path`, `mode`, `owner`, inline `content` (pushed with `incus file push`) |
| `[services]` | `system_enable`, `user_enable_global` (systemd units) |
| `[[pre_step]]`, `[[step]]`, `[[post_step]]` | Shell snippets with `name`, `enabled`, `as_user`. `post_step` runs only in the post stage |

Layout (`spikes/s3-incus-desktop/`): `fragments/xfce-desktop.toml` (headless Xorg, XFCE session, PipeWire, cleanup), `fragments/distro-{ubuntu-24.04,debian-13}.toml`, `fragments/preset-{basic,developer}.toml`, `addons/docker.toml`, and four recipes that only list includes:

```toml
# recipes/debian-13-xfce-developer.toml
include = [
  "../fragments/xfce-desktop.toml",
  "../fragments/distro-debian-13.toml",
  "../fragments/preset-developer.toml",
]

[recipe]
name = "debian-13-xfce-developer"
```

```toml
# addons/docker.toml (excerpt)
[incus_config]
"security.nesting" = "true"
"security.syscalls.intercept.mknod" = "true"
"security.syscalls.intercept.setxattr" = "true"

[[apt_repo]]
name = "docker"
key_url = "https://download.docker.com/linux/{{distro}}/gpg"
key_fingerprint = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
uri = "https://download.docker.com/linux/{{distro}}"
suite = "{{codename}}"
components = "stable"

[apt]
packages = ["docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"]

[user]
groups = ["docker"]
```

How the desktop is wired (all from the recipe): `hx-xorg.service` (system) runs `Xorg :0` with the `dummy` driver at 1920x1080, `-nolisten tcp`, and an Xauthority cookie owned by the desktop user. `hx-session.service` (systemd **user** unit, enabled globally, user lingering) runs `xfce4-session` once the X socket exists. PipeWire, `pipewire-pulse` and WirePlumber are enabled as user units; a null sink (`hx-sink`) is configured so there is always something to capture. No display manager.

Recipe decisions worth keeping:

- Ubuntu's `firefox` is a snap shim. The recipe uses the Mozilla Team PPA (a real deb). The official `packages.mozilla.org` repo is better long term but is IPv4-only and could not be reached from this host; **switch back on real servers if preferred** (the fragment is the only place to change).
- Key fingerprints are pinned in the recipe (Docker, Microsoft, Mozilla Team PPA); keys are downloaded at build time and verified, not committed.
- Claude Code and Codex CLI are present as **disabled** `post_step`s (`enabled = false`). They were not installed in this spike.

## 4. Results: build on the server

Base image cached unless stated; `apply` at 2 vCPU / 4 GiB, timer from `incus launch` to the end of the last stage. Debian's first (cold) base-image download was 6.6 s for 100 MiB.

| Distro | Preset | Total | apt bootstrap | apt install | Host load avg at start / end | Note |
|---|---|---|---|---|---|---|
| Ubuntu 24.04 | basic | 520 s | 50 s | 459 s | 25.5 / 34.2 | **Contaminated** by other agents' load |
| Debian 13 | basic | 213 s | 76 s | 132 s | 4.6 / 4.9 | |
| Ubuntu 24.04 | developer | 307 s | 35 s | 260 s | 3.6 / 9.6 | |
| Debian 13 | developer | 308 s | n/a | 255 s | 8.6 / 7.3 | |

Every build produced a working desktop on first boot (screenshot below). Installed sizes: Ubuntu developer rootfs `/usr` 2.6 GB.

Environment problems that cost time and are product relevant:

- `apt-get update` hung for 9+ minutes twice inside a container (an IPv6 transfer stalled and apt's own timeouts did not fire). The runner now caps each `apt-get update` try at 120 s and retries. **The real provisioner needs the same.**
- apt lists/caches are removed in the last build step. That cut the Ubuntu basic image from 706 MiB to 408 MiB.

## 5. Results: prebuilt-image path

`incus publish` (default gzip) -> `incus image export` to a file -> delete the image -> `incus image import <file>` -> `incus launch` -> `hx-recipe post` (user, password, `apt-get upgrade`). "Local" excludes the download. **Download times are estimates** (size / line rate, no protocol overhead, no signature verification) because no real network path was involved.

| Distro / preset | Image file | Import | Launch (incl. first unpack) | Post (updates) | Local total | Est. download 100 Mbps | Est. download 1 Gbps | Est. total at 100 Mbps | Publish (CI only) |
|---|---|---|---|---|---|---|---|---|---|
| Ubuntu / basic | 408 MiB | 1.5 s | 17.2 s | 40.5 s | 59 s | 34 s | 3.4 s | ~93 s | 76 s |
| Debian / basic | 532 MiB | 1.2 s | 22.5 s | 32.0 s | 56 s | 45 s | 4.4 s | ~101 s | 96 s |
| Ubuntu / developer | 1001 MiB | 3.1 s | 51.5 s | 12.3 s | 67 s | 84 s | 8.3 s | ~151 s | 217 s |
| Debian / developer | 921 MiB | 2.6 s | 42.3 s | 30.8 s | 76 s | 77 s | 7.7 s | ~153 s | 187 s |

Compared with building on the server, the prebuilt path saves roughly 2 to 3 minutes at 100 Mbps and about 3.5 to 4 minutes at 1 Gbps on an unloaded host. The post stage depends on how stale the image is (security updates). Image export is not a bottleneck (1 to 5 s); `publish` compression is (gzip, 1.3 to 3.6 min). Trying `zstd` for the CI image is a follow-up.

## 6. Results: running desktop and idle resources

Evidence the desktop renders: [screenshot](../../spikes/s3-incus-desktop/results/ubuntu-basic-2c4g/screenshot.png) taken from inside the container with `scrot` against `DISPLAY=:0` (`xdpyinfo`: 1920x1080; full-size PNG next to it). XFCE panel, desktop icons and dock are drawn by `xfce4-session` as the unprivileged user. PipeWire check: `pactl info` talks to `pipewire-pulse`, sink `hx-sink` listed. Real audio capture was not tested (S2 territory).

Method: boot the container, wait for Xorg and the panel, install `scrot` (screenshot only), settle 90 s, sample CPU for 60 s from the container's own `cpu.stat`, then read `memory.current` and `memory.stat`. "Free (strict)" = limit minus everything charged to the cgroup, **page cache included** (lower bound). "Free (reclaimable)" = limit minus anon, shmem and kernel memory.

| Distro | Preset | Spec | Idle CPU (cores) | anon | charged (incl. cache) | Free, strict | Free, reclaimable |
|---|---|---|---|---|---|---|---|
| Ubuntu | basic | 2 vCPU / 4 GB | 0.0006 | 153 MiB | 384 MiB | 3711 MiB | 3919 MiB |
| Ubuntu | basic | 4 vCPU / 8 GB | 0.0003 | 172 MiB | 420 MiB | 7771 MiB | 7999 MiB |
| Debian | basic | 2 vCPU / 4 GB | 0.0003 | 138 MiB | 476 MiB | 3619 MiB | 3926 MiB |
| Debian | basic | 4 vCPU / 8 GB | 0.0005 | 165 MiB | 283 MiB | 7908 MiB | 7999 MiB |
| Ubuntu | developer | 2 vCPU / 4 GB | 0.0008 | 152 MiB | 643 MiB | 3452 MiB | 3919 MiB |
| Ubuntu | developer | 4 vCPU / 8 GB | 0.0006 | 172 MiB | 334 MiB | 7857 MiB | 8000 MiB |
| Debian | developer | 2 vCPU / 4 GB | 0.0004 | 134 MiB | 165 MiB | 3930 MiB | 3935 MiB |
| Debian | developer | 4 vCPU / 8 GB | 0.0003 | 157 MiB | 189 MiB | 8002 MiB | 8008 MiB |

The `free` output inside the container (LXCFS) agrees: for Ubuntu basic 2c/4G it reported 175 MiB used, 3920 MiB available. 33 to 35 processes. Largest: Xorg (109 MB RSS), `xfce4-session` (81 MB), `xfdesktop` (40 MB), panel (33 MB), `xfwm4` (30 MB). The developer preset adds only disk at idle (VS Code, git, compilers are not running). The 60 s CPU window ran at host load 5 to 12. Idle numbers say nothing about a running browser or editor; that is S1's loaded measurement.

With Docker running and idle, anon rose to 215 MiB (Ubuntu) and 208 MiB (Debian) on a basic desktop: `dockerd` about 99 MB RSS plus `containerd` about 49 MB.

**inotify cost:** one idle desktop session (13 processes) holds **23 inotify instances**. See section 9.

## 7. Docker nested in the container

Add-on applied to a copy of the prebuilt-imported container: 45 s (Ubuntu) and 57 s (Debian) end to end. Installed: Docker Engine 29.10.0, containerd.io 2.4.2, runc 1.5.3, from Docker's apt repo, user `desk` in group `docker`, config `security.nesting=true`, `security.syscalls.intercept.mknod=true`, `security.syscalls.intercept.setxattr=true`. `docker info`: Docker 29 on a fresh install selects the **containerd image store** (`Storage Driver: overlayfs`, `driver-type: io.containerd.snapshotter.v1`), not the classic `overlay2` driver; the backing filesystem of `/var/lib/docker` is btrfs (the container root). Image pulls and layer extraction work (`hello-world`, `busybox`, `nginx:alpine`, `debian:stable-slim` all pulled, no dockerd warnings).

**But starting any container on the default bridge network fails, on both distros:**

```
OCI runtime create failed: runc create failed: unable to start container process:
error during container init: open sysctl net.ipv4.ip_unprivileged_port_start file:
reopen fd 8: permission denied
```

| Attempt | Result |
|---|---|
| `docker run hello-world` (default bridge) | FAIL (above) |
| `docker run --network host hello-world` | OK |
| compose app (busybox init writes a named volume, nginx serves it), default network | FAIL (above) |
| same compose app with `network_mode: host` on every service | OK, `down` and `up` kept the volume; a plain `docker volume` write then read in a new container returned the data |
| container AppArmor profile set to `unconfined` through `raw.lxc` (diagnostic) | `hello-world` OK on the bridge, so the Incus-generated AppArmor profile is the cause |
| `raw.apparmor` allow rules for `/proc/sys/net/**` | still FAIL (deny rules win) |
| Docker `--security-opt apparmor=unconfined` | still FAIL |
| Docker with runc 1.3.3 extracted from containerd.io 1.7.29 as the default runtime | still FAIL |
| `docker run --sysctl net.ipv4.ip_unprivileged_port_start=0` | still FAIL |
| `mknod /tmp/n c 1 3` inside a Docker container (with `--cap-add MKNOD`) | `Operation not permitted`. The device node limitation exists even with interception enabled; plain image builds that only unpack layers were fine |

Not tested: the classic `overlay2` driver (`"features": {"containerd-snapshotter": false}`), Docker versions older than 29, a newer Incus (the Zabbly 6.x packages or Debian 13's own package), and rootless Docker. The likeliest fix is a newer Incus/LXC AppArmor profile, so the first thing to run on the real servers is `docker run hello-world` on both a Debian 13 host (distro Incus) and an Ubuntu 24.04 host (Incus 6.0.0 vs Zabbly). Unconfining AppArmor for the whole container is not acceptable as a default: it removes a layer of the container isolation that section 8.6 of the architecture relies on.

## 8. Storage pool and snapshots

btrfs on a loop file. `incus snapshot create` is metadata only; copy-on-write cost is exactly what diverges. Because the pool was shared with other agents, absolute "pool used" figures carry noise (some deltas were slightly negative); the pattern is consistent across all four containers.

| Operation (Ubuntu developer; Debian runs similar) | Time | Pool growth |
|---|---|---|
| Snapshot of a running ~3 GB desktop | 0.34 s | about 0 MiB |
| Write 1 GiB random data, then snapshot | 0.38 s | +1029 MiB (the data), +0 for the snapshot |
| Overwrite 100 MiB of that file | | +100 MiB |
| Delete the 1 GiB file with a snapshot present | | space is not released (held by the snapshot) |
| `incus snapshot restore` (rootfs modified by 1 GiB) | 2.0 to 3.0 s | |
| Delete two snapshots | 0.3 to 0.5 s | |

Implications for backups (S4): snapshots are cheap enough to take per backup run and to keep only for the duration of the upload; space reclaim after delete is asynchronous on btrfs. Loop file versus block device: the loop file adds a filesystem-on-filesystem layer (double page cache, extra journal, a sparse file that can fail the host's filesystem when it fills), and its size is fixed at creation unless resized. A spare block device (`--storage-device`) avoids all of that and is preferred when the VPS has one. I did not test btrfs quotas (container disk limits), `btrfs scrub`, or fragmentation after long use.

## 9. Host requirements found

### 9.1 inotify limits (installer requirement)

**All unprivileged containers on one host share a single inotify budget.** The default `fs.inotify.max_user_instances` is 128, charged to the owner of the containers' user namespaces (the Incus daemon's user, root) rather than per container, and shared with root's own processes. One idle XFCE desktop session uses **23 instances**; with three other desktops already running on this host the budget hit zero, and every new container failed to boot with:

```
Failed to create control group inotify object: Too many open files
Failed to allocate manager object: Too many open files
```

(`systemd` PID 1 and `user@1000.service` fail; `security.idmap.isolated=true` did not help.) A probe that tried to create inotify instances inside a running container reported 0 free. The limits were raised by the user to the values below after the problem was found and the spike then ran normally.

Requirement for the installer, via `hx-privd` (it needs root and must be idempotent): write `/etc/sysctl.d/90-hx-incus.conf` (same values as Incus' production-setup guide) and apply with `sysctl --system`:

```
fs.inotify.max_queued_events = 1048576
fs.inotify.max_user_instances = 1048576
fs.inotify.max_user_watches = 1048576
vm.max_map_count = 262144
```

Add a preflight check that reads the current values and warns when they are below these; `run-on-vps.sh` sets the same file (`RAISE_INOTIFY=0` skips it, to reproduce the failure with distro defaults).

### 9.2 Docker on the host versus Incus networking

Container IPv4 egress was broken on this host while IPv6 worked, and bridge-to-bridge routing did not work either. The cause could not be read without root, but the host runs Docker, whose `FORWARD` chain defaults to DROP, which is the documented conflict with Incus bridges. If hash-xcreen is installed on a server that already runs Docker (a real possibility on a VPS), the installer must detect it and add `iptables -I DOCKER-USER -i <bridge> -j ACCEPT` and `iptables -I DOCKER-USER -o <bridge> -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT` (or the nftables equivalent). **UNVERIFIED** here; it is an inference from symptoms.

## 10. Network isolation

Rule from the design: the container must not reach `169.254.169.254` or the host's agent ports.

What I found with Incus 6.0.0 as a member of `incus-admin` (no sudo):

- Without isolation the container reached a listener on the bridge gateway (HTTP 200) and the host's public address (200). The host's own loopback is not reachable (the container has its own).
- A NIC-level `security.acls` key is **rejected** on this NIC (`Invalid device option "security.acls"`, tried through the default profile's `network:` NIC and with `nictype=bridged`). ACLs for bridge networks are set on the **network**: `incus network set <bridge> security.acls=<acl>`. ACL and network creation did not need host sudo, because the Incus daemon (root) installs the nftables rules. So the installer should create its own bridge for the desktop instead of using the shared `incusbr0`.
- Verified: with the ACL below attached to a dedicated bridge, the container could no longer reach a host listener through the bridge gateway (200 became timeout), while DNS (dnsmasq on the gateway) kept working, so Incus permits DNS and DHCP to the gateway on its own.
- **Not verified:** the `169.254.169.254` rule and the public-address rule. On this host I could not make a routed path to a stand-in (no root to add the address to the host, no inter-bridge forwarding), and a stand-in on the same bridge is reached at layer 2, which the ACL does not filter. On a real server nothing on the bridge answers for that address, so traffic is routed through the host and the rule applies. `net-test.sh` tests this properly on a VPS (as root it adds `169.254.169.254/32` to the host loopback). One run of the combined test script was refused by the tool permission layer; I did not retry it and ran the steps by hand with a narrower listener.

ACL (applied to a dedicated bridge `hxbr0`; replace the host addresses):

```sh
incus network create hxbr0 ipv4.address=10.77.3.1/24 ipv4.nat=true ipv6.address=none
incus network acl create hx-isolate
incus network acl rule add hx-isolate egress action=drop destination=169.254.169.254/32 description="cloud metadata"
incus network acl rule add hx-isolate egress action=drop destination=fd00:ec2::254/128   description="cloud metadata (AWS IPv6)"
incus network acl rule add hx-isolate egress action=drop destination=10.77.3.1/32        description="host via the gateway"
incus network acl rule add hx-isolate egress action=drop destination=<host public IPv4>/32
incus network acl rule add hx-isolate egress action=drop destination=<host public IPv6>/128
incus network acl rule add hx-isolate egress action=allow description="everything else"
incus network set hxbr0 security.acls=hx-isolate security.acls.default.egress.action=allow
```

Caveats: the list of host addresses must be maintained (a floating or secondary IP is missed). A more robust companion, needing root and written here for later, drops all traffic from the bridge into the host except DNS/DHCP, which covers every host address at once, and drops metadata in forwarding:

```sh
nft add table inet hx
nft 'add chain inet hx input   { type filter hook input   priority -10; policy accept; }'
nft 'add chain inet hx forward { type filter hook forward priority -10; policy accept; }'
nft add rule inet hx input   iifname "hxbr0" ct state established,related accept
nft add rule inet hx input   iifname "hxbr0" udp dport { 53, 67 } accept
nft add rule inet hx input   iifname "hxbr0" tcp dport 53 accept
nft add rule inet hx input   iifname "hxbr0" counter drop
nft add rule inet hx forward iifname "hxbr0" ip  daddr 169.254.169.254 drop
nft add rule inet hx forward iifname "hxbr0" ip6 daddr fd00:ec2::254 drop
# persist in /etc/nftables.d or the hx-agent's own unit; hx-privd owns this
```

Note the container's IPv6 default: this spike's dedicated bridge had IPv6 off. If IPv6 is enabled for the desktop, add the equivalent v6 gateway address to both mechanisms.

## 11. Criteria

| Criterion | Result | Reason |
|---|---|---|
| Desktop idle with at least 1.5 GB free on the minimum spec | **PASS (local)**, VPS UNVERIFIED | 3.45 to 3.93 GB free (strict, cache counted) and about 3.92 GB reclaimable of 4 GiB, both distros, both presets. The limit here is cgroup-only; a real 4 GB VPS also pays for the host kernel, Incus and the agent, so confirm there |
| Docker `hello-world` runs nested | **FAIL as designed**; works only with `--network host` | runc cannot configure a bridge-network container under the Incus 6.0.0 AppArmor profile on Ubuntu 24.04. Needs a newer Incus or a different approach (see decision) |
| Prebuilt path under 5 min | **PASS (local + estimate)**, download UNVERIFIED | 56 to 76 s local plus an estimated 34 to 84 s download at 100 Mbps (about 93 to 153 s total) |
| Build path under 20 min | **PASS (local)**, VPS UNVERIFIED | 3.6 to 5.1 min on an unloaded host; 8.7 min under host load of 25 to 34. Real mirror speed, disk and CPU steal are unmeasured |
| Both recipes x both distros apply successfully | PASS | All four recipes built and booted a working desktop; Docker add-on applied on both distros |

## 12. Decision

- **Minimum spec: keep 2 vCPU / 4 GB / 30 GB, recommended 4 vCPU / 8 GB**, provisionally. Idle headroom is large (3.4 GB or more free), so the minimum is not set by idle. It is set by loaded use (browser, VS Code, Docker) and by host overhead, both of which need the VPS run and S1. Do not lower it.
- **Pool defaults:** btrfs; a spare block device when `--storage-device` is given, otherwise a **sparse loop file sized at about 60 % of free disk at install, bounded to 12 GiB to 200 GiB** (never the 60 GB used here on a 30 GB disk; a developer container is about 3.3 GB plus up to a few GB of CoW divergence per snapshot). Leave at least 8 GB for the host filesystem. Verify host filesystem headroom in preflight. Quotas on btrfs are untested.
- **Recipe format:** adopt this TOML design (fragments with `include`, `[vars]`, add-ons, pinned key fingerprints, stage order, `post` stage separate from `apply`) as the schema for `hx-provision`. Keep shell `step`s as the escape hatch but prefer typed sections. The same recipe gave the build path and the image; the parity CI of architecture 4.3 can diff `dpkg -l`, `/etc` and enabled units between a built and an imported container.
- **Image path:** both paths meet their limits with large margin, and the build path is fast (3.6 to 5.1 min unloaded), so `--image auto` can keep its design but the prebuilt path only saves about 2 to 4 minutes. Clean apt lists in the image (halves the size). Evaluate `zstd` publish compression.
- **Docker opt-in is not ready as specified.** Needs the follow-ups in section 13 before the installer offers it. Until then, the safe statement for the UI is that Docker needs host networking in the container.
- **Installer must set the inotify sysctls** (section 9.1) and create a dedicated Incus bridge with the isolation rules (section 10).

## 13. Risks and follow-ups

Sections 7, 10, 11, 12 and 13 describe the local run; see section 15 for what the VPS run changed (Docker on the bridge works on Incus 6.0.5, metadata and host-IP ACL rules verified, Debian 13 needs `signal,`).

1. **Docker on bridge networking** (section 7). Re-test on real servers with: Debian 13 host with its own Incus, Ubuntu 24.04 with Incus 6.0.0, Ubuntu 24.04 with Zabbly stable; also classic `overlay2`, Docker 28.x and rootless Docker. If still failing, options are a vendor-specific AppArmor fix through a narrow `raw.apparmor` profile (not found here), a documented host-network-only mode, or the later VM option.
2. **Re-run on real VPSs** (needs root on a throwaway server): everything marked UNVERIFIED, namely host overhead and idle free RAM at 4 GB, real build and download times (prebuilt over 100 Mbps and 1 Gbps links), CPU steal, a spare block device pool versus loop file, the metadata and public-address ACL rules, Docker bridge networking on newer Incus, IPv4-only and dual-stack apt behaviour, and `RAISE_INOTIFY=0` to reproduce the failure. Script: `spikes/s3-incus-desktop/run-on-vps.sh`.
3. **Xorg runs as root inside the (unprivileged) container** in `hx-xorg.service`. A rootless Xorg configuration is a hardening follow-up. A restart of Xorg changes the cookie, so the user session must restart with it (not yet wired).
4. **Not tested:** loaded memory with Firefox or VS Code open, audio capture, Docker idle at 4 GB after a reboot, Debian 12, Ubuntu 26.04, arm64, an Incus VM, Claude Code and Codex CLI installers, snapshot behaviour with Docker volumes in use, `btrfs` quotas, backups from a mounted snapshot (S4).
5. **apt hangs** over a stalled IPv6 transfer (section 4); bound apt in production and prefer a configured mirror.
6. **Shared inotify budget** also affects any other software on the host that uses Incus; the preflight should check it before touching anything.
7. The unloaded timings come from a machine with other agents' load always present (4 to 12); treat them as indicative, not absolute.

## 14. Reproduce

Locally (needs Incus access):

```sh
cd spikes/s3-incus-desktop/runner && cargo build --release && cd ..
./build.sh recipes/debian-13-xfce-basic.toml s3-deb 2 4GiB       # build path, timed
./measure.sh s3-deb results/deb-basic-2c4g 90 60                  # screenshot + idle RAM/CPU
./snapshot-test.sh s3-deb                                         # btrfs snapshot behaviour
./prebuilt.sh s3-deb recipes/debian-13-xfce-basic.toml /tmp/export 2 4GiB
./runner/target/release/hx-recipe apply recipes/debian-13-xfce-basic.toml <container> --addon addons/docker.toml
./docker-test.sh <container>
```

On a fresh Ubuntu 24.04 or Debian 13 VPS, as root, copy the spike directory over and run `run-on-vps.sh` (variables documented at its top; it writes `results-<host>-<date>/summary.tsv`). The raw logs of the runs in this report are in `spikes/s3-incus-desktop/results/` (apt output is stripped from the build logs).

---

## 15. VPS run (2026-11-20)

Second run, on a real server, by root over SSH with passwordless `sudo`. It answers the open items of section 13. Raw logs: [spikes/s3-incus-desktop/results-vps-2026-11-20/](../../spikes/s3-incus-desktop/results-vps-2026-11-20/). Branch `spike/s3-vps-run`. Everything here was measured unless it says **estimate**.

### 15.1 Host and setup

| Item | Value |
|---|---|
| Host | KVM guest, 4 vCPU AMD EPYC-Rome, 7936 MiB RAM, no swap, 193 GB disk (172 GB free), `/dev/kvm` present (nested virtualisation works), CPU steal 0 in every sample |
| OS | **Ubuntu 26.04.1 LTS** (the plan said 24.04), kernel 7.0.0, glibc 2.43. `kernel.apparmor_restrict_unprivileged_userns=1` |
| Incus | 6.0.5 from Ubuntu's own repository (`apt install incus btrfs-progs`, 43 s). Zabbly has a `resolute` (26.04) suite, current stable 7.6 (checked, not installed) |
| Pool | `default`, btrfs, **103 GiB loop file** (60% of 172 GB free, inside the 12 to 200 GiB bound) |
| Bridge | `hxbr0`, 10.77.3.0/24, NAT, no IPv6; the default profile's NIC uses it |
| Host Docker | Docker Engine 29.9.3 already active (FORWARD policy DROP), three user images, no containers. Untouched; `docker images` (name, tag, digest) is identical before and after |
| Idle host before Incus | 712 MiB used, 7223 MiB available, load 0.12, 95 to 100 % CPU idle. With Incus installed and idle: 802 MiB used, 7133 MiB available |
| Network | 1 Gbit class: a public 621 MB file downloaded at 137 MB/s (4.5 s); Incus image downloads ran at 270 MB/s. IPv4 only on the bridge. The host has IPv6 `/128` on `ens3` |
| Load | The server was otherwise quiet (load average 0.1 to 3). Spike S5 ran on the same server; no listener of mine used TCP 80, 443 or UDP 443 and none was blocked (the only test listener was TCP 9443, removed afterwards) |

Setup commands (root; what `run-on-vps.sh` now does):

```sh
apt-get install -y incus btrfs-progs bc curl ca-certificates
incus admin init --preseed < preseed.yaml      # pool "default" btrfs size 103GiB; network hxbr0 10.77.3.1/24 nat, ipv6 none; default profile eth0 -> hxbr0
```

### 15.2 inotify limit reproduced, then fixed

With the distro default (`fs.inotify.max_user_instances = 128`), copies of one built Ubuntu basic desktop were started one by one. The first four booted, the fifth came up **degraded** (`systemd-networkd`, `systemd-resolved`, `user@1000` failed), the sixth and seventh did not start at all (`Failed to create control group inotify object: Too many open files`). Together with the original that is five usable desktops of the 128 budget, so two desktops were not enough to fail on this host; the budget is shared with root's own processes. After writing `/etc/sysctl.d/90-hx-incus.conf` with the section 9.1 values and `sysctl --system`, the same seven copies plus the original **all booted** (8 desktops running at once, 5.8 GB of 7.9 GB available afterwards). The file stays on the server.

### 15.3 Build on the server

Base image cached after the first launch, `apply` at 2 vCPU / 4 GiB, host load average at start 0.1 to 1.9, real Ubuntu and Debian mirrors over the same line.

| Distro | Preset | Total | apt bootstrap | apt install | Note |
|---|---|---|---|---|---|
| Ubuntu 24.04 | basic | **206 s** (201 s in a first run) | 8 s | 195 s | |
| Ubuntu 24.04 | developer | **192 s** | 7 s | 177 s | |
| Debian 13 | basic | **86 s** | 5 s | 78 s | needs `raw.apparmor=signal,` (section 15.8e) |
| Debian 13 | developer | **140 s** | 6 s | 128 s | same |

This is 1.4 to 3.4 minutes against the 20-minute limit, and it is faster than the local run (3.6 to 5.1 min). Ubuntu's apt install is more than twice as slow as Debian's for a smaller package set; I did not find out why (mirror or package mix).

### 15.4 Prebuilt path

`incus publish` (default gzip) to export, then `incus image import`, `incus launch` and `hx-recipe post`, all local on the server. **The download is not measured on the exported images**: I had no public URL I could use for the images without publishing them. Instead I measured the line itself by downloading a comparable public file to disk (621 MB from `cloud-images.ubuntu.com`: 4.5 s, **137 MB/s**), and applied that rate to the image sizes. Those two download columns are therefore **estimates** (size divided by measured throughput; size divided by 100 Mbit/s for a slow link). The post stage was short because the images were fresh; it grows with how stale the image is.

| Distro / preset | Image file | Publish (CI only) | Export | Import | Launch | Post | Local total | Est. download at the measured 137 MB/s | Est. total | Est. download at 100 Mbit/s | Est. total |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Ubuntu / basic | 520 MiB | 70.8 s | 0.9 s | 1.0 s | 12.1 s | 6.1 s | 19.3 s | 4.0 s | **~23 s** | 43.6 s | ~63 s |
| Ubuntu / developer | 1000 MiB | 143.9 s | 1.9 s | 2.3 s | 20.6 s | 6.1 s | 29.1 s | 7.7 s | **~37 s** | 83.9 s | ~113 s |
| Debian / basic | 532 MiB | 70.9 s | 0.9 s | 0.8 s | 11.3 s | 3.8 s | 16.0 s | 4.1 s | **~20 s** | 44.6 s | ~61 s |
| Debian / developer | 1037 MiB | 155.1 s | 2.0 s | 2.4 s | 21.4 s | 3.5 s | 27.5 s | 8.0 s | **~36 s** | 87.0 s | ~115 s |

The prebuilt path is 20 to 37 s here (about 1 to 2 minutes at 100 Mbit/s), against the build path's 1.4 to 3.4 minutes. Publish with gzip (the CI side) takes 1.2 to 2.6 minutes; zstd is still not tried.

### 15.5 Idle desktop and host overhead

Method as in section 6 (boot, wait for Xorg and the panel, install `scrot`, 90 s settle, 60 s CPU window from the container's own `cpu.stat`). Before each run every other instance was stopped, so the host numbers are for one desktop only. **Spec A** is the minimum, 2 vCPU / 4 GiB. **Spec B** is the largest this host can spare: all **4 vCPU / 6400 MiB**, which leaves 1536 MiB to the host. `anon`, charged (incl. cache) and the two free columns are in MiB, read inside the container.

| Distro | Preset | Spec | Idle CPU (cores) | anon | charged | Free, strict | Free, reclaimable | Procs | Host `used` before to after (MiB) | Host `available` (MiB) |
|---|---|---|---|---|---|---|---|---|---|---|
| Ubuntu | basic | A | 0.0002 | 153 | 628 | 3467 | 3921 | 37 | 833 to 1003 (+170) | 7102 to 6932 |
| Ubuntu | basic | B | 0.0002 | 172 | 321 | 6078 | 6209 | 37 | 813 to 1046 (+233) | 7122 to 6889 |
| Ubuntu | developer | A | 0.0002 | 153 | 641 | 3454 | 3920 | 37 | 871 to 1025 (+154) | 7064 to 6910 |
| Ubuntu | developer | B | 0.0002 | 172 | 322 | 6077 | 6209 | 37 | 860 to 1057 (+197) | 7075 to 6879 |
| Debian | basic | A | 0.0003 | 147 | 483 | 3612 | 3920 | 33 | 884 to 923 (+39) | 7051 to 7012 |
| Debian | basic | B | 0.0002 | 165 | 284 | 6115 | 6208 | 33 | 894 to 915 (+21) | 7041 to 7020 |
| Debian | developer | A | 0.0002 | 139 | 480 | 3615 | 3928 | 33 | 1078 to 1111 (+33) | 6857 to 6824 |
| Debian | developer | B | 0.0002 | 165 | 287 | 6112 | 6209 | 33 | 1079 to 1107 (+28) | 6856 to 6828 |

Host overhead: the Incus daemon (`incusd`) uses 86 to 122 MiB RSS and dnsmasq a few MiB; a running idle desktop adds 21 to 233 MiB to the host's `used` (the spread is noise from caches settling, so read it as "about 0.2 GB at most") and about 280 to 640 MiB of page cache charged to its cgroup, which is reclaimable. A 4 GB host extrapolated from these numbers (**estimate**, no 4 GB server was available): about 0.8 GB base system plus Docker, 0.1 GB Incus, 0.15 to 0.25 GB desktop leaves **about 2.8 GB available**, above the 1.5 GB limit. A host running a Docker daemon of its own (as this one does) is already included in the 0.8 GB.

Docker inside the container adds about 85 MiB: anon 237 MiB with `dockerd` (114 MB RSS) and `containerd` (57 MB) idle, against 153 MiB without (Ubuntu basic).

### 15.6 Network isolation

All with Incus 6.0.5 on the dedicated bridge `hxbr0`.

1. **169.254.169.254 answers on this provider.** From the host: HTTP 200 with an EC2-style version listing (`1.0`, `2007-01-19`, ...). A container reaches it too (200) as soon as forwarding works, so the rule is needed. I did not read any metadata, only the first few version lines.
2. **Host Docker blocks the Incus bridge.** With Docker active and `iptables -P FORWARD DROP`, a fresh container on `hxbr0` got a DHCP lease and resolved names (dnsmasq), but IPv4 egress failed (HTTPS timeout, `ping 1.1.1.1` 100 % loss). This confirms the inference of section 9.2. Two rules fixed it immediately, and it still worked afterwards:

   ```sh
   iptables -I DOCKER-USER -o hxbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
   iptables -I DOCKER-USER -i hxbr0 -j ACCEPT
   ```

   Both rules are **not persistent across a reboot** (Docker keeps `DOCKER-USER` while it runs). The installer needs a persistent form (a unit in `hx-privd` that re-adds them after `docker.service`, or an nftables file).
3. **ACL test** (`net-test.sh`, ACL `s3-isolate` on `hxbr0`, listener on TCP 9443 as the stand-in for the agent port; S5's ports were not touched):

   | Probe from inside the container | Without ACL | With ACL |
   |---|---|---|
   | `169.254.169.254:80` | 200 | **blocked** |
   | bridge gateway `10.77.3.1:9443` | 200 | **blocked** |
   | host public IPv4 `85.190.123.74:9443` | 200 | **blocked** |
   | host `docker0` address `172.17.0.1:9443` | 200 | **blocked** |
   | host IPv6 `2001:880:a:339::26` | no route (the bridge has no IPv6) | blocked |
   | HTTPS to the internet, DNS lookup, DHCP lease | works | **still works** |

   The same rules bind a Docker container nested inside the desktop (`acl-docker-test.sh`): metadata, gateway and host public IP blocked, example.com reachable, `docker pull` works. ACL commands that worked are the ones in section 10 plus `incus network acl rule add ... destination=172.17.0.1/32` for each extra host address (`net-test.sh` adds every global address it finds). The ACL was **removed from `hxbr0` at the end** so that S2's measurements are not disturbed (`incus network set hxbr0 security.acls= security.acls.default.egress.action=`); it is a one-line reapply.
4. The ACL drops the whole host IP, so a desktop cannot reach a service the host publishes on its own public address (a hairpin). That is intended for the agent port; document it for anyone who hosts other services on the same IP.

### 15.7 Docker: test order and results

a. **Nested Docker on Incus 6.0.5** (container with `security.nesting=true` and `security.syscalls.intercept.mknod/setxattr=true`, Docker Engine 29.10.0 with the containerd image store, default bridge):

| Test | Ubuntu 24.04 guest | Debian 13 guest |
|---|---|---|
| `docker run hello-world` on the default bridge | **PASS** (0.9 s after the image was pulled; 3.2 s with pull) | **PASS** (2.6 s with pull) |
| compose app (init writes a stamp to a named volume, nginx serves it), default network | PASS | PASS |
| `down` then `up`: stamp identical (volume persists) | PASS | PASS |
| same app with `network_mode: host` | PASS | PASS |
| `docker run --network host hello-world` | PASS | PASS |
| `debian:stable-slim` (layers with device nodes and xattrs) | PASS | PASS |
| `mknod /tmp/n c 1 3` inside a Docker container | `Operation not permitted` | `Operation not permitted` |

   That is the opposite of the local run, where the same Docker version failed on the same two guests under Incus 6.0.0. The compose volume check was improved: the earlier test let nginx's image content copy into the volume first, which hid the written file; it now reads a stamp the init service writes.

   **Why it now works is not established.** The differences are Incus 6.0.0 versus 6.0.5, kernel 6.8 versus 7.0 and the host distribution. For the record, the AppArmor profile Incus generated here for a container with `security.nesting=true` does **not** contain the `deny /proc/sys/[^fknu]*`, `deny /proc/sys/net?*` and `deny /sys/...` block that the non-nesting profile has, and it adds `pivot_root`, `ptrace`, `signal`, `mount` (unrestricted) and `deny /dev/.lxc/...`. I could not diff against 6.0.0's nesting profile, so whether 6.0.5 changed this is a hypothesis.

b. **Zabbly Incus:** not needed, since (a) passed. Recorded: Zabbly publishes `resolute` packages (stable 7.6-ubuntu26.04). Not installed, so the "upgrade and recheck pool, bridge, ACL" step did not apply. **Still unknown:** whether 6.0.1 to 6.0.4 or Ubuntu 24.04's own updated package fix the failure, and whether Ubuntu 24.04 with 6.0.0 still fails (it did locally). The installer therefore needs a runtime self-test.

c. **Incus VM desktop** (`incus launch images:ubuntu/24.04 --vm`, 2 vCPU / 4 GiB, secure boot off, recipe `ubuntu-24.04-xfce-basic` plus Docker add-on without the container-only Incus keys, `vm-test.sh`):

| Measure | Container (Ubuntu basic) | VM |
|---|---|---|
| Boot to usable (`incus launch` to agent) | `incus start` to XFCE panel **2.1 s** | launch command 10.5 s, agent ready after **34.8 s**; reboot to XFCE panel **30.8 s** |
| Build (`apply` with Docker add-on) | 206 s without Docker, Docker add-on alone 23 s | 211 s with Docker |
| XFCE on Xorg dummy | 1920x1080, as measured | **same**: Xorg 1.21.1.11 dummy driver, `xdpyinfo` 1920x1080, `scrot` works, same recipe and systemd units |
| Idle CPU | 0.0002 cores | 0.11 % busy of 2 vCPUs inside the guest; **QEMU on the host 0.06 cores** over 30 s |
| Idle RAM inside | anon 153 MiB (237 with Docker) | used 539 to 577 MiB with Docker, 3.27 GB available of 3848 MiB |
| RAM on the host | +20 to 230 MiB | QEMU RSS **1049 MiB** shortly after boot, **1812 MiB** after a few Docker pulls (guest page cache stays resident on the host); host `used` 1931 MiB with the VM against about 880 MiB idle |
| Docker `hello-world` on the default bridge | PASS (needs `security.nesting`) | **PASS**, no special Incus configuration |
| `mknod` in a Docker container (with `--cap-add MKNOD`) | EPERM | **works** |
| Process count | 37 | 148 |

d. **Targeted AppArmor change:** not needed for Docker. Found for another problem instead, in the next paragraph.

e. **Debian 13 guests do not boot on this host with the default profile.** On Incus 6.0.5 / kernel 7.0 the container's `systemd` 257 stays in `initializing` (`journald`, `resolved`, `networkd` all stuck at `(sd-mkuserns)`), so there is no network and the recipe fails at `wait-network`. With `security.nesting=true` it boots. The narrowest fix I found (`apparmor-try.sh`): a single raw AppArmor rule, `incus config set <c> raw.apparmor "signal,"`. `pivot_root,`, `mount,` and `ptrace,` alone, and every combination without `signal,`, still hang; `signal,` alone and `ptrace,` + `signal,` boot. The kernel log shows AppArmor denying `signal` (kill/term/exists) from the container's own `systemd` to a peer in its stacked `//&unconfined` profile. All Debian numbers above use this rule (`INCUS_LAUNCH_ARGS="-c raw.apparmor=signal,"` in `build.sh` and `prebuilt.sh`); a published image does not carry instance config, so the prebuilt launch must set it as well, preferably as an Incus profile. The earlier local run (kernel 6.8, Incus 6.0.0) did not need it. Ubuntu 24.04 guests never did. **The installer must treat this as a kernel/Incus-version dependent compatibility rule** and verify that the desktop reaches `running` after launch.

### 15.8 Recommendation: Docker

1. **Default for the opt-in Docker add-on: nested Docker in the unprivileged container, on Docker's default bridge, with `security.nesting=true` and syscall interception**, on Incus **6.0.5 or newer** (verified on Ubuntu 26.04, both guests). The "fix on the default bridge" option of Gate 0 holds, without any custom AppArmor profile. It costs about 85 MiB, no boot penalty and keeps the cheap btrfs file-level snapshots of section 8.
2. **The installer must not trust the version number.** After enabling Docker it runs `docker run --rm hello-world` (with a pull) on the default bridge as a self-test. If that fails with the `ip_unprivileged_port_start` error (seen on Incus 6.0.0 / Ubuntu 24.04), it must say so and offer, in this order: (a) upgrade Incus from the Zabbly repository, (b) **host-network-only Docker**, which worked on every version, with the limitations that no port isolation exists inside the desktop and `network_mode: host` is needed in compose files, (c) the VM option when `/dev/kvm` exists. A custom AppArmor profile or `unconfined` is **not** recommended: it was never required once the version was good, and it would need maintenance against every Incus update.
3. **The VM is the option for stronger isolation, not for compatibility.** Trade-offs: security (no shared kernel, nesting and the relaxed AppArmor rules are not needed; `mknod` and other privileged operations work); resources (about 1.0 to 1.8 GiB host RAM per desktop and 148 against 37 processes, so a 4 GB server loses most of its headroom, and a boot of 30 s instead of 2 s); availability (`/dev/kvm` was present here but a lot of VPS offers lack nested virtualisation; probe it in preflight); and plumbing (the backup design in S4 reads a mounted btrfs snapshot of the container filesystem, which does not exist for a VM disk image, so S4's file-level restore would need a guest agent or a different approach). Recommendation: do not build it for the first release; keep the host-network fallback and revisit the VM when someone asks for hardened Docker.
4. The `security.nesting` trade-off must be shown in the app as in architecture 4: with it Incus removes the `deny /proc/sys` and `/sys` rules from the container's AppArmor profile and allows `mount`, `pivot_root`, `ptrace` and `signal`. Docker is opt-in for that reason.

### 15.9 Criteria after the VPS run

| Criterion | Result | Basis |
|---|---|---|
| Desktop idle with at least 1.5 GB free on 2 vCPU / 4 GB | **PASS** | Measured: 3.45 to 3.93 GB free in the container (strict, cache counted) and 3.92 GB reclaimable, both distros and presets; host overhead of Incus plus one desktop 0.1 to 0.35 GB. **The 4 GB host view is an estimate** (about 2.8 GB available), since no 4 GB server was available. At 4 vCPU / 6.4 GB: 6.1 to 6.2 GB free |
| Docker `hello-world` runs nested | **PASS** on Incus 6.0.5 (Ubuntu 26.04 host), on the default bridge, both guests; compose with a volume PASS | Needs the version self-test; FAILED on Incus 6.0.0 / Ubuntu 24.04 (local run) |
| Prebuilt path under 5 min | **PASS** | 16 to 29 s local + download: about 20 to 37 s at the measured 137 MB/s (**download estimated from the line rate, not from the image**), about 1 to 2 min at 100 Mbit/s (estimate) |
| Build path under 20 min | **PASS** | Measured 86 to 206 s on real hardware with real mirrors |
| Both recipes x both distros apply | PASS | All four built and booted a desktop; Debian needs the `signal,` AppArmor rule on this host |
| Metadata-address rule | **PASS (verified)** | Address answers on this provider; blocked with the ACL, from the container and from Docker inside it |
| Host-public-IP rule | **PASS (verified)** with a test listener on TCP 9443 | Agent ports 80/443 not used; the whole host IP is dropped by the rule |
| Docker + host Docker coexistence | PASS with the two `DOCKER-USER` rules | Without them IPv4 egress fails |
| UNVERIFIED | | Real 4 GB host; a 100 Mbit/s link; real download of our own images; a spare block device instead of a loop file; Incus 6.0.1 to 6.0.4; Ubuntu 24.04 and Debian 13 **hosts**; Zabbly packages; IPv6 for the desktop; reboot persistence of the firewall rules; loaded (browser, VS Code) memory |

### 15.10 What changed versus the local run

- **Docker bridge networking now works** (Incus 6.0.5 instead of 6.0.0); the Gate 0 decision becomes "default bridge with a runtime self-test and fallbacks" instead of an AppArmor change.
- **Debian 13 needs `signal,`** on this kernel (new, not seen locally).
- IPv4 egress works once `DOCKER-USER` accepts the bridge; the local failure was this (cause confirmed, no longer inferred).
- Build times are about half the local ones (86 to 206 s against 213 to 520 s) because the server was idle and the mirrors are close; prebuilt totals are lower for the same reason.
- inotify: reproduced with the default 128 (fifth and later desktops fail), fixed by the sysctl file.
- The metadata address is real on this provider; both ACL rules verified.
- `vm-test.sh`: a VM desktop works with the same recipe.
- Not repeated: btrfs snapshot timings (section 8). Desktop screenshots were taken again (`results-vps-2026-11-20/*/screenshot.png`).

### 15.11 What is left on the server

Incus 6.0.5 installed and running (`incus` service, no instances, no images), pool `default` (btrfs, 103 GiB loop file under `/var/lib/incus/disks`), bridge `hxbr0` (10.77.3.1/24, no ACL attached, default profile uses it), `/etc/sysctl.d/90-hx-incus.conf` applied, and the two `DOCKER-USER` accept rules for `hxbr0` (live only). `apt` packages added: `incus`, `btrfs-progs`, `bc` and their dependencies. Removed: every `s3-` instance and image, the ACL, the helper directory under the admin's home, temporary files. Docker, its images and its configuration were not touched.

### 15.12 Risks and follow-ups

1. **Ubuntu 24.04 and Debian 13 hosts are still unverified.** The run was on 26.04; the plan's targets differ. `run-on-vps.sh` accepts 26.04 now and should be rerun on both.
2. **Incus version floor for Docker is unknown** between 6.0.0 (fails) and 6.0.5 (works). Do not publish a number until bisected, or require 6.0.5.
3. **Debian-guest compatibility** (`signal,`) needs an installer check, as above; it could also appear on other kernels.
4. Persist the `DOCKER-USER` rules; handle the host Docker being restarted (rules survive) and a reboot (they do not).
5. The ACL drops the full host IP. A server that exposes web services on the same IP cannot be reached from the desktop on that IP; document it.
6. `incus publish` compression time (1.2 to 2.6 min) is a CI cost; try zstd.
7. Build timing depends on the apt mirror; the Ubuntu number is more than double Debian's.
8. Measured on a 7.9 GB host, not a 4 GB one; run `HOST_RESERVE_MIB`-style limits on a real 4 GB server before the minimum spec is final.
