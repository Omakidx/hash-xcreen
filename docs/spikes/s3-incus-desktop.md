# Spike S3: Incus desktop on a VPS

Status: local run complete (2026-11-20), real-VPS run pending. Branch `spike/s3-incus-desktop`. Code and raw logs: [spikes/s3-incus-desktop/](../../spikes/s3-incus-desktop/).

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
