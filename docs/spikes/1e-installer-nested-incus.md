# Spike 1E: the real installer, end to end, in a nested Incus container

Status: run complete (2026-11-21), local Incus 6.0.0. **Verdict: PASS on Ubuntu 24.04 (two clean runs in a row) and Debian 13 (one run), after eight product bugs the run found were fixed (section 6), with the limits of section 7 not run.** The whole flow is real: `install.sh` (test-keyed) then `hx-agent install` through every stage, the units under real systemd, privd and gatewayd, the inner Incus the installer installed from the distro, the desktop build, pairing and PIN login from the host over QUIC and WebSocket, and the first video frame of the desktop that was built inside L1.

Contracts under test: [architecture.md](../architecture.md) section 5 (the installer), [ipc.md](../ipc.md) (privd, the C2 stdin frames, the C3 progress lines, uninstall, the rescue helper). This is the first time `install.sh`, `hx-agent install`, the units under real systemd, privd, gatewayd, the inner Incus and the desktop build ran together. Until now each had only been tested against fakes (the install engine's fake runner) or outside systemd (the 1C real-Incus spike ran the daemons as the invoking user, and its section 9 listed "the units have never run under real systemd" as not run).

Code: `apps/hx-agent/tests/install_nested_incus.rs` (the ignored test), `apps/hx-agent/tests/install_harness/` (the Incus side, the C2 frames, the C3 parser, the client), `apps/hx-agent/tests/installer_vm_client.rs`, `.github/workflows/installer-vm.yml` and `tests/installer-vm/` (the CI cells on KVM VMs, **which could not be run where they were written**: no `/dev/kvm`).

## 1. What runs

```text
test process (host, unprivileged, group incus-admin)
  | incus exec / file push                 +--- CONNECT proxy on the bridge gateway (apt, images)
  v                                        |
 L1 = hx1e-host-<distro>   unprivileged system container, systemd as PID 1, root inside
  | sh install.sh --release-dir ... --ssh        (C2 secret frames on stdin, C3 JSON Lines on stdout)
  | hx-agent install -> real units (hx-privd, hx-gatewayd, three sockets) -> the inner Incus
  v
 inner Incus: pool hx-pool, bridge hxbr0, ACL hx-isolate, the desktop container hx-main (Ubuntu 24.04 XFCE)
```

The test is `#[ignore]` and does nothing without `HX1E_LOCAL=1`:

```text
HX1E_LOCAL=1 sg incus-admin -c 'cargo nextest run -p hx-agent --run-ignored only \
    --test install_nested_incus --no-capture'
```

`HX1E_DISTROS` (default `ubuntu-24.04`; `ubuntu-24.04,debian-13` runs both) and `HX1E_KEEP=1` (leave the `hx1e-` objects for a post-mortem) are the switches; `HX1E_REUSE=1` (with a `HX1E_KEEP=1` run before) attaches to the kept L1 for development of the later phases.

## 2. Setup

| Item | Value |
|---|---|
| Host | Ubuntu 24.04, kernel 6.8.0-151, 16 cores, no `/dev/kvm`, no sudo (Incus through the `incus-admin` group), Docker on the host, Incus 6.0.0 |
| Host objects (all `hx1e-`, `user.hx1e-test=1`) | pool `hx1e-pool` (btrfs, 60 GiB sparse loop file made by incusd), bridge `hx1e-br0` (10.77.0.1/24), profile `hx1e-l1` (root disk on the pool, `eth0` on the bridge), instance `hx1e-host-u2404` (4 CPU, 8 GiB, 50 GiB root), launched with `--no-profiles --profile hx1e-l1` |
| L1 | unprivileged; `security.nesting`, `security.syscalls.intercept.mknod` and `.setxattr`, `security.idmap.isolated`, `security.idmap.size=1000000`, `limits.kernel.memlock=unlimited`. Never `security.privileged`, never `raw.lxc` (the test asserts both from `incus config show --expanded`). `raw.apparmor=signal,` only for a Debian 13 L1 |
| CONNECT proxy | the `e2e_common::start_proxy` of the 1C spike, bound to the bridge gateway only; with NAT off it is L1's only way out (apt, the inner Incus's image download, the desktop's apt) |
| Release | built per run: the real binaries with `--features test-release-key,install-test-hooks,privd-test-hooks` (key from `HX_TEST_RELEASE_PUBKEY`), the real `hx-session.deb` for Ubuntu 24.04 (`packaging/hx-session/build-deb.sh`), `hx-pwcheck`, and `release/make-test-release.sh` (extended with `--key-dir`, see section 8, because the agent embeds the key at build time). The key pair persists in `target/hx1e/keys`; `release-keys/*.pub` are untouched |
| Driver | emulates the 1G app: C2 frames (password, PIN, a fresh pairing token) on stdin of `install.sh --ssh`, C3 JSON Lines parsed from stdout, exit codes checked |

### Why the bridge adds no host firewall rule

The bridge is made with `ipv4.nat=false ipv4.firewall=false ipv4.routing=false ipv6.address=none ipv6.nat=false ipv6.firewall=false dns.mode=none` and no `security.acls`. In Incus 6.0.0's bridge driver (`internal/server/network/driver_bridge.go`, read from the v6.0.0 tag) the firewall options are only filled when they are asked for: `FeaturesV4` needs `ipv4.address` and `ipv4.firewall` true or empty, `SNATV4` needs `ipv4.nat` true, `ACL` needs `security.acls`, and `net/ipv4/ip_forward` is written only when `ipv4.routing` is true or empty. With those keys all three are off, and `NetworkSetup` in `drivers_nftables.go` then does nothing (no ACL, no SNAT, no features: it returns). The docs page of the bridge keys does not say this, so the source was the evidence; the daemon log of the create (`incus monitor --type=logging --loglevel=debug`) shows "Setting up firewall" and no rule. DHCP still works (dnsmasq, `dns.mode=none` only turns its DNS off): L1 got 10.77.0.x. The host's `INPUT` accepted the proxy's port without any change.

## 3. Deviations from a production host

Each is the test's; none changes what the product does. All are also in the test's module documentation.

| # | Production | In the test | Why |
|---|---|---|---|
| 1 | not a container | L1 is a container, so `--test-allow-container` | no KVM on this machine (the CI workflow uses VMs) |
| 2 | btrfs loop-file pool made by `SetupHost` | stop after stage `incus`, create the inner `hx-pool` as a `dir` pool whose description starts with the marker `hash-xcreen`, resume; `ensure_host` leaves an existing pool alone and the uninstall's teardown removes it **by that marker** (checked) | no loop devices in an unprivileged container |
| 3 | privd writes the sysctl drop-in and the values take effect | built with `privd-test-hooks` (the EPERM becomes a warning) | `vm.max_map_count` and `fs.inotify.*` are not namespaced |
| 4 | the units as shipped | a drop-in `zzzz-hx1e-test.conf` on `hx-privd` and `hx-gatewayd` re-adds `LoadCredentialEncrypted=` and `NoNewPrivileges=yes` | Incus writes `/run/systemd/system/service.d/zzz-lxc-service.conf` into every container with `LoadCredential=` (which also clears the encrypted ones) and `NoNewPrivileges=no`; without the drop-in gatewayd cannot read its identity and privd falls back to a plaintext pepper (section 7, O1). Four more keys that file relaxes (`ProtectProc`, `ProtectKernelTunables`, `ProtectControlGroups`, `ProcSubset`) stay relaxed, so those four hardening options of our units were **not** exercised |
| 5 | `systemd-creds encrypt` makes the host secret itself | `setpriv --bounding-set=-dac_read_search systemd-creds setup` once | in an unprivileged container its `linkat(AT_EMPTY_PATH)` gets ENOENT; without `CAP_DAC_READ_SEARCH` systemd takes the temporary-file path |
| 6 | `/etc/subuid` has a 4-billion range | `root:100000:900000` in both files, then `incus` restarted | the package's range starts above L1's id map and unpacking the desktop image failed with `Failed chown: Invalid argument` |
| 7 | the desktop reaches the internet through NAT | `core.proxy_http(s)` on the inner server, `environment.*proxy` on the `hx-desktop` profile, installer run with `--allow-private-networks` so the ACL lets the desktop reach the proxy's private address | with NAT off the proxy is the only way out |
| 8 | the host has `curl`, `openssl`, `acl` | installed before the run, plus an apt proxy file | the proxy |
| 9 | per-distro `.deb` | real for Ubuntu 24.04; placeholders for the other three | `build-deb.sh` must run on the distro (FFmpeg sonames) |
| 10 | real release key, GitHub download | per-run-keyed (persisted) test key through `test-release-key`; `--release-dir` | no real key exists yet |
| 11 | a real reboot | `incus restart` of L1 | |

Not reproduced at all: TPM sealing, a loop-file pool, the Zabbly repository, cloud firewalls, GitHub downloads, an internet-facing 443 (the client is on the bridge, 10.77.0.1 to L1, no NAT).

## 4. Results

Every row passed. Ubuntu 24.04 ran twice in a row from a clean host state (696 s and 779 s for the whole test), Debian 13 once (639 s). The rows below are the Ubuntu 24.04 run; Debian 13 differs only in the numbers (its rows are in the second table).

| # | Check | Result |
|---|---|---|
| 1 | Host objects | pool, bridge (no NAT, no firewall, no routing, no IPv6), profile and CONNECT proxy made; L1 launched unprivileged with nesting and an isolated idmap; no `security.privileged`, no `raw.lxc` |
| 2 | Refusals change nothing | empty stdin exit 2; `--port 22` exit 2; `--image prebuilt` exit 6; `--image-file` exit 6; afterwards no state file, no `/usr/lib/hx`, no `incus` package |
| 3 | Resume after every stage | `--test-fail-after` for preflight, packages, incus, release, system-files, credentials, config, units, setup-window, host, firewall-port, desktop, verifiers, backup, pairing, finish: each run exits 1 with code `TEST_HOOK`, nothing after the stage started, the state records it (`done`; `backup` is `deferred`), and the next run resumes. 16 runs in a chain |
| 4 | Lock | a second installer started while stage `desktop` runs (5 minutes) exits 11 with "another install or uninstall is running"; a held `/run/hx-install.lock` gives 11 as well |
| 5 | Complete install | exit 0 as `result` JSON: `ok`, a 64 hex server key, port 443, desktop path `BUILD`, pairing kind `token`; `complete: true`, mode `ssh`; stdout holds nothing but JSON lines and no secret |
| 6 | Units | `hx-privd.socket`, `hx-gatewayd-admin.socket`, `hx-gatewayd-public.socket`, `incus.socket` active; `hx-host-firewall.service` enabled; 443 listening for TCP and UDP; `systemd-analyze verify` of the installed units and of `default.target` clean (no ordering cycle) |
| 7 | Credentials | `pepper.cred` and `identity.cred` are sealed by `systemd-creds` (0600 root); there is no `pepper.key`; gatewayd loaded its identity (see the listing below); the client pinned the server key the installer reported and it matched |
| 8 | Pairing and login | the app's token pairs a device over QUIC (about 0.5 s), the PIN login works; the token is single use (a second pairing is refused); a fresh code from `hx-agent pairing code` pairs a device over WebSocket and its PIN login works |
| 9 | Stream | `ViewConfig`, then an IDR of 14.9 kB 86 to 138 ms later, from the XFCE desktop built inside L1 (`hx-session` installed by privd's `InstallSession` from the real `.deb`) |
| 10 | Secrets canary (Gate 1) | the password, the PIN, the token and its body are in none of: `/proc/*/cmdline` and `/proc/*/environ` (sampled every 50 ms for the whole run, from before the first stage), the journal, `/var/log/hx*`, the state file, `/etc/hx`, `/var/lib/hx*`, `/run/hx`, `/run/credentials`, the unit files; nor on the installer's stdout or stderr |
| 11 | Idempotence | a second run exits 0 in about 1 s; 102 files (sha256, mode, owner, mtime) identical; `install_id`, server key, mode and version unchanged; the stages `packages` to `desktop`, `verifiers` and `owner-key` are skipped |
| 12 | Port change | `--port 8443`: the socket drop-in, `gatewayd.toml` and the listeners follow, PIN login on 8443 works, 443 refuses; back to 443 the same |
| 13 | Rescue | a release whose `hx-privd` exits 1 plus a `pending` record: `OnFailure` runs `hx-privd-rescue`, `current` goes back to the previous release, the old privd runs `rollback_now` (the pending record is cleared and `rolled_back` names 9.9.9, the audit log has the rollback line) |
| 14 | Restart of L1 | `incus restart`: all sockets active, `table inet hx` loaded again, PIN login works, the inner desktop autostarts |
| 15 | Uninstall, destroy | 6 s: no file, unit, drop-in, user or state left; no `hx-*` instance, profile, network, pool (the marked dir pool the harness made included) or ACL in the inner Incus; `table inet hx` gone |
| 16 | Reinstall after uninstall | a second complete install, a new desktop built (259 s) |
| 17 | Uninstall, keep | 4 s: no leftover except what keep mode keeps (`/etc/hx/host-firewall.nft` and both firewall unit files); the desktop is kept |
| 18 | Host untouched | `incus profile show default`, `incus network show incusbr0` and `incus storage show default` unchanged (the `used_by` lists excluded, see below); no `hx1e-` object after the run |

`ls -l` and `getfacl` of the credential gatewayd loaded (Ubuntu 24.04):

```text
total 4
-r-------- 1 hx-gatewayd hx-gatewayd 32 Nov 21 21:37 identity
# file: /run/credentials/hx-gatewayd.service/identity
# owner: hx-gatewayd
# group: hx-gatewayd
user::r--
group::---
other::---
```

The "unchanged" comparison of the three default objects removes their `used_by` lists: other sessions share this machine and start and stop instances, so a user list is not configuration. The harness separately asserts that no `hx1e-` object is among the users.

### Debian 13 as the L1 host

The same test with `HX1E_DISTROS=debian-13` (L1 with `raw.apparmor=signal,`, the distro's own Incus installed by stage `incus`, systemd 257): all rows pass, including the first frame (an IDR of 14.9 kB after 138 ms), the rescue, the restart and both uninstalls. No Debian-specific change was needed in the product.

### The CI cells (not run)

`.github/workflows/installer-vm.yml` and `tests/installer-vm/` do the same on KVM VMs of ubuntu-24.04, ubuntu-26.04, debian-12 and debian-13, times `build` and `prebuilt`, plus the variants ufw (24.04), Docker on the host (Debian 13) and `--allow-private-networks` (24.04). They add what a container cannot show: the hx-provision host-ruleset checklist from inside the desktop (items 1 to 5), a real reboot with `table inet hx` loaded before `incus.service`, a loop-file pool, and the sysctl drop-in without the test hook. They could not be run here (no `/dev/kvm`); the shell scripts pass `sh -n` / `bash -n`, the workflow parses as YAML, and the client half (`installer_vm_client.rs`) compiles and shares its code with this test. Treat the first CI run as the test of the scripts themselves.

## 5. Measurements

Install duration per stage, in milliseconds, of the run in which the stage did its work (so the stage's own time; `desktop` is the build of the XFCE desktop through the proxy):

| Stage | Ubuntu 24.04, run 1 | Ubuntu 24.04, run 2 | Debian 13 |
|---|---|---|---|
| preflight | 61 | 73 | 61 |
| packages | 10031 | 10887 | 9212 |
| incus | 19515 | 20969 | 37822 |
| release | 336 | 301 | 204 |
| system-files | 583 | 409 | 186 |
| credentials | 96 | 77 | 70 |
| config | 83 | 189 | 51 |
| units | 4166 | 5660 | 3262 |
| setup-window | 31 | 41 | 28 |
| host | 2768 | 2895 | 2697 |
| firewall-port | 69 | 59 | 72 |
| desktop | 286460 | 332045 | 262903 |
| verifiers | 666 | 579 | 567 |
| backup | 0 (deferred) | 0 (deferred) | 0 (deferred) |
| pairing | 18 | 14 | 15 |
| finish | 53 | 44 | 69 |
| **sum** | **324936** | **374242** | **317219** |
| whole test for the distro | 692 s | 766 s | 623 s |

The host was shared with other sessions (load average 10 to 17), so read the numbers as rough. Without the desktop build the installer takes about 40 s on a host with a warm apt proxy (packages and `incus` are the two stages that download). Pairing took 0.4 to 0.6 s and the first frame arrived 86 to 138 ms after `ViewConfig`, over the bridge with no network latency.

## 6. Bugs found

Eight bugs of the product, each found by running the real thing for the first time, each fixed on this branch in its own commit with a regression test (the commit message says which failed before the change). None was visible to the fake-runner or in-process tests.

| # | Bug | Effect on a real host | Commit | Regression test |
|---|---|---|---|---|
| 1 | feature `install-test-hooks` did not enable `tempfile`, so `cargo build -p hx-agent --bins --features install-test-hooks` failed to compile | the harness and CI could not build the hook binary | `6d71ba4` | the harness build itself (and the `installer-vm` workflow build) uses exactly that feature set without `test-support` |
| 2 | `hx-gatewayd.service`'s `SystemCallFilter=` (`@system-service` minus groups, answering EPERM) does not allow `seccomp`, which the daemon calls to install its own allowlist (`seccomp` is in `@sandbox`) | gatewayd dies at start: "seccomp: Operation not permitted". The installer's stage `setup-window` then timed out | `cc89efa` | `gateway_unit_syscalls.rs` (first test failed before) |
| 3 | apt runs with `--no-install-recommends` and `incus` only recommends `dnsmasq-base` | `SetupHost` failed creating `hxbr0`: "Failed to check dnsmasq version" | `7046cd0` | `packages::tests`; the nested run |
| 4 | `GetHostInfo` caches its nft probe for 5 s; stage `units` reads it, `SetupHost` then loads `table inet hx`, and the `GetHostInfo` right after answered the stale "not loaded" | the first install on a clean host failed at stage `host` (a retry passed) | `aa354da` | `host_info_right_after_setup_host_sees_the_firewall_that_setup_host_loaded` (failed before) |
| 5 | `hx-privd.service` and `hx-privd-rescue.service` set `RestrictSUIDSGID=yes`; systemd cannot inspect the mode in `openat2`'s `open_how`, so every `openat2` answers `ENOSYS` | `InstallSession`, the update's extract, the release switch and the **rescue helper** all die with "Function not implemented" under the real units | `d415868` | `privd::update::beneath` tests (the injected `openat2` answers `ENOSYS`) |
| 6 | `InstallSession` pushed `/var/lib/hx/session` into the desktop, but Incus makes one directory per call and a desktop has no `/var/lib/hx` | `CreateDesktop` failed with `404 Not Found` after the 5-minute build and rolled the desktop back | `c3c2070` | the existing `install_session_reads_one_verified_package...` test failed once `FakeIncus` was made as strict as Incus, and passes with the fix |
| 7 | `hx-agent uninstall` removed `/usr/lib/hx` (which holds the running agent) before the child that empties gatewayd's state, which execs that agent as gatewayd's user | `hx-agent uninstall` failed at U5: "cannot empty gatewayd's state as its user: No such file or directory" | `643c227` | `gatewayds_state_is_emptied_while_the_agent_binary_still_exists` (failed before) |
| 8 | `var-lib-hx-updates.mount` was `WantedBy=local-fs.target` with default dependencies (so ordered before it) and `After=systemd-tmpfiles-setup.service`, which is itself after `local-fs.target`: an ordering cycle | systemd broke it at boot by **deleting the start job of `systemd-tmpfiles-setup.service`**: after a reboot `/run/hx` was missing, `hx-privd.socket` and `hx-gatewayd-admin.socket` did not start, and Incus's autostart of the desktop failed on its proxy device. It did not happen on every boot | `9496c34` | `the_fetchers_mount_is_not_a_local_fs_mount_so_it_cannot_cycle_with_tmpfiles`; the nested test and the VM cell now run `systemd-analyze verify default.target` and refuse a cycle |

Bug 5 was fixed in the code, not by dropping `RestrictSUIDSGID`, to keep that hardening. If the maintainer prefers the unit-level fix (remove the option from the two units), `open_beneath` can stay as a harmless fallback.

Also changed, not bugs: `release/make-test-release.sh` gained `--key-dir` (`a8d8da4`), because the agent embeds the test key at build time and the script made a new key per run; `docs/architecture.md` lists `dnsmasq-base` among the prerequisite packages.

### The harness found a bug in itself too

The first version of `incus::leftovers()` listed profiles, networks, pools and ACLs with `-c n`, which those commands do not accept: the command failed, its empty output read as "nothing left", and the "no `hx1e-` object left" assertion would have passed whatever was left. It now reads the first CSV column and panics when a listing fails (`dbebd07`). The same mistake in the VM cell script was fixed too.

## 7. Observations and what was not tested

### Observations (not fixed here)

* **O1. privd silently falls back to a plaintext `pepper.key`** when it has no credential directory. In L1 the Incus drop-in cleared `LoadCredentialEncrypted=` and privd started, "serving", having generated `/var/lib/hx/pepper.key` itself. The installer's `credentials` stage then found a pepper that differed from the sealed one and renamed the old file to `pepper.key.orphaned-<ts>` with a warning, which is the right recovery, but a privd that starts without its sealed pepper is a risk on any host where `LoadCredentialEncrypted=` does not take effect. Suggest: after 1E, refuse to start (or at least log at error level) when the pepper credential is missing, and keep the fallback only for tests.
* **O2. A new install over a kept desktop is not adopted.** After `--keep-desktop` the desktop stays in Incus but privd's registry (`/var/lib/hx`) is removed. A new install's stage `desktop` reports `done` and `finish` then fails with `DESKTOP_NOT_READY`. The docs promise only that a surviving desktop stays isolated, so this is a gap in the documented flow, not a regression. The test therefore does destroy mode first, a fresh install, then keep mode.
* **O3. `hx-host-firewall.service` is enabled but inactive** until the next boot (privd loads the table itself for this boot; the unit is the boot-time persistence). `systemctl is-active` on it is misleading; the checks use `is-enabled` and, after a restart, `is-active`.
* **O4. Cosmetic:** in `--ssh` mode the human text lists stage `pairing-token` as "already done" although it does not apply to that mode (the JSON line says `skip`).
* **O5. The rescue took 2 s, not the roughly 10 s of five failed starts.** Probably the start limit (5 in 300 s) had already been used by earlier starts of the unit in the same run, so the first failure reached it; this was not isolated. The path is the real one (`OnFailure`, the helper's journal line, the old privd's `rollback_now`, the cleared pending record and the audit line); a run on a fresh unit should take about 10 s.

### Not tested

* **VMs and the CI workflow**: no `/dev/kvm`. The workflow, `run-cell.sh`, `vm-cell.sh`, `checklist.sh` and `build-artifacts.sh` have never run. Specifically not exercised here: the hx-provision host-ruleset checklist, a real reboot ordering (`table inet hx` before `incus.service`), the loop-file pool, privd's sysctl drop-in applying, `--allow-private-networks` item 5, ufw, Docker on the host, DNAT drop.
* **`--docker`, Debian 12, and any host whose own Incus is too old**: the Zabbly apt key (`src/install/zabbly-key.asc`) is still `UNPROVISIONED`, so only distros with their own Incus 6.0.0 or newer were used (Ubuntu 24.04 and Debian 13). `--docker` needs Incus 6.0.5 or newer, which on those two means Zabbly. Ubuntu 26.04 was not run as an L1 either (its Incus version is not known); the CI matrix lists it.
* **The other install modes**: `--interactive`, `--pair` and `--token` (the one-liner modes stop after `pairing-token`; the post-pairing setup protocol is 1G's) and the owner key frame (EnrolOwnerKey, Phase 2).
* **Port rules**: the host had no ufw and no blocking nft chain, so the `firewall-port` stage chose `none`; the ufw, nft and manual backends ran only in the engine's fake-runner tests.
* **Updates over the network**: `CheckUpdate` and `ApplyUpdate` against GitHub; only the rescue path was run.
* **The prebuilt image path** (privd answers `UNIMPLEMENTED`; the refusal was tested, the path itself does not exist in this release).
* **Four hardening options of the units** that Incus's `zzz-lxc-service.conf` relaxes in every container (`ProtectProc`, `ProtectKernelTunables`, `ProtectControlGroups`, `ProcSubset`) were not in force, and `NoNewPrivileges` was put back by the test's drop-in.
* **TPM-sealed credentials, a real power cycle, internet reachability of 443, cloud firewalls, `apt` contending with unattended-upgrades**, a network with latency or loss, and any measurement of throughput.
* **The `hx-session` package for Debian 12, Debian 13 and Ubuntu 26.04** (placeholders in the tarball; the desktop built here is Ubuntu 24.04 on both L1 hosts).

## 8. Files

| File | What |
|---|---|
| `apps/hx-agent/tests/install_nested_incus.rs` | the ignored test and its documentation (deviations, safety) |
| `apps/hx-agent/tests/install_harness/` | `incus.rs` (host objects, cleanup, the default-object comparison), `frames.rs` (C2 encoder, with a unit test), `progress.rs` (C3 parser and the `incus exec` runner), `client.rs` (pairing, PIN login, first frame), `mod.rs` (the build of the test-keyed release, the results table) |
| `apps/hx-agent/tests/installer_vm_client.rs` | the client half of the CI cells (two ignored tests driven by environment variables) |
| `.github/workflows/installer-vm.yml`, `tests/installer-vm/{run-cell,vm-cell,checklist,build-artifacts}.sh` | the CI cells |
| `release/make-test-release.sh` | `--key-dir` |

