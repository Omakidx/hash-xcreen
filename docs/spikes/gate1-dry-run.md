# Gate 1 dry run on a real VPS (2026-11-23)

A rehearsal of the Gate 1 checks on the maintainer's VPS before the release keys exist. It used a
**test-keyed** build (`tests/installer-vm/build-artifacts.sh` with `HX_SKIP_IMAGE=1`) and the
installer-vm cell steps driven over SSH instead of `incus exec`. It does not tick a Gate 1 box: the
gate run repeats this with the real signed release and the real app.

## Host

- Ubuntu 26.04, kernel 7.0.0-43, systemd 259, AppArmor 5.0.2, KVM, 4 vCPU, 7.9 GB RAM, 193 GB disk.
- Not fresh at first: an earlier Incus with an `hxbr0` network and a pool, which were removed
  (packages purged) before the runs. Docker 29.9 with the maintainer's own images and volumes stays
  on the host; the installer only reports it, and the checklist below covers it.
- Round trip from the test machine: 14 ms.

## Results

| Check | Result |
|---|---|
| Install over the SSH path (`install.sh --ssh`, secrets as stdin frames, as the app sends them), `--image build` | **Pass** on the third run, after the two defects below were fixed. Exit 0, port rule `nft`, `path_taken` BUILD / `build_requested`. Stages: about 5 min in all, of which the desktop build 283 s and Incus 14 s. |
| Re-running a failed install resumes and succeeds | **Pass**: stopped on purpose after `incus` and after `host` (`--test-fail-after`); each re-run skipped what was done and the final run completed. |
| Units, port and credentials | **Pass**: units active, 443 on TCP and UDP, `systemd-analyze verify` clean, credentials sealed (no `pepper.key`). |
| Pairing and PIN login over the internet | **Pass**: QUIC with the install token in 532 ms, WebSocket with a pairing code in 382 ms; the first frame of the real desktop (an IDR of 14.9 kB) 86 ms after the view request. |
| Wrong PIN ×5 revokes the device; a revoked device cannot connect | **Pass**: backoffs of 1, 2, 4 and 8 s, revoked by the fifth wrong PIN, the right PIN then refused with `UNAUTHORIZED` (`vm_wrong_pin`, PR #68). |
| No secret in any command line, log or process list | **Pass**: `/proc/*/cmdline` and `environ` sampled every 50 ms through the whole run, plus the journal, `/var/log/hx*`, the state file, `/etc/hx`, `/var/lib/hx*`, `/run/hx`, `/run/credentials` and the units. |
| Host-ruleset checklist from inside the desktop, with Docker on the host | **Pass**: items 1 to 4 and the Docker-published port unreachable. |
| Idempotence | **Pass**: a second run changed none of 171 files. |
| Idle ≈ 0 CPU and bandwidth | **Pass**: desktop container about 0.001 of a core, `hx-session` 56 ms of CPU per minute, `hx-gatewayd` 0, `hx-privd` about 0.0001; 0 bytes on the bridge in 60 s. Desktop memory 207 MiB. |
| Uninstall and leftovers | **Pass** (twice, `--destroy-desktop`): nothing the installer created remained; Incus stays installed by design. |

## Defects found and fixed

1. **The Firefox PPA outage broke the desktop build** (PR #66). Launchpad answered 503 for the
   mozillateam PPA; `apt-get update` only warned and dropped the PPA with its pin, so apt chose
   Ubuntu's transitional `firefox`, which installs a snap that cannot work in an unprivileged
   container. Fixed: `apt-get update --error-on=any` in every recipe step, Ubuntu's `firefox` pinned
   to -1, the PPA's current key on 24.04. privd's answer for a failed step now keeps the end of
   the output (the error was cut off at 256 bytes) and the full text goes to the journal.
2. **A systemd update cut the desktop's network** (PR #67). On this host's AppArmor 5.0 the
   container's systemd could not signal the old process of a restarted service; when the security
   update restarted `systemd-networkd`, two copies fought over `eth0` and DNS was gone. The
   `signal,` rule that Debian 13 already needed now applies to every desktop. Without the dry run,
   every Ubuntu desktop on such a host would have lost its network at its first systemd update.

Also fixed on the way: the gateway setup tests' race with the setup window's tick (PR #65).

## Not covered here

- **The one-liner path** (`install.sh --pair`, then setup from the app over `INTENT_SETUP`): needs
  the app's setup flow against the server; covered by the local end-to-end tests, not yet run on
  the VPS.
- **The real app** (the Add server wizard, the desktop view): this run used the headless test
  client. The gate run uses the app.
- **Typing and scrolling at most 1.5 cores, and added latency at most 40 ms p95 on a LAN**: the test
  client cannot inject input, and the VPS is not on a LAN. These need the app (or the perf suite)
  against a LAN host.
- **A host reboot** and the **rescue** path (a failing update rolled back): covered by the
  installer-vm cells, not repeated on the maintainer's server.
- **The real release keys**: the gate run installs the signed release.
