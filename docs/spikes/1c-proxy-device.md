# Spike 1C: Incus proxy-device semantics for the session link

Status: run complete (2026-11-21), local Incus 6.0.0 with an isolated idmap. **Verdict: PASS, with two amendments to the wording of ipc.md §11 (section 7) and two items that were not run (section 8).** Verified first, before any code builds on the link, as ipc.md §22 decision 10 requires. Contract under test: [ipc.md](../ipc.md) §11 ("Must be verified first"), items 1 to 4.

## 1. Goal

Confirm on real Incus that the Incus proxy device used as the session link behaves as §11 assumes:

1. `uid`, `gid`, `mode` of the host-side socket, and `security.uid` / `security.gid` of the connect side, so that the container-side connect arrives as the desktop user and never as the container's root.
2. Connections keep working after the container is stopped and started, and after the device is removed and re-added.
3. Throughput of at least 20 Mbps through three concurrent connections (the three lanes) with frames up to the 4 MiB cap.
4. The symlink and replacement test: nothing the desktop user does inside the container can make the proxy connect anywhere except the systemd-created socket as that user, and nothing the container does makes the proxy connect to a host path.

There is no fallback to a root-identity connect (§11, §22 decision 10): a failure would have reopened the design.

## 2. Setup

| Item | Value |
|---|---|
| Host | Ubuntu 24.04, kernel 6.8.0-151, 16 cores, no sudo (Incus through the `incus-admin` group) |
| Incus | 6.0.0 client and server, `default` btrfs pool |
| Container | `hx3a-link`, from the locally cached `images:ubuntu/24.04` image, `security.idmap.isolated=true` (host uid base 1065536, range 65536), `security.guestapi=false`, 2 vCPU, 1 GiB. Desktop user: `ubuntu`, uid and gid 1000 |
| Host sysctl that matters | `kernel.apparmor_restrict_unprivileged_userns=1` |
| Stand-in for `hx-session` | `/opt/hx-standin.py`, a Python 3 server (stdlib only) that takes the systemd-passed socket (`LISTEN_FDS=1`, fd 3), reads `SO_PEERCRED` of every accepted connection and offers `PEER` (report the credentials), `ECHO`, `SINK` (u32 LE length-prefixed frames, one ack byte each) and `SRC` (server to client frames) |
| Stand-in for `hx-gatewayd` | a Python client run as the author's own uid, connecting to the host-side socket |
| Deviation | `/run/hx/link` cannot be created without root. The host directory was `~/hx3a-link` (owner = the author, mode 0750); its socket was `~/hx3a-link/main.sock`. The host directory's ownership is not what is under test (it is plain filesystem permissions); the proxy-created socket is. The path had to be short: a scratch-area path longer than 108 bytes failed with `bind: invalid argument` (the 108-byte `sun_path` limit), which is a constraint for privd's computed path too (`/run/hx/link/<desktop_id>.sock` is at most 33 bytes) |
| Stand-in for gatewayd uid | the author's uid and gid (1000:1000 on the host; coincidentally numerically the same as the desktop user's, so the host-side owner and the container-side identity are told apart by the control runs and by `SO_PEERCRED` inside, never by the number alone) |

Units inside the container, exactly as §11 specifies:

```ini
# /etc/systemd/system/hx-session.socket
[Socket]
ListenStream=/run/hx-session/link.sock
SocketUser=ubuntu
SocketGroup=ubuntu
SocketMode=0600
DirectoryMode=0755
Accept=no
[Install]
WantedBy=sockets.target

# /etc/systemd/system/hx-session.service
[Unit]
Requires=hx-session.socket
[Service]
User=ubuntu
ExecStart=/usr/bin/python3 /opt/hx-standin.py
KillMode=control-group
```

Result of the socket unit: `/run/hx-session` is `drwxr-xr-x root:root`, `link.sock` is `srw------- ubuntu:ubuntu`; the service starts on the first connection and runs as uid 1000.

The proxy device, as `ProvisionSessionLink` specifies (§6.11), with only the host path changed:

```sh
incus config device add hx3a-link hx-link proxy bind=host \
  listen=unix:$HOME/hx3a-link/main.sock connect=unix:/run/hx-session/link.sock \
  uid=1000 gid=1000 mode=0600 security.uid=1000 security.gid=1000
```

(`uid`/`gid` here are the author's host ids, the stand-in for the gatewayd ids.)

## 3. Results

| # | Check | Result |
|---|---|---|
| 1a | Host-side socket owner and mode | `srw------- 1000 1000 main.sock` as set by `uid`, `gid`, `mode`; re-created with the same owner and mode at every start (2a, 2c) |
| 1b | Container-side identity, with `security.uid=1000` and `security.gid=1000` | `SO_PEERCRED` inside the container: `uid=1000 gid=1000` (pid shows 0: the forkproxy lives outside the container's pid namespace). Never uid 0 |
| 1c | **Control**: no `security.*` keys | `uid=0 gid=0`. The properties are what makes the difference; without them the proxy connects as the container's root |
| 1d | **Control**: only `security.uid` set | `uid=1000 gid=0`. **Both `security.uid` and `security.gid` are required**; `ProvisionSessionLink` must set both (it does, §6.11) |
| 2a | Container stop, start | After `incus stop`: connect is refused (`ECONNREFUSED`; the stale socket file is left on the host). After `incus start`: connects succeed on the first attempt, twelve in a row, as 1000:1000; the socket is recreated with the right owner and mode |
| 2b | Three forced restarts (`incus restart --force`) | Connect and `PEER` correct after each |
| 2c | Device removed, then re-added | While removed: `ECONNREFUSED` (stale socket file left). After re-add: owner, mode, identity and echo all as before |
| 2d | `hx-session.service` stopped, socket unit active | A connect starts the service on demand (systemd socket activation) and is answered as uid 1000. Matches §11 ("connections queue instead of failing") |
| 3a | Three concurrent lanes, each paced to 20 Mbps, 20 s: 1 500 B frames, 4 MiB frames (4 194 283 B payload, the cap minus kind and header), 64 KiB chunks, each frame acked | 20.00, 21.65 and 20.02 Mbps achieved, 61.7 Mbps aggregate. Ack latency p50 / max: 0.17 / 12.4 ms (1 500 B), 9.4 / 13.9 ms (4 MiB, 13 frames), 0.33 / 4.1 ms (64 KiB) |
| 3b | Three lanes, unpaced, 10 s (media lane server to client, 4 MiB frames; bulk 64 KiB; ctl 512 B, acked) | media 3 006 Mbps, bulk 707 Mbps, ctl 8 Mbps (latency-bound, ack per message; p50 0.17 ms, p99 5.2 ms). The proxy is not the bottleneck: the 20 Mbps target has about 150 times headroom |
| 4a | As uid 1000 inside the container: `unlink` and `rename` of `link.sock`; `rename` and `rmdir` of `/run/hx-session`; create a file, a symlink or a socket inside `/run/hx-session`; remove-then-symlink at the path; replace the directory by a symlink in `/run`; rename another directory over it | **All failed**: `EACCES` (directory is root-owned 0755), `EXDEV` for the rename-over case |
| 4b | Bind a different listener at `/run/hx-session/link.sock` while the socket unit runs | Failed: `EADDRINUSE` |
| 4c | `chown link.sock` to root | Failed: `EPERM`. (The owner can `chmod` its own socket; it stays reachable only by uid 1000 either way, so this is not an escalation) |
| 4d | `mount --bind` and `mount -t tmpfs` over `/run/hx-session` as uid 1000 in the container's mount namespace | Failed: `mount: must be superuser` (exit 32). Final state unchanged: no mount at the path, `link.sock` still `ubuntu:ubuntu 0600` |
| 4e | `unshare -Urm` as uid 1000 | **Not possible on this host**: `Permission denied` for any unprivileged user namespace, because of `kernel.apparmor_restrict_unprivileged_userns=1` on the host (also with `security.nesting=true` and with `raw.apparmor: userns,`). The inner-namespace case therefore could not be run as uid 1000 (section 8) |
| 4e' | Substitute: the same attack from a private user plus mount namespace created by the container's root (`unshare -Urm`): mount tmpfs over `/run/hx-session`, delete the path, bind a rogue listener there that answers `ROGUE`, while the host connects three times | The rogue listener saw **no connection**; all three host connects were answered by the real stand-in as 1000:1000. Mounts in a private namespace do not affect the forkproxy, which enters the container's own mount namespace |
| 4f | Container root (trust domain, §11) in the container's own mount namespace: mount tmpfs over `/run/hx-session`, rogue listener | With the default socket mode (0755 root) the proxy's connect as uid 1000 fails (`EACCES`, host connection reset). After the rogue also does `chmod 0666`, the proxy connects to it (`ROGUE`). **Expected and accepted**: root in the container can impersonate `hx-session` (§10 table, first row); it cannot reach anything outside the container. Restored by `umount` |
| 4g | **No host path is reachable.** Container root replaced `link.sock` by symlinks to a host-only listener's path (`/home/.../host-only.sock`) as an absolute path, `/proc/1/root/<path>`, `/proc/self/root/<path>`, `../../../../../<path>`, `/proc/1/cwd/../../../<path>` and `/../..<path>`; the host client connected after each | The host-only listener recorded **0 connections**; every connect was reset by the proxy. The connect path is resolved inside the container's mount namespace, and a host path does not exist there |

## 4. Reading of the results

- §11's central claim holds: with `security.uid=1000` and `security.gid=1000` the container-side connect is the desktop user, never root, and without them it is root (control 1c, 1d). So the properties are load-bearing and mandatory, and the design needs no fallback.
- The socket the proxy created on the host has exactly the owner and mode requested.
- The root-owned `/run/hx-session` blocks every replacement the desktop user can attempt (unlink, rename, symlink, planted socket, bind, mount). The remaining ways to redirect the link need container root, which §10 and §11 already place inside the container's trust domain.
- The proxy never reached a host path, whatever the container root arranged.

## 5. Behaviours to design for (not contradictions)

1. **A stale host socket file remains after `incus stop` and after device removal.** Connecting to it gives `ECONNREFUSED`, not a hang. gatewayd's redial-with-backoff (§19.2) covers it; `ProvisionSessionLink` is unaffected because Incus recreates the socket on start. A host-side tool must not read the stale file as evidence that the desktop is up.
2. **A connect that reaches the proxy while the container side cannot be reached is reset.** Observed in 4f (permission) and 4g (no such path): the host client sees `ECONNRESET` or `EPIPE` on the first read or write, not `ECONNREFUSED`, so the link code must treat a reset right after connect as "session not available", the same as a refusal.
3. **uid and gid numbers can coincide across the boundary.** The host-side owner (`uid`/`gid`, the gatewayd ids) and the container-side `security.uid`/`security.gid` (1000 here) are different identities. Tests for `ProvisionSessionLink` should use a host id that differs from the desktop user's.
4. **Socket-activated start works as §11 says**: the session service starts on the first connection, so `hx-session` is not running until gatewayd's first dial.

## 6. Verdict

PASS. All four items hold on Incus 6.0.0 with an isolated idmap, within the limits listed in section 8. No design change is required, and the link side of `hx-ipc` may be built as specified.

## 7. Amendments to ipc.md §11 (small, no design change)

1. §11 says the unprivileged-user-namespace variant of the test is part of item 4. On a host with `kernel.apparmor_restrict_unprivileged_userns=1` (the Ubuntu 24.04 default) an unprivileged user in the container cannot create a user namespace at all, which makes that attack unavailable there; the substitute run (4e') shows a private mount namespace has no effect on the proxy. The verification list keeps the user-namespace case for hosts that allow it (section 8).
2. §11 (and §6.11) should state that **both** `security.uid` and `security.gid` are required: with only the uid set, the connect arrives as gid 0 (control 1d). `ProvisionSessionLink` already sets both; the sentence makes the reason explicit.

## 8. Not run

| Item | Why | Residual risk |
|---|---|---|
| Host reboot (§11 item 2) | Not allowed in this environment | The device is part of the instance configuration and is recreated at instance start (verified by stop/start, restart and re-add); a reboot adds only Incus's own autostart ordering. Re-run on the first real VPS (S3-style) before the Phase 1 gate |
| Incus daemon restart | Not allowed in this environment | Proxy devices of running instances are forkproxy processes that Incus restarts on daemon start; not observed here. Re-run with the reboot |
| Unprivileged user namespace created by the desktop user (`unshare -Urm`, §11 item 4) | Blocked by the host's `apparmor_restrict_unprivileged_userns=1`; the host sysctl could not be changed (no root) | Substituted by 4e'. On a host that permits it (for example Debian 12/13 hosts, or Docker-enabled desktops where nesting may relax the profile) the same attack should be repeated; the mechanism (the forkproxy joins the container's own mount namespace, not the attacker's) predicts the same result |
| Incus versions other than 6.0.0, `security.nesting=true` desktops with Docker | One local version available | Repeat the 1c/1d controls when the minimum Incus version is raised (Docker needs 6.0.5+) |
| Real `hx-session` | Does not exist yet (1F) | The stand-in exercises the socket-activation handoff and `SO_PEERCRED`; the real daemon must use `sd_listen_fds` the same way |
| Desktop user with `sudo` | The test image's `ubuntu` user has passwordless sudo, and the attacks were run with `--user 1000` bypassing it | A desktop user with sudo is container root for this purpose and is inside the trust domain (§10); the recipe decides whether the desktop user has sudo |

## 9. Cleanup

The container `hx3a-link` (and with it the proxy device and the stale host socket) and the host directory `~/hx3a-link` were deleted after the run; `incus list`, `incus profile list` and `incus network list` showed only the pre-existing objects.
