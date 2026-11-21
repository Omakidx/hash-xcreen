# hx-privd

The root daemon that serves the fixed, typed command set of [docs/ipc.md](../../../../docs/ipc.md)
Part 1 over `/run/hx/privd.sock`. `hx-gatewayd`, the root CLI and the installer drive Incus only
through it. The code is the library module `hx_agent::privd`; `src/bin/hx-privd.rs` is a thin
`main`.

## Running it

```text
hx-privd.socket   (systemd creates /run/hx/privd.sock, root:hx-gatewayd 0660)
  └─ hx-privd.service   (root, started through the socket; no arguments, no environment)
```

Units and tmpfiles are in `apps/hx-agent/systemd/`; a test parses them and asserts the values of
ipc.md section 3. Startup order of the binary: `umask 0077`; process hardening (a failure is
fatal); configuration (the gateway uid from the `hx-gatewayd` passwd entry); the inherited socket;
the daemon (state directory, pepper, audit log); the account-policy self-checks (must pass). The
daemon takes **no** command-line argument and reads **no** environment variable that changes its
behaviour: every path and the gateway user are compiled in (`PrivdConfig::production`).

## Public library API

| Item | Use |
|---|---|
| `PrivdConfig::production()` | Paths and the gateway identity, from constants and `/etc/passwd` |
| `activation::from_env(path)` | The activated socket (`sd_listen_fds`), checked to be a listening unix stream socket bound to `path` |
| `hardening::apply()` | `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `mlockall` |
| `Daemon::system(cfg)` | The production daemon (real Incus socket, runner, probe, clock, audit log) |
| `Daemon::new(cfg, incus, Deps)` | A daemon over any `hx_provision::incus::Transport` and collaborators |
| `Daemon::run_self_checks()` | Re-runs the ipc.md section 3 account-policy checks; sets or clears `HOST_ACCOUNT_POLICY` |
| `Daemon::handle(request, Ctx)` | One request end to end (authorize, rate-limit, run, audit) |
| `serve(daemon, listener, ServeOptions, shutdown)` | The accept loop |
| `auth::authorize(role, request, phase)` | The pure authorization decision, table-tested |
| `privd::testing` (feature `test-support`) | `FakeIncus`, `FakeRunner`, `FakeProbe`, `Harness`, `RawClient` |

**Test-only constructors.** `PrivdConfig::for_tests`, `Daemon::new_with_catalog` and the
`testing` module exist only with the `test-support` feature. The crate enables it for its own tests
through a dev-dependency on itself; the binary never has it. The gateway uid is injected only
through `PrivdConfig::for_tests` (a test passes its own uid to be the Gateway).

## On-disk state

All under `/var/lib/hx` (the unit's `StateDirectory=hx`, 0700, root). Every write is atomic
(temporary file, `fsync`, `rename`, `fsync` of the directory). A file that exists but does not parse
is an error: privd refuses to start rather than reset a lockout or a window.

| File | Content | Mode |
|---|---|---|
| `privd-state` | JSON: phase and setup window (`return_to`, start, expiry), desktop registry with per-desktop attention flags, host-wide flags, the last `SetupHost` options | 0600 |
| `ratelimit` | JSON: `PepperVerify` failure times per purpose and the locks, `PepperEnrol` call times, current-password check times | 0600 |
| `pepper.key` | 32 random bytes, the verifier pepper, **only when there is no systemd credential** (a development run, or a host that has not migrated yet; see "The pepper") | 0600 |
| `owner-key` | the enrolled owner public key (Phase 2 shape) | 0644 |
| `updates-state` | JSON: highest accepted manifest timestamp, the verified version, a `pending` update awaiting its health check, the last automatic rollback | 0600 |
| `staging/` | privd's own verified copies: the staged manifest and signature (the artifact is an unnamed `O_TMPFILE`, never a name here) | dir 0700 |
| `updates/` | what the fetcher left: **hostile**, root-owned mode 1733, bind-mounted into the fetcher's unit, swept before every fetch | dir 1733 |

Other files privd writes: `/etc/hx/host-firewall.nft` (0600, the generated ruleset, loaded at boot
by `hx-host-firewall.service`), `/etc/sysctl.d/90-hx-incus.conf` (0644), `/var/log/hx/audit.log`
(append-only, 0640). Instance metadata is in the Incus instance config (`user.hx.state`,
`username`, `recipe`, `created`, `docker_ack`, `session_version`).

The registry exists because `hx-provision`'s client has no "list instances" call: privd manages
exactly the desktops it created (an id is written before its instance exists, so a crash leaves a
record to clean up) and never touches an instance it did not.

## The pepper

privd reads the pepper of the PIN and password verifiers (ipc.md 5.3) from the systemd credential
`pepper` (`$CREDENTIALS_DIRECTORY/pepper`, accepted only under `/run/credentials/`) when the unit has
one, else from the root-only `/var/lib/hx/pepper.key`, creating that file on first use (written to a
temporary file, synced, hard-linked into place, so it never exists half written; owner and mode are
checked on every load). A credential that is present but has the wrong length, owner or mode is an
error, never a silent fallback. The shipped unit has
`LoadCredentialEncrypted=pepper:/etc/hx/creds/pepper.cred`, so on a host that follows the steps below
the plaintext file is never created.

For the installer (1E):

* **First install:** before enabling the units, `head -c 32 /dev/urandom | systemd-creds encrypt
  --name=pepper - /etc/hx/creds/pepper.cred` (root, file 0600; sealed to the TPM where there is one,
  else to the host key). The unit does not start without the file.
* **Migrating a host that ran with `pepper.key`:** the existing pepper must be kept, or every stored
  verifier becomes invalid: `systemd-creds encrypt --name=pepper /var/lib/hx/pepper.key
  /etc/hx/creds/pepper.cred`, restart privd (the log says nothing about the source; check
  `systemctl show -p LoadCredentialEncrypted hx-privd`), then `shred -u /var/lib/hx/pepper.key`.
* Until this is done on a host with a TPM, the pepper is only as protected as a root-only file: a
  stolen disk image yields it. That is a release blocker for 1E.

## Authorization

`Daemon::handle` runs, in order: `hx_ipc` validation (done when the frame is decoded) → class →
`hx_ipc::privd::gateway_denied` (class `X`, Admin-only arguments by presence, `DeleteSnapshot` kinds,
the `SetUserPassword` current password) → phase gates (`A`: READY or SETUP_OPEN; `S`: SETUP_OPEN only;
`EnableDocker` after setup is `PERMISSION_DENIED`) → `UNIMPLEMENTED` for reserved commands → rate
limits → the command, which re-checks the rules that need state (`ISOLATION_NOT_RESTORED`, locks,
caps, ownership). The role is the peer uid and nothing else; no message has a role field.

A request that decodes but breaks a validation rule is answered `INVALID_ARGUMENT` naming the field
(ipc.md section 4 error table) and the connection stays usable: the secret frames it announced are
swallowed. `hx_ipc::privd::decode` reports such a request as a violation without a request id, so
the server re-decodes a rejected body (at most 4 KiB, where skipping `hx-ipc`'s pre-scan costs
nothing) to find the id. Anything that breaks the framing (length, kind, truncation, garbage,
ancillary data) closes the connection without a reply.

## Setup window, verifiers, audit

* **Window.** `BeginSetup` (Admin) opens it for 2 hours by default (`return_to` remembers the phase it
  came from); `ExtendSetup` (Admin) clamps the total to 24 hours; expiry closes it lazily on the next
  request and is persisted; `FinishSetup` needs a `ready` desktop unless Admin passes `force`.
* **`PepperVerify`** answers `ok` only. Failures are counted globally per purpose (PIN 10/h and
  50/day, PASSWORD 5/h and 20/day); reaching a cap locks the purpose until Admin's `ResetLockout`.
  The failure that reaches the cap is answered `ok: false`; the next call is `RESOURCE_EXHAUSTED`
  (`LOCKED`). The check, the comparison and the count happen under one lock, so concurrent callers
  cannot overshoot the cap. Wrong current passwords of `SetUserPassword` are charged to the same
  PASSWORD budget (and refused while it is locked). All counts are written to disk on every change.
* **`PepperEnrol`** returns the MAC (the only command that does): Gateway 5/day after setup and
  60/hour during `SETUP_OPEN`, Admin unlimited.
* **Audit log.** One `key=value` line per completed request (`request_id`, role, uid, pid, command,
  desktop id, outcome, duration), plus `RecordEvent` entries and notices; labels are sanitized and
  quoted, argument values are never logged.

## Cancellation and deadlines

`Cancel`, a closed connection and an expired deadline (the command's maximum from
`hx_ipc::privd::command_info`, shortened by `deadline_ms`) stop the running command:

* Secret sections (`SetUserPassword`, `PepperVerify`, `PepperEnrol`) are **shielded**: they run to
  completion; privd keeps polling `change_user_password`, holds the `desktop:<id>` lock until it
  resolves, and only then answers `CANCELLED` or `DEADLINE_EXCEEDED` (the effect of a finished
  change stands).
* Everything else is dropped, the request's Incus operations are cancelled and waited for (at most
  30 s); if one will not end, the answer is `INTERNAL` and the desktop gets `STUCK_OPERATION`.
* `CreateDesktop`: Incus 6.0.0 refuses to cancel exec operations, so privd cancels what it can,
  force-stops and deletes the unfinished instance (which ends the rest), waits for the operations and
  removes the registry record, **then** answers `CANCELLED` (or the error that stopped it).

One request per connection is in flight; one command at a time per desktop (a lock with at most 4
waiters and a 10 s wait). `Ping` is answered at once, at most 10 times a second.

## Command coverage

| Command | Status |
|---|---|
| GetHostInfo | implemented (Incus down leaves `incus_version` unset) |
| GetRecipientKey | `UNIMPLEMENTED`: sealed secrets (HPKE) are Phase 2 |
| BeginSetup, ExtendSetup, FinishSetup | implemented |
| SetupHost | implemented: `ensure_host`, the ruleset (`nft -c -f`, `nft -f`, persisted), sysctl, `DOCKER-USER`; `pool_device` is verified (block device, whole disk, not mounted or held, `blkid -p`) |
| CreateDesktop | implemented for the build path; `PREBUILT` and `image_file` are `UNIMPLEMENTED` (they need the fetcher and signature verification) |
| GetDesktop, ListDesktops | implemented |
| StartDesktop, StopDesktop, RestartDesktop | implemented |
| SetLimits | implemented; the disk floor is the configured size (see follow-ups) |
| SetUserPassword | implemented |
| EnableDocker, DisableDocker | implemented; `HOST_NETWORK_ONLY` is `UNIMPLEMENTED` |
| CreateSnapshot, ListSnapshots, DeleteSnapshot | implemented (`size_bytes` is 0: no size API) |
| ProvisionSessionLink | implemented |
| InstallSession | implemented; `FAILED_PRECONDITION` while the host has no `hx-session` package for the distro |
| RestartSession | implemented |
| CheckUpdate, ApplyUpdate, RollbackUpdate | implemented (see "Self-update"); a build whose `release-keys/` are `UNPROVISIONED` answers `FAILED_PRECONDITION` |
| DestroyDesktop | implemented |
| Uninstall | `UNIMPLEMENTED`: installer-level removal of units, credentials and the registry |
| ResetLockout, EnrolOwnerKey | implemented |
| UpgradeIncus, BeginSecretUpload, every Phase 2 command | `UNIMPLEMENTED` (reserved) |
| PepperVerify, PepperEnrol, RecordEvent | implemented |

## Self-update

ipc.md 6.12 is the contract; this is how it is built (code in `update/`, `cmd/update.rs`,
`cmd/update_resume.rs`, the fetcher in `src/fetcher/`).

* **Fetch.** `systemctl start hx-update-fetcher@manifest-<channel>.service` (or `@artifact-<version>`)
  runs `hx-update-fetcher` as a dynamic user with no capabilities and only `AF_INET`/`AF_INET6`; the
  instance is its whole argument vector. It writes `manifest.json`, `manifest.json.minisig` or
  `artifact.tar.gz` into `/var/lib/hx/updates`, bind-mounted at `/var/lib/hx-update`. privd sweeps the
  directory with `unlinkat` before every fetch and reads the three fixed names only, through a
  descriptor opened once and `openat2(RESOLVE_BENEATH|NO_SYMLINKS|NO_MAGICLINKS)`, checking the open
  file (regular, one link, size). The manifest is read into memory, the artifact is copied into an
  unnamed `O_TMPFILE` in `staging/` while being hashed; nothing is read twice.
* **Verify.** minisign (prehashed only) against the keys of `release-keys/current.pub` and `next.pub`,
  compiled in; then every manifest field; then the freshness counter (`updates-state`); then, at
  `ApplyUpdate`, size and SHA-256 of the artifact against the signed manifest. A build whose key files
  say `UNPROVISIONED` verifies nothing. 1E must put the real keys there.
* **Unpack and switch.** `extract` unpacks the verified `.tar.gz` into `/usr/lib/hx/.incoming-<v>-<rand>`
  with `openat2`, renames it to `/usr/lib/hx/<v>` after checking it is complete, then points
  `previous` at the old `current` and `current` at the new one (`symlinkat` + `renameat`, atomic).
  Two versions are kept; the rest are removed when an update is confirmed.
* **Re-exec and judge.** The old process records `pending` in `updates-state`, answers
  `restarting`, restarts gatewayd and then `hx-privd.service` itself (`--no-block`; the socket unit
  keeps the socket). The **new** process runs `Daemon::resume_update` from `serve`: privd answers on
  its socket, gatewayd is active with one `MainPID` for 30 s, gatewayd's admin socket answers
  `Status`, all within 90 s of the switch. Otherwise the links flip back, both units restart again
  and `needs_attention=UPDATE_ROLLED_BACK` is set. A new privd that starts three times without
  succeeding is rolled back too, and so is one running a version other than the one switched in.
* **Not covered by privd.** A new `hx-privd` binary that cannot start at all (a missing library, a
  bad ELF) is never seen by `resume_update`; systemd's `Restart=on-failure` retries the same binary.
  The installer should add `StartLimitBurst`/`OnFailure=` pointing at a rollback helper that lives
  outside `/usr/lib/hx/<version>` (for example a ten-line script that swaps the two links); that is a
  1E item. Unit files are not part of an artifact: a release that needs a changed unit needs the
  installer, not self-update.
* **Tests** never restart a unit or connect to a daemon: `FakeSystemd`, a fake health probe and the
  test keys are injected through `Daemon::set_update_deps`, which exists only with `test-support`.

## Unit hardening

`hx-privd.service` runs as root because it drives Incus, loads nftables and writes sysctl drop-ins.
`systemd-analyze security --offline` rates it 2.8 OK. What is set and why:

* `ProtectSystem=strict` with `ReadWritePaths=/etc/hx /etc/sysctl.d`, `-/run/xtables.lock` and
  `-/usr/lib/hx` (the release directory self-update unpacks into): the only host files it writes
  besides its own `StateDirectory` and `LogsDirectory`. `/etc/hx` and
  `/run/xtables.lock` are created by tmpfiles so that the namespace setup cannot fail.
* `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_IPC_LOCK` and `IPAddressDeny=any`: nft and
  iptables; `mlockall` as a second line next to `LimitMEMLOCK=infinity`. `CAP_DAC_OVERRIDE` is gone:
  every path privd touches (state, `/etc/hx`, `/etc/sysctl.d`, block device nodes `root:disk 0660`,
  the Incus socket `root:incus-admin 0660`, `/proc`, `/sys`, the credential directory) is owned by
  root or world-readable. The daemon sends no IP packet itself. `NoNewPrivileges`, `RestrictSUIDSGID`, `LockPersonality`,
  `MemoryDenyWriteExecute`, `RestrictRealtime`, `RestrictNamespaces`,
  `RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6` (iptables-legacy needs inet),
  `SystemCallFilter=@system-service`, `ProtectHome`, `PrivateTmp`, `ProtectKernelModules`,
  `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible`.
* **Not set, deliberately:** `ProtectKernelTunables` (`sysctl -p` writes `/proc/sys`),
  `PrivateDevices` (blkid reads host block devices), `ProcSubset=pid` (the daemon reads
  `/proc/meminfo` and `/proc/self/mountinfo`), `PrivateNetwork` (nft and iptables act on the host
  network), `RuntimeDirectory` (it would delete `/run/hx` and the socket at stop).
* `LimitCORE=0`, `UMask=0077`, `TimeoutStopSec=60s` (a cancel waits up to 30 s).

## If `hx-host-firewall.service` fails

The unit loads `/etc/hx/host-firewall.nft` before `incus.service` but is only ordered, not required:
a failure (a bad ruleset file, `nft` missing, the kernel module not loadable) does **not** stop Incus,
so desktops can start at boot without the host ruleset. The Incus network ACL on the desktop bridge
still applies (it blocks the host's unicast addresses), but not the broadcast, multicast, link-local
and forwarding rules of the ruleset (architecture 4.2). What privd does about it: at start it
re-applies the ruleset (`refresh_host`, from what the last `SetupHost` recorded) and again after a
host address change; `GetHostInfo.host_firewall_loaded` is `false` while the table is missing, which
the installer's verification and `hx-agent status` surface; and `SetupHost` can be re-run at any
time. It does not stop desktops on its own: failing closed there would take a user's desktop down
for a host firewall fault. An administrator who wants that adds `Requires=hx-host-firewall.service`
to `incus.service` through a drop-in.

## Deviations and follow-ups

* The pepper is a root-only file in the state directory, not yet sealed with `systemd-creds`.
* Host addresses are enumerated with `ip -j address show` (fixed argv, parsed with `serde_json`), not
  with a netlink socket of our own.
* Security-relevant budgets are written on every change (rarer than once a second by construction)
  rather than once a second; in-memory rate buckets are not persisted.
* `/etc/hx/privd.toml` (ipc.md section 2) is read for `[update] channel` only (a private, root-owned
  file; anything else means `stable`); the desktop cap is the compiled-in 1.
* `CreateDesktop` warns instead of failing when the host has no `hx-session` package for the distro
  (the packaging of `hx-session` and the signed artifact store are not in this release), so a desktop
  still becomes `ready`; `InstallSession` installs it later. The current-password helper ships in that
  package, so until then a current-password check outside the setup window fails closed (`INTERNAL`).
* `hx-provision` has no instance listing, disk-usage or snapshot-size API; the registry, the
  configured-size disk floor of `SetLimits` and `size_bytes: 0` follow from that.
* The automatic re-run of steps 1 to 3 of `SetupHost` (at start and 30 s after a host address
  changes) is implemented and uses what the last `SetupHost` recorded; it is covered by
  `Daemon::refresh_host` but its timing loop is not exercised by a test.
