# hx-agent(8)

`hx-agent` is the local administration tool of a hash-xcreen server. It runs **as root, on demand**
(architecture section 2) and talks to two daemons and nothing else:

* **`hx-gatewayd`** through its admin socket `/run/hx/gatewayd-admin.sock`
  ([ipc.md](../../../../docs/ipc.md) section 9): devices, pairing credentials, PIN and password
  verifiers, the gateway's mirror of the setup window;
* **`hx-privd`** through `/run/hx/privd.sock` as the `Admin` role (uid 0, ipc.md Part 1): host and
  desktop facts and operations, lockout reset, updates, uninstall.

The code is the library module `hx_agent::cli`; `src/bin/hx-agent.rs` is the process shell. The
socket paths are constants: no flag or environment variable moves them, and the program reads **no
environment variable at all**.

## Synopsis

```text
hx-agent [--json] <command> [options]

status
devices list | revoke <id-prefix> | reinstate <id-prefix> [--yes]
pairing code [--ttl 15m]
pairing token [--ttl 15m] [--generate | --token <t> --token-on-command-line]
pin set [--device <id-prefix>]
pin reset-lockout [--purpose pin|password] [--yes]
setup begin [--for 2h] [--yes] | extend <time> | finish [--force]
desktop start|stop|restart [--force] [--desktop main]
desktop limits [--cpu N] [--memory-mib N] [--disk-gib N] [--desktop main]
desktop password [--verifier-only] [--desktop main]
docker enable [--yes] [--desktop main] | disable [--desktop main]
snapshots list|create [--desktop main] | delete <name> [--desktop main]
logs [-f|--follow] [-n <lines>] [--journal] [--audit]
update check | apply [<version>] [--yes] | rollback [--yes]
uninstall [--keep-desktop | --destroy-desktop] [--yes]
install --interactive | --pair | --ssh | --token <t> --token-on-command-line  [options]      (see "install" below)
port-rule apply
help [command]    --help    --version
```

Durations are seconds or take a suffix: `90`, `15m`, `2h`. `--desktop` defaults to `main` (v1 has
exactly one desktop).

## Root only

Every command except `help` and `--version` refuses to run unless the **real and the effective**
uid are both 0 (exit 7, "hx-agent must run as root"): a setuid-root copy run by an ordinary user is
refused like that user. The sockets enforce it as well (`SO_PEERCRED`); the check gives a clear
message first. Run it with `sudo hx-agent ...`.

The CLI also checks **who it talks to** before it writes anything: each socket must be a socket (not
a symlink) owned by root in a directory owned by root and not writable by group or others, and
`SO_PEERCRED` of the connected socket must say root. A socket that fails is refused, so a stand-in
placed in a writable directory never receives a token, a verifier or a command.

## Commands and what they call

| Command | Calls |
|---|---|
| `status` | privd `GetHostInfo`, `ListDesktops`; gatewayd `Status`, `ListDevices`. Reports versions, setup phase and window, desktop state, `needs_attention` flags, lockouts and device counts. Each daemon is reported on its own; exit 3 if either is unreachable. |
| `devices list` | gatewayd `ListDevices` |
| `devices revoke <id>` | gatewayd `ListDevices` (to resolve the prefix), `RevokeDevice` (closes the device's live sessions) |
| `devices reinstate <id>` | gatewayd `ListDevices`, `ReinstateDevice` (lifts a revocation or a PIN lockout of that device and resets its failure counter; a revoked device is shown in full and a typed `yes` (or `--yes`) is required) |
| `pairing code` | gatewayd `CreatePairingCode`. Prints the short code once. |
| `pairing token` | gatewayd `CreatePairingToken` (the token as a secret frame). See "Secrets". |
| `pin set` | hidden prompt (twice); Argon2id in the CLI; privd `PepperEnrol` (purpose `PIN`); gatewayd `ListDevices` (with `--device`), `SetPinVerifier` |
| `pin reset-lockout` | privd `ResetLockout`. Asks for a typed `yes` unless `--yes`. |
| `setup begin` / `extend` / `finish` | privd `BeginSetup` / `ExtendSetup` / `FinishSetup`, then gatewayd `SetupWindow` (open / extend / close), so that both agree. If gatewayd cannot be updated the command fails and says privd already changed. |
| `desktop start` / `stop` / `restart` | privd `StartDesktop` / `StopDesktop` / `RestartDesktop` |
| `desktop limits` | privd `GetDesktop`; with a value, `SetLimits` (the fields not given keep their current value). Says when a restart is needed. |
| `desktop password` | hidden prompt (twice); privd `SetUserPassword` (secret frame; Admin needs no current password), `PepperEnrol` (purpose `PASSWORD`); gatewayd `SetPasswordVerifier`. `--verifier-only` skips the first call: it only refreshes gatewayd's verifier after the password was changed inside the desktop with `passwd`. **privd has no check-only command, so that password is not verified against the desktop**: it is typed twice and the CLI says so; a wrong entry makes re-pairing by password fail until the command is run again (`verified_against_desktop` is false in the JSON). |
| `docker enable` | privd `EnableDocker`. Shows the isolation warning and asks for a typed `yes` unless `--yes`; progress goes to stderr. |
| `docker disable` | privd `DisableDocker` (restarts the desktop) |
| `snapshots list` / `create` / `delete` | privd `ListSnapshots` / `CreateSnapshot` / `DeleteSnapshot` |
| `logs` | `journalctl` and the audit file, see below |
| `update check` / `apply` / `rollback` | privd `CheckUpdate` / `ApplyUpdate` / `RollbackUpdate`. The CLI does no update logic. `UNIMPLEMENTED` is reported as exit 6. `apply` without a version applies what `check` found; both ask for a typed `yes` unless `--yes`. |
| `uninstall` | privd `Uninstall` plus the CLI's own steps U1 to U8. A guided flow, see below. |
| `install` | The installer engine (`hx_agent::install`), see below. |
| `port-rule apply` | Re-applies the nftables accept rule for the public port. Run by `hx-agent-port.service`. |

### Device ids

A device is named by the hex of its 16-byte id or an **unambiguous prefix** of at least 4 hex
digits. The prefix is resolved against the live registry: no match is "not found", several matches
is "ambiguous" and lists the candidates (exit 5); the CLI never guesses. Device names are untrusted
text, shown for convenience, and never select a device. `devices list` shows 12 digits of the id;
`--json` has all 32.

### logs

* **journal**: `journalctl --no-pager --output=json --lines <n> [--follow]` with the match
  `(_SYSTEMD_UNIT=hx-privd.service AND _UID=0) OR _SYSTEMD_UNIT=hx-gatewayd.service`. The argv is
  built from constants and the line count only; the environment is cleared, no shell is used. The
  match uses fields only journald sets, so a local user who writes to the journal cannot make a line
  look like privd's (ipc.md section 8). Each entry is shown as `<time> <unit> [pid] message` from
  the trusted `__REALTIME_TIMESTAMP`, `_SYSTEMD_UNIT` and `_PID`; the sender-controlled
  `SYSLOG_IDENTIFIER` is never shown, and a multi-line message is folded onto one line.
* **audit log**: `/var/log/hx/audit.log`. The directory is opened `O_DIRECTORY|O_NOFOLLOW` and
  checked with `fstat` (root-owned, not writable by group or others); the file is opened relative to
  that descriptor with `O_NOFOLLOW|O_NONBLOCK` (a FIFO cannot hang it) and checked with `fstat`
  (regular, root-owned, not writable by others), also after every rotation. A rotation is followed
  by reading the old file to its end first.
* Without `--journal` or `--audit` both are shown. `--follow` streams new journal lines and lines
  appended to the audit log (following a rotation) until Ctrl-C or until `journalctl` ends. With
  `--json --follow` every line is one JSON object `{"source":"journal"|"audit","line":"..."}`.
* Every line is cut to 4096 bytes and sanitized.

### uninstall

Asks whether to keep the desktop (deleting it is never the default; with `--yes` you must say
`--keep-desktop` or `--destroy-desktop`), asks for a typed confirmation (`uninstall` or `destroy`),
then runs, under the lock `/run/hx-install.lock` (exit 11 if an install or uninstall is running):

| Step | What |
|---|---|
| U1 | `systemctl disable --now` the gateway units (the public and admin sockets and the service), so no gateway traffic arrives during the uninstall |
| U2 | privd `Uninstall` (what privd created: the desktop and Incus objects in destroy mode, the firewall table, the link devices) |
| U3 | stop and disable privd's units, the fetcher and the updates mount (destroy mode: the firewall units too) |
| U4 | remove the port rule (ufw, nft by comment) and its unit |
| U5 | remove the files and directories; gatewayd's state is emptied by a child that runs as the `hx-gatewayd` uid and gid (`ipc.md` 7 rule 15), never walked by root |
| U6 | `userdel hx-gatewayd` |
| U7 | `daemon-reload`, `reset-failed` |
| U8 | drop the resume file `/var/lib/hx-uninstall.json` |

Every step is idempotent and recorded, so a run that stops resumes after the last finished step.
Keep mode leaves `/etc/hx/host-firewall.nft` and both firewall units. From keep to destroy is
allowed only until privd's part is done; from destroy to keep never (exit 12). Incus and the Zabbly
repository stay installed, and the result says how to remove the repository. If privd answers
`UNIMPLEMENTED` (an old privd), or cannot be reached and cannot be started, the CLI puts the gateway
units back, prints the manual steps for the chosen mode, changes nothing and exits 6. It never runs
those steps itself.

### install

`hx-agent install` is run by `install.sh` (`--bootstrap-dir <dir> --lock-fd 9`), or by hand. It
checks the host (Ubuntu 24.04 or 26.04, Debian 12 or 13, x86_64, systemd 250 or newer, not a
container, 3584 MiB, 2 CPUs, 30 GiB), then runs 19 stages: preflight, packages, incus, release,
system-files, credentials, config, units, setup-window, host, firewall-port, pairing-token, desktop,
verifiers, owner-key, backup (deferred: Phase 2), pairing, finish, done. State is
`/var/lib/hx/install-state.json`; the log is `/var/log/hx-install.log`. Nothing secret is ever in
an argument, an environment, a log or the state.

| Mode | Behaviour |
|---|---|
| `--interactive` | asks every question on `/dev/tty` before any change; ends with a pairing code |
| `--pair` | the one-liner: the token is typed at a hidden prompt; the stages run through `pairing-token` and stop, the setup window stays open for the app |
| `--token <t>` | like `--pair` with the token on the command line (weaker: a warning is printed); refused (exit 2) without `--token-on-command-line` |
| `--ssh` | the secrets arrive on stdin (framed: `HXI1`, then records of kind, length and bytes: password, PIN, optional token and owner key; at most 8192 bytes in 30 s); `--json` is implied; the token, if any, is installed last |
| none | resume or re-verify the recorded install; a fresh host refuses (exit 2) |

A run again resumes and converges: a stage is skipped only when it is recorded as done and its
check still passes. `pairing-token`, `pairing` and `finish` are never skipped (a token or code must
be fresh). A changed option that cannot change after its stage is done (`--user`, `--distro`,
`--docker`, `--storage-device`, ...) is exit 12 with the command that changes it. `--image-file`
implies `--image prebuilt` (exit 2 together with `--image build`); preflight checks its signed
manifest, entry, size and SHA-256 (exit 10 when they do not verify, exit 9 for an unusable file or
too little disk).

The port rule (stage `firewall-port`): with ufw active, `ufw allow <p>/tcp` and `/udp`; else, if a
native nftables input chain drops, one rule `meta l4proto { tcp, udp } th dport <p> accept comment
"hx-agent-port"` inserted at the **top** of that chain, before every other rule, so the chain's own
drop rules cannot shadow it (it also comes ahead of anything the administrator put first on
purpose, such as a fail2ban or geo-blocking rule: for this port, every source is accepted).
With ufw or a dropping nftables firewall the stage also lets the desktop's bridge `hxbr0` through (input udp 67 and udp/tcp 53; forward from the bridge, nft also related and established out), because the build needs DHCP, DNS and forwarding: ufw `allow in on hxbr0 ...` and `route allow in on hxbr0` (no out-on-bridge rule: ufw already accepts related and established replies), nft rules with the comment `hx-agent-bridge:<kind>`. They are recorded, converged, adopted and removed like the port rule. Because they come before the administrator's own rules, an outbound policy in the host's forward chain does not apply to the desktop's traffic; only `inet hx` filters it (architecture §5.3). `hx-agent-port.service` brings the nft rules back after a ruleset reload. The planned rule is recorded in the
state before it is inserted. Uninstall finds our comment in every input chain, falls back to
searching by comment when the state is unreadable, and does not delete a ufw rule that already
existed before the installer ran (recorded as `adopted`).

With `--json` standard output is only JSON Lines (`stage`, `step`, `warn`, `result`; `docs/ipc.md`
and the installer design C3) and human text goes to standard error.

Install exit codes besides 0 to 8: 9 preflight failed (nothing changed), 10 verification failed
(signature, digest, version), 11 another install or uninstall is running, 12 the options conflict
with the existing install.

## Secrets

A Linux password, a PIN and a pairing token are **only** ever

1. typed at a hidden prompt on `/dev/tty` (echo and signal characters off while typing, restored
   afterwards on every exit path; the terminal's interrupt, quit and suspend characters abort the
   prompt; SIGTERM, SIGHUP, SIGQUIT, SIGINT and SIGTSTP are held back until the terminal is
   restored; the prompt reads the terminal, never stdin, so a pipe cannot feed one), or
2. generated by the CLI (`pairing token --generate`, shown once),

held in zeroizing memory, and sent as a **kind-2 secret frame** (ipc.md 5.2): never in argv, the
environment, a file, a protobuf field or a log. `--password` and `--pin` do not exist (they are
refused with an explanation).

`pairing token --token <t> --token-on-command-line` exists for **unattended** installs only; without
the explicit flag `--token` is refused (exit 2), so a token never reaches argv by accident. It is
**weaker**: the token is
visible in the process list while the command runs, stays in your shell history, and under `sudo` is
written to the auth log and the journal. A token is single use and expires (15 minutes), which
bounds but does not remove that exposure. The command prints that warning every time. The default,
`pairing token` without options, is the hidden prompt (decision 14 of ipc.md section 22).

### What is and is not protected in memory

The CLI process disables core dumps and `PR_SET_DUMPABLE` and, as root, locks its memory
(`mlockall`) before it reads anything; if the lock fails it says so on stderr before any prompt, and
a typed secret could then be swapped out. A typed secret, a generated token, the Argon2id input and
the token from `--token` are kept in zeroizing buffers that are wiped on drop, Argon2id wipes its
memory blocks (`zeroize` feature), and the copies of the command line made while parsing are wiped.
These copies remain, and nothing here can remove them:

* the **original argv** of the process (the kernel keeps it; `/proc/<pid>/cmdline`, the shell
  history and, under `sudo`, the auth log hold a `--token` value);
* a **generated token or pairing code in `--json` output**, which is built as a JSON value and
  written through the usual output buffers (in text mode both are written to the terminal straight
  from a zeroizing buffer, once);
* the kernel's terminal and pipe buffers, and the operator's scrollback.

A token is single use and short lived, which bounds these exposures.

Usage errors never repeat what was typed: an argument that does not belong may be a secret typed in
the wrong place.

## Untrusted text

Everything that came from gatewayd, privd, Incus (through privd) or journald is untrusted. It is
sanitized when it enters the CLI (`hx_ipc::text::sanitize_text`: control characters including ESC,
format characters such as bidi overrides and zero-width characters, line separators, and a length
bound), and **everything** written to stdout, in text and in `--json`, is scrubbed once more, so no
terminal escape sequence, bidi control or forged line can reach the operator's terminal.

## Confirmations

`devices reinstate` (of a revoked device), `setup begin`, `pin reset-lockout`, `docker enable`, `update apply`, `update rollback` and `uninstall` ask the
operator to type a word (`yes`, `uninstall`, `destroy`) on the terminal, after printing what the
action does. `--yes` answers for scripts; there is no other way around the question (no terminal and
no `--yes` is exit 8). `pin reset-lockout` clears the **whole** failure history of the purpose, not
only the lock, so an attacker's recent guesses stop counting; privd writes it to the audit log with
the role `admin`.

## Output and exit codes

Human output goes to stdout; errors, warnings and progress go to stderr (`hx-agent: error: ...`).

`--json` prints exactly one JSON object on stdout (and nothing on stderr, progress included), except
`logs --follow` (one object per line):

```json
{"ok": true,  "command": "devices revoke", "data": { ... }}
{"ok": false, "command": "devices revoke", "error": {"code": "NOT_FOUND", "detail": "...", "message": "..."}}
{"ok": false, "command": "docker enable",  "data": { ... }}
```

`ok` is true exactly when the exit code is 0. A command that did its work only in part, or whose
outcome is a refusal that carries data (`status` with a daemon down, `docker enable` on an Incus that
is too old, `uninstall` with its manual steps), has `ok: false` and a `data` member instead of
`error`. The members of `data` are stable: they are asserted exactly by `tests/cli_json.rs`; new
members may be added, existing ones are not renamed or removed within a major version. Enum values
are the names of the wire schema without their prefix (`READY`, `PIN_LOCKED`, `UBUNTU_24_04`).
Times are Unix seconds with the suffix `_unix_s`.

| Exit | Meaning |
|---|---|
| 0 | Success |
| 1 | Failed: an internal error, a protocol violation, a half-finished operation (the message says what is already done) |
| 2 | Usage error: unknown command or option, a value out of range, a secret given as an option |
| 3 | A daemon is unavailable: socket missing or refusing, timeout, or the daemon answered `UNAVAILABLE` |
| 4 | Refused by the server: `PERMISSION_DENIED`, `FAILED_PRECONDITION` (wrong phase, setup window closed, no ready desktop), `RESOURCE_EXHAUSTED` (rate limit, a lock), `INVALID_ARGUMENT`; also a Docker outcome that changed nothing |
| 5 | Not found: unknown device, desktop or snapshot, or an ambiguous id prefix |
| 6 | Not implemented in this release (`UNIMPLEMENTED`), for example `update` on a privd without self-update and `uninstall` (manual steps printed) |
| 7 | Not root |
| 8 | Declined: the operator did not confirm, or there was no terminal to ask on |
| 9 | `install`: preflight failed, nothing was changed |
| 10 | `install`: a signature, digest or version check failed |
| 11 | `install`, `uninstall`: another install or uninstall is running |
| 12 | `install`, `uninstall`: the options conflict with the existing install |

## Not implemented here

* **Offline registry edits** when gatewayd is down (ipc.md section 9 says `hx-agent devices` *may*
  do them, as the gatewayd uid after `setresuid`): `devices` needs gatewayd running.
* `owner enrol` (the Phase 2 `EnrolOwnerKey`) and the Phase 2 backup commands.
* `UpgradeIncus` (reserved, `UNIMPLEMENTED` in privd).
