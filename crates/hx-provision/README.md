# hx-provision

Library used by `hx-privd`: declarative desktop recipes (`recipes/` at the repository root) and
Incus orchestration. See `recipes/README.md` for the recipe format and architecture section 4.3
for the design.

| Module | What it does |
|---|---|
| `catalog`, `recipe`, `plan`, `manifest` | Resolve a recipe (includes, vars, preset, add-ons) into a flat `Plan`; `Plan::manifest()` for the CI equivalence check |
| `exec`, `lower` | `Executor` trait, `apply_stage`, and the exact commands each step runs (apt with timeouts and retries; the password only on stdin) |
| `incus` | Typed REST client over the Incus unix socket (`hyper` + `serde`) |
| `host` | Pool, bridge with ACLs, profiles (`ensure_host`) |
| `orchestrate` | Create the container, `IncusExecutor`, readiness, `build_on_server`, `finish_prebuilt` |
| `docker` | Docker opt-in with Incus version gate and self-test |

## Tests

```text
cargo nextest run -p hx-provision          # unit tests, fake Incus daemon on a unix socket (no root needed)
```

### Tests against a real Incus (`#[ignore]`)

`tests/incus_real.rs` creates a throwaway pool, bridge, ACL, profiles and container, all named
`hx1d-test-*`, checks pool/network/ACL setup, unprivileged container, limits, readiness, the
password-via-file path, snapshots and that the ACL blocks a listener on the host (with a control
run with the ACL detached), then removes everything (also before the run, in case of leftovers).
Existing Incus objects are never touched.

The user must be allowed to use the Incus socket (member of `incus-admin`, or root):

```text
sg incus-admin -c 'cargo nextest run -p hx-provision --run-ignored only --test incus_real --no-capture'
# or with plain cargo
sg incus-admin -c 'cargo test -p hx-provision --test incus_real -- --ignored --nocapture --test-threads=1'
```

- `HX_INCUS_SOCKET`: socket path, default `/var/lib/incus/unix.socket`.
- A cached Debian 13 image is reused; otherwise `debian/13` is downloaded from the official image server.
- `HX1D_TEST_DOCKER=1` additionally runs the Docker opt-in end to end. It needs working internet
  inside the container: a host that runs Docker needs the `DOCKER-USER` accept rules for the test
  bridge (architecture 4.2), otherwise the container has no IPv4 egress and the test stops early.

`tests/incus_real_session.rs` (`HX3B_REAL=1`, objects named `hx3b-*`) builds a real recipe into an
unprivileged isolated-idmap container and checks the `hx-session` socket and service units and
the follow-up APIs against the daemon:

```text
HX3B_REAL=1 sg incus-admin -c 'cargo nextest run -p hx-provision --run-ignored only --test incus_real_session --no-capture'
```

It needs a way for the container to reach package mirrors; on a host that runs Docker it starts a
proxy bound to the test bridge's gateway only (see the module docs). `HX3B_RECIPES` selects recipes.

## Caller obligations for `hx-privd`

`hx-provision` trusts its caller. These are the rules `hx-privd` (1C) and the installer (1E) must
follow; `hx-gatewayd` and everything else unprivileged is never allowed to influence them.

- **Names and paths stay inside privd.** privd maps desktop IDs to instance names itself.
  `Naming`, `HostSpec`, `PoolSource`, `Catalog::from_dir`, instance names and
  `DockerOptions::allow_old_incus` are never taken from `hx-gatewayd` or from a client.
- **`PoolSource::Device` is installer-only.** Before `ensure_host` is given a device, the
  installer must verify that it is unused (no partitions in use, not mounted, no signature).
- **Validate limits.** `Limits` must not be zero (enforced), and privd must bound them by what the
  host has: CPUs <= host CPUs, memory leaving headroom for the host and Incus, disk within the
  pool. `limits.processes` defaults to 8192 and can never be unlimited.
- **User name.** Use `Catalog::resolve_for(.., Some(&Username))` and `resolve_addon_for`. The
  `Username` type is the only value derived from user input that reaches a recipe; the post stage
  renames the image's `desk` account when the chosen name differs.
- **Host firewall.** `ensure_host` returns `HostReport::host_firewall`, an nftables ruleset
  (`table inet hx`) that stops the desktop bridge from reaching host listeners (the ACL knows only
  unicast addresses). privd/the installer must load it with `nft -f` and keep it loaded across
  reboots; `hx-provision` never touches the host's firewall.
- **`host_addresses` must be complete** (every address of the host, including private ones and
  Docker bridge gateways), and `ensure_host` must be re-run when they change, until the nftables
  rule above is installed everywhere.
- **LAN access.** `HostSpec::allow_private_networks` (default `false`) lets desktops reach private
  networks behind the host. Expose it only as an explicit, warned installer option.
- **Post stage.** Call `orchestrate::run_post_stage` (it sweeps `/run/hx-provision` before and
  after) rather than `apply_stage` directly with a password.
- **Docker.** Check `DockerOutcome::SelfTestFailed::isolation_restored`; when `false`, retry the
  rollback or warn the user that `security.nesting` is still on.
- **Secrets are moved, never copied.** `Secret`, `Secrets`, `ExecRequest` and `Action` are not
  `Clone` and `Secret` zeroizes on drop. Build `Secrets` from the secret frames
  (`with_user_password`, `with_current_password`), hand them over by value.
- **Set a password: `password::change_user_password(&client, instance, &username, secrets,
  require_current)`.** Outside the setup window always `require_current = true`. The whole
  sequence (sweep, check, `chpasswd`, sweep) runs as one detached task, so dropping the future
  (cancel, deadline) cannot leave the 0600 file behind; answer `CANCELLED` afterwards. The check
  runs `session::PASSWORD_CHECK_HELPER <login>` with the candidate on stdin and trusts only its
  exit status (0 match, 1 wrong, anything else `CheckUnavailable`, fail closed). Contract of the
  helper: `hx_provision::session`. Map `PasswordChange::CurrentPasswordWrong` to
  `PERMISSION_DENIED` and charge the failure budget; `CheckUnavailable` is `INTERNAL`;
  `ProvisionError::NotRunning` is `FAILED_PRECONDITION`.
- **Cancel an Incus operation.** Use one `client.scoped()` per request. After dropping the
  request's futures call `client.cancel_in_flight(Duration::from_secs(30))`: `Ok(n)` cancelled
  and ended, `Err(ids)` means set `STUCK_OPERATION`. (`in_flight_operations`, `cancel_operation`
  and `wait_operation_end` are the pieces.) An operation the daemon created while a request was
  still on the wire is not known yet: check the instance during cleanup.
- **Session link.** `incus::SessionLink::new(desktop_id, (gateway_uid, gateway_gid), (1000, 1000))`
  then `client.add_session_link(instance, &link)`; nothing else can be added as a device.
  privd creates `/run/hx/link` (root:`hx-gatewayd` 0750) itself. `remove_session_link` for
  teardown.
- **Limits.** `client.set_limits(instance, &LimitsUpdate{..})` writes `limits.cpu`,
  `limits.memory` and the root disk `size` (live). Only "not zero" and absurd maxima are checked
  here; every host-dependent bound of ipc.md 6.8 is yours.
- **Settings.** Build `Settings` (`with_hostname`, `with_timezone_in(.., "/usr/share/zoneinfo")`,
  `with_locale`, `with_keyboard`) and resolve with `Catalog::resolve_with`.
- **Docker.** `docker::disable_docker(&client, instance)`; `DockerOptions { mode:
  DockerMode::HostNetworkOnly, .. }` makes `enable_docker` return `ProvisionError::Unimplemented`
  (map to `UNIMPLEMENTED`) before anything changes.
- **Teardown.** `teardown::destroy_desktop` (instance must carry `user.hx.*`, else
  `ProvisionError::NotOurs`) and `teardown::teardown_host(&client, &Naming::production())`
  (skips, and reports, any object without the hash-xcreen description). `DesktopSpec::to_create`
  sets `user.hx.state=creating`; privd moves it on. Pools and networks created by older builds have
  no description and are therefore never torn down by these helpers.
- **In-container paths.** `hx-session` installs at `session::SESSION_BINARY`
  (`/usr/lib/hx-session/hx-session`), the password helper at `session::PASSWORD_CHECK_HELPER`; the
  recipes' units use exactly these.
- **Messages.** Text that came out of a container is sanitized (control and ANSI characters
  removed, truncated) before it appears in an error or outcome, but it is still untrusted: do not
  interpret it, and escape it for any UI.

## Instance hardening and backups

Every desktop gets `security.privileged=false`, `security.guestapi=false` (no `/dev/incus`
socket), `security.idmap.isolated=true` and `limits.processes`. With isolated idmaps each
desktop has its own uid/gid range on the host, so file-level backups taken from a snapshot see
shifted ids and a restore into a *new* container (which gets a different range) needs the ids
mapped back (restore through Incus, or `incus` import, which remaps; a plain file copy does not).
Phase 2 backups must account for this.

## Output handling

No exec sets `record-output` (that would make the host write unbounded files under
`/var/log/incus` for a container that may be hostile). Output goes through
`orchestrate::exec_captured`: a wrapper writes stdout/stderr (last 64 KiB) to files in the
container's 0700 `/run/hx-provision` and the client reads them back with a size cap and deletes
them. `Client::exec` returns the exit status only. All execs in this crate (readiness,
post stage, Docker) use the bounded path, so they are safe on a container that has run user code.

## Host ruleset: installer (1E) verification checklist

`hx-provision` only generates the nftables ruleset (`HostReport::host_firewall`); the installer
loads it with `nft -f` and persists it. It parses with `nft -c -f` (checked in a throwaway
`unshare -rn` namespace by the unit tests), but nothing in this repository loads it on a host, so
the installer's CI must verify these at runtime on a fresh VM, from inside a desktop:

1. **Input drop.** A UDP listener on the host bound to `0.0.0.0` does not receive a broadcast
   (`255.255.255.255`) or a datagram sent to the gateway address from the desktop; TCP connections from the
   desktop to a host listener on the gateway address or the host's public address time out.
2. **DHCP and DNS still work.** A new desktop gets its lease, and `getent hosts example.com`
   resolves through the gateway (udp and tcp 53).
3. **Forward drop.** From the desktop, connections to an address in each of `10.0.0.0/8`,
   `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16` (for example a host
   Docker bridge gateway `172.17.0.1`, a second Incus bridge, a VPN address) time out, and a
   host port published with Docker (`-p`) or another DNAT is unreachable.
4. **Internet via NAT still works** (HTTPS to a public address) and a `docker run` inside the
   desktop can pull images (with the `DOCKER-USER` rules for a host Docker).
5. **With `allow_private_networks`** the private-range probes in item 3 succeed while item 1 and the
   DNAT drop still hold.
6. **Persistence.** After a reboot the table `inet hx` exists before the first desktop starts.

Known limit: Incus 6.0 network ACLs do not filter traffic between two instances on the same
bridge, so with several desktops on one bridge they can reach each other (v1 has one desktop).
