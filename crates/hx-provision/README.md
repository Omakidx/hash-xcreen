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
- **Post stage.** Call `orchestrate::run_post_stage` (it sweeps `/run/hx-provision` before and
  after) rather than `apply_stage` directly with a password.
- **Docker.** Check `DockerOutcome::SelfTestFailed::isolation_restored`; when `false`, retry the
  rollback or warn the user that `security.nesting` is still on.
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
