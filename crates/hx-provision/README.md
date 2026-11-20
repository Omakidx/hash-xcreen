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
