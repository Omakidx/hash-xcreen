# Spike S3: Incus desktop on a VPS

Throwaway spike code. The report is [docs/spikes/s3-incus-desktop.md](../../docs/spikes/s3-incus-desktop.md).

| Path | What |
|---|---|
| `recipes/*.toml` | One recipe per distro x desktop x preset (they only `include` fragments) |
| `fragments/` | Shared building blocks: desktop, distro specifics, presets |
| `addons/docker.toml` | Opt-in Docker add-on (Incus config + apt repo + packages + group) |
| `addons/docker-vm.toml` | Same add-on for an Incus VM (no container-only Incus keys) |
| `runner/` | `hx-recipe`, a small Rust program that applies a recipe with the `incus` CLI |
| `build.sh` | Build-on-server path: launch base image, apply recipe, time it |
| `prebuilt.sh` | Prebuilt path: publish, export, import, launch, post-steps |
| `measure.sh` | Idle RAM/CPU, screenshot from inside the container |
| `docker-test.sh`, `snapshot-test.sh`, `net-test.sh` | Docker, btrfs snapshot and network ACL checks |
| `run-on-vps.sh` | Repeats everything on a fresh Ubuntu 24.04 / 26.04 or Debian 13 VPS (as root) |
| `vps-matrix.sh` | VPS run: build, host overhead + idle at the minimum spec and at the host maximum, prebuilt path (Incus already installed) |
| `vm-test.sh`, `acl-docker-test.sh`, `apparmor-try.sh` | Incus VM desktop with Docker; ACL against nested Docker containers; narrow `raw.apparmor` trials |
| `results/` | Raw logs and screenshots from the local runs |
| `results-vps-2026-11-20/` | Raw logs and screenshots from the VPS run |

Local use (needs `incus` access; the runner is built with `cargo build --release` in `runner/`):

```sh
./build.sh recipes/debian-13-xfce-basic.toml s3-deb 2 4GiB
./measure.sh s3-deb results/deb 90 60
./runner/target/release/hx-recipe apply recipes/debian-13-xfce-basic.toml s3-deb --addon addons/docker.toml
```
