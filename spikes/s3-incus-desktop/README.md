# Spike S3: Incus desktop on a VPS

Throwaway spike code. The report is [docs/spikes/s3-incus-desktop.md](../../docs/spikes/s3-incus-desktop.md).

| Path | What |
|---|---|
| `recipes/*.toml` | One recipe per distro x desktop x preset (they only `include` fragments) |
| `fragments/` | Shared building blocks: desktop, distro specifics, presets |
| `addons/docker.toml` | Opt-in Docker add-on (Incus config + apt repo + packages + group) |
| `runner/` | `hx-recipe`, a small Rust program that applies a recipe with the `incus` CLI |
| `build.sh` | Build-on-server path: launch base image, apply recipe, time it |
| `prebuilt.sh` | Prebuilt path: publish, export, import, launch, post-steps |
| `measure.sh` | Idle RAM/CPU, screenshot from inside the container |
| `docker-test.sh`, `snapshot-test.sh`, `net-test.sh` | Docker, btrfs snapshot and network ACL checks |
| `run-on-vps.sh` | Repeats everything on a fresh Ubuntu 24.04 / Debian 13 VPS (as root) |
| `results/` | Raw logs and screenshots from the local runs |

Local use (needs `incus` access; the runner is built with `cargo build --release` in `runner/`):

```sh
./build.sh recipes/debian-13-xfce-basic.toml s3-deb 2 4GiB
./measure.sh s3-deb results/deb 90 60
./runner/target/release/hx-recipe apply recipes/debian-13-xfce-basic.toml s3-deb --addon addons/docker.toml
```
