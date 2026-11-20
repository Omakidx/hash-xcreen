# Desktop recipes

One declarative recipe describes one desktop: distro x desktop environment x preset. The
`hx-provision` crate (`crates/hx-provision`) parses, validates and resolves recipes into a flat,
ordered plan and applies that plan inside an Incus container. The same plan drives both ways of
getting a desktop (architecture section 4.3):

- **prebuilt image**: CI runs the *build* stage weekly and publishes a signed image; the server
  imports it and runs the *post* stage;
- **build on the server**: the server launches the official base image, runs the *build* stage,
  then the *post* stage.

## Layout

```
recipes/
  <distro>-<desktop>-<preset>.toml     one file per shipped combination (the "recipes")
  fragments/xfce-desktop.toml          headless Xorg + XFCE + PipeWire (distro independent)
  fragments/distro-<distro>.toml       base image, vars, browser, per-distro apt repositories
  fragments/preset-<preset>.toml       basic, developer
  addons/docker.toml                   opt-in add-ons, chosen at resolve time
```

Shipped distros: `ubuntu-24.04`, `ubuntu-26.04`, `debian-12`, `debian-13`. Desktop: `xfce`.
Presets: `basic` (XFCE, browser, file manager, text editor), `developer` (basic + VS Code, git,
build tools, Claude Code, Codex CLI). Add-on: `docker`.

## Format

A recipe is a TOML file. A top-level recipe is usually only `include` plus `[recipe].name`.

**Merging.** `include` lists files, relative to the including file, loaded in order. Tables merge
recursively, arrays concatenate in order, and for scalars the later value wins (the including file
last). Add-ons are merged after the recipe, in the order requested. An include may not leave the
recipes root directory, may not be absolute, may not form a cycle and may nest at most 8 deep.

**Variables.** `[vars]` holds string values (`distro`, `codename`, `distro_version`, `desktop`,
`preset`; `user` is added from `[user].name`). `{{name}}` in any string value of the merged recipe
is replaced; an unknown name is an error that names the key. `{{` is reserved for this; `[vars]`
values themselves are not expanded.

**Unknown keys are errors**, everywhere, so typos fail loudly.

| Section | Meaning |
|---|---|
| `[recipe]` | `name` (required), `base_image` (required, `images:debian/13`-style alias on the Incus image server, or `local:<alias>`). |
| `[vars]` | String variables, see above. |
| `[incus_config]` | Instance configuration applied to the container, not content inside it. Only `security.nesting` and `security.syscalls.intercept.*` are allowed; `security.privileged` is always rejected (desktops are unprivileged). Used by the Docker add-on. |
| `[[apt_repo]]` | `name`, `key_url`, `key_fingerprint` (40 hex characters), `uri`, `suite`, `components`, optional `pin` (apt preferences body). The downloaded key must contain exactly the pinned primary key fingerprint or the step fails. Written as a deb822 `.sources` file with `Signed-By`. |
| `[apt]` | `packages`: installed with `--no-install-recommends`; duplicates are removed, first occurrence wins. |
| `[user]` | `name`, `uid`, `shell`, `groups`, `linger`. The desktop user is created locked (no password); the password is set in the post stage from a secret handed over at run time. An add-on may add `groups` only. |
| `[[file]]` | `path` (absolute), `content`, `mode` (default `0644`), `owner` (default `root:root`). A path may appear only once. |
| `[services]` | `system_enable` (`systemctl enable`), `user_enable_global` (`systemctl --global enable`, started by the user's lingering manager). |
| `[[pre_step]]` | Shell commands that run after apt repositories are configured and before packages are installed. |
| `[[step]]` | Shell commands that run at the end of the build stage. |
| `[[post_step]]` | Shell commands that run in the post stage, after security updates. |

Step fields: `name` (required, unique within its list), `run` (required, executed with
`bash -euo pipefail -c`), `enabled` (default `true`), `as_user` (run as the recipe user, default
`false`), `optional` (a failure is reported as a warning instead of failing the stage, default
`false`), `timeout_secs` (default 1800, at most 7200).

### Stages and ordering

Build stage (also what the prebuilt image CI runs): wait for network, apt bootstrap, apt
repositories, `pre_step`, apt install, user, files, services, `step`.

Post stage (always runs, after a prebuilt import and after a server build): wait for network,
ensure the user exists, set the password (secret, via stdin of `chpasswd` from a 0600 file, never
argv), security updates, `post_step`.

Every apt invocation is bounded: apt's own HTTP timeouts and retries, a hard `timeout` per attempt
and several attempts. In S3, `apt-get update` hung for over nine minutes twice.

### Secrets

Recipes contain no secrets, and the validator rejects nothing that could hold one by design: the
only secret in the system, the desktop user's Linux password, never appears in a recipe. It is
supplied by the caller at run time. Vendor installers in `post_step` must not need credentials.

## Adding a recipe

1. New distro: add `fragments/distro-<name>.toml` with `base_image` and the vars, and one recipe
   file per preset. Extend the `Distro` enum in `hx-provision` (the `every_shipped_recipe_resolves`
   test fails until recipes, enum and embedded file list agree).
2. Pin every new apt repository by full key fingerprint.
3. Run `cargo nextest run -p hx-provision`; golden plans under `crates/hx-provision/tests/golden/`
   are refreshed with `HX_UPDATE_GOLDEN=1` after review.

## Status

Verified on a real VPS in S3: Ubuntu 24.04 and Debian 13 with the Docker add-on. Ubuntu 26.04 and
Debian 12 recipes are derived from them; repository suites were confirmed to exist, but a full
build of those two has not been run yet.
