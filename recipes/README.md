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
  fragments/xfce-desktop.toml          headless Xorg + XFCE + PipeWire + the hx-session units (distro independent)
  fragments/settings.toml              post steps for hostname, timezone, locale, keyboard
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
is replaced; an unknown name is an error that names the key. `{{` is reserved for this; `user` and `uid` are filled from `[user]` (the validated account, see below) and cannot be defined in `[vars]`; `[vars]`
values themselves are not expanded.

**Desktop settings.** `hostname`, `timezone`, `locale` and `keyboard` are also reserved: they come
only from the caller's validated `hx_provision::Settings` (the wizard's choices, ipc.md 6.5), are the
empty string when unset, and are used by `fragments/settings.toml`, whose post steps do nothing
for an empty value. Always single-quote them in a script.

**Unknown keys are errors**, everywhere, so typos fail loudly.

| Section | Meaning |
|---|---|
| `[recipe]` | `name` (required), `base_image` (required, `images:debian/13`-style alias on the Incus image server, or `local:<alias>`). |
| `[vars]` | String variables, see above. |
| `[incus_config]` | Instance configuration applied to the container, not content inside it. Only `security.nesting`, `security.syscalls.intercept.mknod` and `security.syscalls.intercept.setxattr` are allowed (values `true`/`false`); everything else, `security.privileged`, `raw.*` and the other intercepts included, is rejected. Used by the Docker add-on. |
| `[[apt_repo]]` | `name`, `key_url`, `key_fingerprint` (40 hex characters), `uri`, `suite`, `components`, `pin` (apt preferences body, **required**: it must hold a `Package: *` stanza with `Pin: origin <host of uri>` and `Pin-Priority` of 100 or lower, so nothing else the origin offers can replace a distro package on `apt-get upgrade`; raise only the intended packages in stanzas placed before it, because apt uses the first matching stanza, and pin them by `origin <host>`, never by the self-declared `o=` field). The downloaded key must contain exactly the pinned primary key fingerprint or the step fails; it is imported into a temporary keyring and only the pinned key is exported. All downloads use `curl --proto '=https' --proto-redir '=https'`, vendor installers included. Written as a deb822 `.sources` file with `Signed-By`. |
| `[apt]` | `packages`: installed with `--no-install-recommends`; duplicates are removed, first occurrence wins. |
| `[user]` | `name`, `uid`, `shell`, `groups`, `linger`. `name` must be a valid, non-reserved login name (`^[a-z_][a-z0-9_-]{0,31}$`; not `root`, `ubuntu`, `docker`, ...). The caller may choose another name at resolve time; a prebuilt image built with `desk` is renamed in the post stage. The account step refuses to adopt an existing system account or one with another uid. The desktop user is created locked (no password); the password is set in the post stage from a secret handed over at run time. An add-on may add `groups` only. |
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

Post stage (always runs, after a prebuilt import and after a server build): wait for network, rename the image user when the caller chose another name,
ensure the user exists, set the password (secret, via stdin of `chpasswd` from a 0600 file, never
argv), security updates, `post_step`.

**Prebuilt images.** `hx-imagectl` (image CI) runs `orchestrate::build_image`: the build stage with
no secrets, then a seal (empty `/etc/machine-id`, no random seed, journal and logs, ssh host keys,
temporary files, shell history, the build user's cache and the apt lists) and a graceful stop. An
image is bound to its recipe by `Plan::build_digest()`, the SHA-256 of the canonical JSON of the
plan's name, base image, vars, instance config and **build** stage (not the post stage), so
changing anything the build stage does invalidates published images. `tests/golden/build-digests.txt`
pins the digests.

Rules that keep a prebuilt desktop equivalent to a server build (checked by `equiv::compare` in
image CI, see the crate README):

- Anything written by the build stage must not depend on the account name: the image is built
  with `desk` and the post stage renames it, so a `{{user}}` inside a written file or enabled unit
  is a drift. Use the numeric `{{uid}}` or a name-free text.
- Every file the build stage writes lives under `/etc` (the facts collect `/etc`, the apt
  sources and keyrings, the home tree, `/var/lib/hx-session` and the linger directory).
- The post stage ends with a restart on both paths, so both end in a clean boot.
- The XFCE session must first run after the post stage (the settings, above all the locale, decide
  the language of the user's XDG folders, which the session creates at its first start). A server
  build boots into the finished desktop, so this holds by itself. An image boots with its units
  enabled, so `finish_prebuilt` writes a drop-in that keeps `hx-xsession.service` from starting
  until the post stage is done and removes it before the final restart. A recipe must not start
  the session in the build stage, and the seal removes session state in any case.
- The user's XDG folders are made by the post stage (`xdg-user-dirs`, right after the settings),
  not by the session. At the session's first start, xfdesktop and `xdg-user-dirs-update` run side by
  side; when xfdesktop looked before `user-dirs.dirs` existed, it fell back to an English
  `~/Desktop` beside the translated one (`~/Schreibtisch` for `de_DE`), on one desktop and not the
  other. With the folders already listed, every session program finds them.

Every apt invocation is bounded: apt's own HTTP timeouts and retries, a hard `timeout` per attempt
and several attempts. In S3, `apt-get update` hung for over nine minutes twice.

### Secrets

Recipes contain no secrets. The only secret in provisioning, the desktop user's Linux password,
is supplied by the caller at run time and reaches the container only as the stdin of `chpasswd`
(never argv, environment, logs or error messages). Recipe commands must not need credentials;
the vendor installers in `post_step` do not.

An escaped `\{{` produces a literal `{{` (for example in a Go template inside a script).

## Units inside the desktop

| Unit | Kind | Runs | Notes |
|---|---|---|---|
| `hx-xorg.service` | system | headless Xorg on `:0` | cookie in `/run/hx-xorg/Xauthority`, owned by the desktop uid |
| `hx-xsession.service` | user (lingering manager) | `xfce4-session` | formerly `hx-session.service`; renamed when that name went to the streaming daemon |
| `hx-session.socket` | system | creates `/run/hx-session/link.sock` | owner = desktop uid, mode 0600; the directory is root:root 0755 (tmpfiles), so the user cannot replace the path |
| `hx-session.service` | system, `User=1000`, started by the socket | `/usr/lib/hx-session/hx-session` | hardened (`NoNewPrivileges`, empty capability set, `AF_UNIX` only, `ProtectSystem=strict`, the only writable path is `/var/lib/hx-session/received`, `KillMode=control-group`); **no** `PrivateNetwork`, `PrivateTmp` or `PrivateDevices` |

The binary is not in the image: the `hx-session` package installs it at
`/usr/lib/hx-session/hx-session` (the `hx_provision::session` constants are the source of truth and
a test keeps the units in step). The same package ships `/usr/lib/hx-session/hx-pwcheck`, the
current-password checker. `~/Received` links to `/var/lib/hx-session/received`.

**FFmpeg runtime.** The package's `Depends` (computed by `dpkg-shlibdeps`) names the distro's
`libavcodecNN` and `libavutilNN`, and privd installs it with `dpkg -i`, which resolves no
dependencies. The recipe therefore installs those two packages itself, through the per-distro
vars `libavcodec_pkg` and `libavutil_pkg` of `fragments/distro-<distro>.toml` (referenced from the
package list of `fragments/xfce-desktop.toml`). `packaging/hx-session/check-recipe-covers-depends.sh`
fails when a built `.deb` depends on a library the recipe does not install.

## Adding a recipe

1. New distro: add `fragments/distro-<name>.toml` with `base_image` and the vars, and one recipe
   file per preset. Extend the `Distro` enum in `hx-provision` (the `every_shipped_recipe_resolves`
   test fails until recipes, enum and embedded file list agree).
2. Pin every new apt repository by full key fingerprint, and give it a `pin` that keeps everything it offers at priority 100 (`Package: *`, `Pin: origin <host>`) and raises only the packages you install from it (the parser refuses a repository without it). Adding or changing a pin changes the recipe and build digests, so prebuilt images are rebuilt.
3. Run `cargo nextest run -p hx-provision`; golden plans under `crates/hx-provision/tests/golden/`
   are refreshed with `HX_UPDATE_GOLDEN=1` after review.

## Status

Verified on a real VPS in S3: Ubuntu 24.04 and Debian 13 with the Docker add-on. All eight recipes
(four distros x basic and developer) were then built through `hx-provision` into an unprivileged,
isolated-idmap Incus 6.0.0 container (`crates/hx-provision/tests/incus_real_session.rs`), booted
into the XFCE session, and passed the `hx-session` socket and service checks. Not covered by a real
build: the Docker add-on on these (needs Incus 6.0.5), and the developer recipes' vendor installers
(optional steps, which need direct internet and were not given it by the test's proxy).

The mozillateam PPA is signed by two keys. Both Ubuntu recipes pin the current one (`738BEB93...1867`,
from the Launchpad API); the older `0AB21567...EC21` is rsa1024, which apt 2.8 (24.04) warns about and
newer apt rejects. Both pin files also give Ubuntu's own `firefox` priority -1: it is a transitional
package that installs the snap, which cannot work in an unprivileged container, so it must never be
chosen, also not when the PPA is unreachable. Every `apt-get update` of a recipe runs with
`--error-on=any`, so an index that cannot be fetched (Launchpad answered 503 during the Gate 1 dry
run on 2026-11-23) is retried and then fails the step, instead of silently dropping the repository
and its pins.
