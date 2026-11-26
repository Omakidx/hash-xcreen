# Release tooling

Scripts behind `.github/workflows/release.yml` (design D7 of the 1E installer). Each runs locally. The desktop images have their own workflow, `images.yml`, described at the end.

| Script | Purpose |
|---|---|
| `gate.sh [--tag vX] [--dry-run] [--workflow FILE]` | The release gate: tag equals the workspace version, both release keys provisioned and embedded in `installer/install.sh`, **both image keys (`apps/hx-agent/image-keys/{current,next}.pub`) provisioned, valid, different from each other and from the release keys** (skipped only while that directory does not exist), no test-hook feature in the workflow, every action pinned to a commit SHA and every `container:`/`image:` pinned by `@sha256:` digest, no build cache, job isolation (check 8). The offline checks also run in `ci.yml` (`sh release/gate.sh --dry-run` and the three `release/tests/gate-*.sh`). |
| `assemble.sh` | Deterministic ustar release tarball. |
| `manifest.sh` | Canonical one-line manifest. |
| `make-test-release.sh` | A TEST-keyed release directory for local and CI tests (never a real release). |
| `openssl-minisign.sh` | minisign-compatible test keys and signatures with openssl only (test use). |
| `verify-with-installer.sh` | Verifies a signature with a shipped `install.sh`'s own function. |
| `tests/gate-pinning.sh` | Test of the SHA-pinning check of `gate.sh` over every workflow file (`sh release/tests/gate-pinning.sh`). |
| `tests/gate-isolation.sh` | Test of check 6b (container/image digests) and check 8 (job isolation) of `gate.sh` (`sh release/tests/gate-isolation.sh`). |
| `tests/gate-image-keys.sh` | Test of the image-key check of `gate.sh` on a synthetic tree with per-run test keys (`sh release/tests/gate-image-keys.sh`). |

## Supply-chain rules (enforced by `gate.sh`)

- Every `uses:` of EVERY workflow in `.github/workflows` is pinned to a full 40-hex commit SHA (a `docker://` image to its `sha256` digest), with the tag as a trailing comment. To bump
  one: `gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`, review the diff of that action, and
  replace both the SHA and the comment.
- No build cache (`Swatinem/rust-cache`, `actions/cache`) anywhere in the workflow: a release build
  never restores anything a pull request could have written. Release builds are uncached.
- rustup is pinned by version and sha256 in the workflow; the Rust toolchain by `rust-toolchain.toml`.

## Repository settings the maintainer must make (not expressible in the repository)

Checklist, to be done once before the first real release.

**Order matters: add the secrets LAST.** A secret placed in an environment before the controls
below exist is reachable by whatever workflow can name that environment. Do them in this order:

1. Create both environments with deployment policies (no secrets yet): `release-signing`
   (tags `v*` only, plus a required reviewer) and `image-signing` (branch `main` only).
2. Add the tag ruleset for `v*` and `channel-*`.
3. Protect `main` (pull request, required CI jobs, CODEOWNERS review, no force pushes).
4. ONLY THEN add the secrets to the environments.

**A "tag is on main" check inside `release.yml` is not a control by itself.** The workflow that
runs for a tag is the workflow file AT THAT TAG, so whoever can push a tag controls the code that
checks it. The real controls are the environment deployment policy, the tag ruleset and the
required reviewer. The in-workflow check is a second line against honest mistakes.

**Reviewer checklist** (every `release-signing` approval): confirm the run's commit is on `main`
(the commit shown on the run is an ancestor of `main`, not a branch or fork commit) and that the
workflow files at that commit equal `main`'s; `.github/`, `release/`, `installer/` changes are
CODEOWNERS-reviewed (`.github/CODEOWNERS`).

- [ ] **Environment `release-signing`** (Settings, Environments): required reviewers (manual
      approval for every run); **deployment branches and tags: selected, allow only the tag
      pattern `v*`**, so no branch, fork or pull-request workflow can reach the signing secrets;
      secrets `MINISIGN_SECRET_KEY` and `MINISIGN_KEY_PASSWORD` live in this environment only, never
      as repository or organisation secrets.
- [ ] **Tag protection** (Settings, Rules, Rulesets): a tag ruleset for `v*` (and `channel-*`) that
      restricts creation, update and deletion to the maintainers and blocks force pushes, so a
      release tag cannot be moved or re-pointed after it was signed.
- [ ] **Branch protection on `main`**: pull request required, the CI jobs required (including
      `shellcheck`, `installer-kat`, `actionlint`), no force pushes. A release tag must be created
      from a commit that is on `main`.
- [ ] **Actions permissions** (Settings, Actions): default `GITHUB_TOKEN` permission read-only;
      allow only actions pinned by commit SHA if the "require SHA pinning" option is available.
- [ ] **Public keys**: provision `apps/hx-agent/release-keys/current.pub` and `next.pub` and the
      `KEY_CURRENT` / `KEY_NEXT` lines of `installer/install.sh` with the same two keys
      (`gate.sh` and `apps/hx-agent/tests/installer_keys.rs` check they match).
- [ ] **Rehearse** with the `workflow_dispatch` dry run before tagging: it builds every artifact and
      signs with a per-run test key, but does not exercise the real signing step.

## Trust root of the one-liner, and what `install.sh` refuses

`curl ... | sudo sh -s -- --pair` runs a script that is itself unsigned: TLS to github.com is the only
protection for that first step. Every later step is signature-checked (the manifest with the
embedded release keys, then the tarball by size and SHA-256, then `hx-agent` again with its
compiled-in keys). To check the script before running it, download it with its signature and verify
with minisign against the release public key published in the repository
(`apps/hx-agent/release-keys/current.pub`):

```sh
curl -O https://github.com/Omakidx/hash-xcreen/releases/download/channel-stable/install.sh
curl -O https://github.com/Omakidx/hash-xcreen/releases/download/channel-stable/install.sh.minisig
minisign -Vm install.sh -P <the public key line of current.pub>
sudo sh install.sh --pair ...
```

`install.sh` also:

- refuses a manifest older than 90 days (a possible replay of a superseded release) unless
  `--allow-old-release` is given. There is no minimum-version floor: after the install, privd keeps
  the highest manifest timestamp it has accepted and refuses anything older, so a replay can only
  matter for the very first install, which the 90-day rule bounds;
- ignores `~/.curlrc` (`curl -q` first) and enforces its download caps without curl (1 MiB for the
  manifest, the manifest's size for the tarball), because curl before 8.4 does not enforce
  `--max-filesize` without a Content-Length;
- with `--release-dir`, refuses a directory or file that is group- or other-writable or not owned by
  root, **and every parent directory of it that is not root-owned or is group-/other-writable** (a
  sticky directory such as `/tmp` is tolerated), and copies only regular files, bounded by those
  caps (a FIFO or a huge file is refused);
- ignores `TMPDIR` (`unset` in `main`; the self-test makes its scratch directory under `/tmp`).

## Pipeline rules (enforced by `gate.sh` check 8)

- A job with `environment:` (it holds signing secrets) never runs `cargo`, `rustup`, a workspace
  binary (`signed/hx-*`) or any workspace script: it downloads artifacts built by secret-free jobs,
  installs minisign from apt and signs. Verification of the signature happens in a later secret-free job.
- A job with `contents: write` never runs `cargo`/`rustup` or a workspace binary either; it uses only
  runner-image tools (`gh`, `jq`, `sha256sum`, coreutils).
- `container:` / `image:` values are pinned by `@sha256:` digest, like actions.
- Signing jobs collect artifacts by exact name, never by `pattern:`.
- `.github/CODEOWNERS` covers `.github/`, `release/`, `installer/`, `apps/hx-imagectl/`,
  `crates/hx-provision/` and `recipes/`; branch protection on `main` must require code-owner review.
- `release.yml` `publish` refuses a version that is not strictly newer than the current channel manifest.

## Desktop packages (`hx-desktop`)

The version release `v<version>` carries the desktop app next to the agent tarball. Build scripts,
package layout and the AppImage decisions are in [`packaging/hx-desktop/README.md`](../packaging/hx-desktop/README.md).

| File | What |
|---|---|
| `hx-desktop_<version>_<distro>_amd64.deb` | `<distro>` is `ubuntu-24.04`, `ubuntu-26.04`, `debian-12` or `debian-13`. `Depends` are the distro's own library packages. |
| `hx-desktop-<version>-x86_64.AppImage` | One file for every x86_64 Linux desktop with glibc 2.39 or newer; FFmpeg is bundled. |
| `<file>.minisig` | A minisign signature of each file above, made in the `sign` job with the same `release-signing` key as `install.sh` (`-t "hx-desktop v<version> <file name>"`). |

How the release workflow handles them:

- Jobs `desktop-deb` (one per distro, in a job container of that distro, so `dpkg-shlibdeps` sees the
  right sonames), `desktop-deb-smoke` (clean-container install, `ldd`, `--version`, `--demo` under Xvfb) and
  `desktop-appimage` (builds and smoke-tests on `ubuntu-24.04`) run for a tag **and** for the dry run, so the
  rehearsal proves they build. They are uncached, use only actions pinned by SHA and enable no features; the
  AppImage tools are downloaded from their official releases and verified against the SHA-256 recorded
  in `packaging/hx-desktop/appimage-tools.lock` before they run.
- `assemble` collects them into `desktop/`; `sign` signs every file there; `attest` attests every
  `.deb` and the AppImage (audit only, like the other subjects); `publish` attaches the files and their
  signatures to `v<version>`, in the same `gh release create` as the agent tarball. The moving
  `channel-*` release does not carry them: nothing on a server reads the desktop app from a channel.
- The release fails if the `ubuntu-24.04`, `ubuntu-26.04`, `debian-12` or `debian-13` `.deb` or the AppImage is missing.
  `assemble` downloads every artifact by exact name, one per matrix cell, so a failing cell fails the release instead of leaving a name free for another job to fill.

Verify a download (the public key is the one of `apps/hx-agent/release-keys/current.pub`):

```sh
minisign -Vm hx-desktop_0.1.0_ubuntu-24.04_amd64.deb -P <the public key line of current.pub>
gh attestation verify hx-desktop_0.1.0_ubuntu-24.04_amd64.deb --repo Omakidx/hash-xcreen
sudo apt install ./hx-desktop_0.1.0_ubuntu-24.04_amd64.deb      # or: chmod +x the AppImage and run it
```

Nothing installs or updates these packages automatically: there is no apt repository and the
AppImage carries no update information. The maintainer needs no setup beyond the `release-signing`
environment that the agent release already uses.

## Desktop images (`images.yml`)

`.github/workflows/images.yml` builds the eight prebuilt desktop images (4 distros, xfce, basic and
developer), proves each one equivalent to a desktop built on the server, then signs and publishes.
Design: docs/architecture.md 4.3, 12 and 13; the manifest rules: docs/ipc.md 6.12 "Images
manifest". The tool is `apps/hx-imagectl`; it shares `hx_provision::images` with `hx-privd`.

Jobs: `plan` (which cells are missing or at least 7 days old, from the published manifest) ->
`image` (one cell each: build, seal, `incus publish --compression zstd`, export, then the
equivalence check; any drift fails the cell) -> `rehearse` (pull requests and non-publish runs: a
manifest signed with a per-run test key, which `hx-imagectl verify` must accept and must refuse
when tampered) or `manifest` (no secrets: builds `hx-imagectl` and the manifest) -> `sign` (environment
`image-signing`: downloads the manifest, installs minisign from apt, signs; runs no workspace code) ->
`verify` (no secrets, read-only token: `hx-imagectl verify`, records the SHA-256 of every verified file)
-> `attest` -> `publish` (`contents: write` only here; runs no workspace-built code, it checks its
downloads against `verify`'s list). The same supply-chain rules as `release.yml` hold: every action is pinned to a commit
SHA (`gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`), and no build cache is used anywhere.

What is published: the release `images-<build_id>` first (the image files and a `SHA256SUMS`), then
`images-manifest-x86_64.json` and its `.minisig` on the moving release `images`, so a manifest never
points at a missing asset. The newest 4 `images-*` releases are kept, and never one the current
manifest references. Images are never overwritten; the manifest is replaced.

**Publishing stays off until the maintainer provisions the image keys.** While
`apps/hx-agent/image-keys/{current,next}.pub` are `UNPROVISIONED` (or missing), `sign`, `attest` and
`publish` are skipped; `plan` and `image` still run, so the recipes and the equivalence are checked
every day. `gate.sh` also refuses a release while those files are `UNPROVISIONED`, so no shipped
agent is stuck without prebuilt images until it updates.

### Maintainer checklist (not expressible in the repository)

Once, before the first publish:

- [ ] **Generate a separate image key pair, offline.** Two minisign pairs (`minisign -G` twice):
      `current` and `next`. They must not be the release keys: a leaked image key must not be able
      to sign agent releases (`gate.sh` checks that they differ). Commit only the two public halves
      as `apps/hx-agent/image-keys/current.pub` and `next.pub`; they are embedded in `hx-privd`
      and checked by the release gate and the `release-build` compile gate.
- [ ] **Environment `image-signing`** (Settings, Environments): **deployment branches: selected,
      allow only `main`**; **no required reviewers** (the daily and weekly runs cannot wait for an
      approval); secrets `IMAGE_MINISIGN_SECRET_KEY` (the secret key file text) and
      `IMAGE_MINISIGN_KEY_PASSWORD` live in this environment only, never as repository or
      organisation secrets. Use a password-protected secret key.
- [ ] **Anything that can change `images.yml` on `main` can publish images**: require a pull
      request and a review from code owners for `main` (`.github/CODEOWNERS` already lists
      `.github/`, `apps/hx-imagectl/`, `crates/hx-provision/` and `recipes/`).
- [ ] **Do not enable repository-wide "immutable releases"**: `images` (and `channel-*`) are moving
      releases whose assets are replaced. The `images-<build_id>` releases are immutable by
      convention: the workflow only adds to them, and refuses (fails) when an asset of that name
      already exists; it never uses `--clobber` on them.
- [ ] **`image-signing` and tags**: `images.yml` only builds `v*` tags whose commit is an ancestor of
      `main` and that are real releases (the tag equals `v` + the workspace version at that tag, or a
      GitHub release of that name exists); others are skipped with a warning, and `release.yml` fails its gate for a tag that is
      not on `main`; also restrict `v*` tag creation with a tag ruleset (above) so that tags cannot
      be pushed from arbitrary branches at all.
- [ ] **Actions permissions**: the default `GITHUB_TOKEN` stays read-only (each job asks for what it
      needs; `contents: write` is in `publish` only).
- [ ] **Rehearse** on a pull request first: the `image` cells and `rehearse` run with test keys and
      publish nothing. Then, after the keys are in, run the workflow on `main` with the `publish`
      input once and check the release `images` (a manifest and its `.minisig`) and an
      `images-<build_id>` release.

Rotation: like the release keys. The next release embeds the old `next` as `current` and a fresh
`next`; sign with the key that every shipped agent still embeds until that release is out.

### Rollback and withdrawal

- Images are never replaced, so a bad build is withdrawn, not overwritten. Run the workflow on
  `main` with `publish` and `drop` set to the images to remove (space-separated `recipe/build_id`,
  for example `debian-13-xfce-basic/20261123.2`): `sign` then re-signs the published manifest
  without them (and with a newer timestamp, which agents require; re-publishing an old manifest
  would be refused by every agent that already saw a newer one). A name that is not in the
  published manifest fails the run.
- Agents fall back to building on the server whenever no usable entry matches (`--image auto`), so
  withdrawing every image of a recipe is safe.
- To stop publishing altogether, disable the workflow or delete the `image-signing` secrets: the
  existing manifest stays valid for 30 days of image age, then agents stop using it.
- The first run on a pull request is the real test of this workflow (it could not be run where it
  was written); watch the `image` cells (Incus on the runner, the btrfs pool on `/mnt`) first.
