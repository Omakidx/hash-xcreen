# Release tooling

Scripts behind `.github/workflows/release.yml` (design D7 of the 1E installer). Each runs locally.

| Script | Purpose |
|---|---|
| `gate.sh [--tag vX] [--dry-run] [--workflow FILE]` | The release gate: tag equals the workspace version, both release keys provisioned and embedded in `installer/install.sh`, no test-hook feature in the workflow, every action pinned to a commit SHA, no build cache. |
| `assemble.sh` | Deterministic ustar release tarball. |
| `manifest.sh` | Canonical one-line manifest. |
| `make-test-release.sh` | A TEST-keyed release directory for local and CI tests (never a real release). |
| `openssl-minisign.sh` | minisign-compatible test keys and signatures with openssl only (test use). |
| `verify-with-installer.sh` | Verifies a signature with a shipped `install.sh`'s own function. |

## Supply-chain rules of `release.yml` (enforced by `gate.sh`)

- Every `uses:` is pinned to a full 40-hex commit SHA, with the tag as a trailing comment. To bump
  one: `gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`, review the diff of that action, and
  replace both the SHA and the comment.
- No build cache (`Swatinem/rust-cache`, `actions/cache`) anywhere in the workflow: a release build
  never restores anything a pull request could have written. Release builds are uncached.
- rustup is pinned by version and sha256 in the workflow; the Rust toolchain by `rust-toolchain.toml`.

## Repository settings the maintainer must make (not expressible in the repository)

Checklist, to be done once before the first real release:

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
  root, and copies only regular files, bounded by those caps (a FIFO or a huge file is refused).

## Desktop packages (`hx-desktop`)

The version release `v<version>` carries the desktop app next to the agent tarball. Build scripts,
package layout and the AppImage decisions are in [`packaging/hx-desktop/README.md`](../packaging/hx-desktop/README.md).

| File | What |
|---|---|
| `hx-desktop_<version>_<distro>_amd64.deb` | `<distro>` is `ubuntu-24.04`, `debian-12` or `debian-13` (`ubuntu-26.04` is a known gap, below). `Depends` are the distro's own library packages. |
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
- The release fails if the `ubuntu-24.04`, `debian-12` or `debian-13` `.deb` or the AppImage is missing.
  **Known gap:** Ubuntu 26.04 ships FFmpeg 8 and the workspace pins `ffmpeg-next` 7.1, so its cells run with
  `continue-on-error`, and the `assemble` job prints a warning when the release has no 26.04 package.
  Remove `known_gap` from the matrix (here and in `desktop-packages.yml`) once the pin moves.

Verify a download (the public key is the one of `apps/hx-agent/release-keys/current.pub`):

```sh
minisign -Vm hx-desktop_0.1.0_ubuntu-24.04_amd64.deb -P <the public key line of current.pub>
gh attestation verify hx-desktop_0.1.0_ubuntu-24.04_amd64.deb --repo Omakidx/hash-xcreen
sudo apt install ./hx-desktop_0.1.0_ubuntu-24.04_amd64.deb      # or: chmod +x the AppImage and run it
```

Nothing installs or updates these packages automatically: there is no apt repository and the
AppImage carries no update information. The maintainer needs no setup beyond the `release-signing`
environment that the agent release already uses.
