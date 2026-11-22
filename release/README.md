# Release tooling

Scripts behind `.github/workflows/release.yml` (design D7 of the 1E installer). Each runs locally. The desktop images have their own workflow, `images.yml`, described at the end.

| Script | Purpose |
|---|---|
| `gate.sh [--tag vX] [--dry-run] [--workflow FILE]` | The release gate: tag equals the workspace version, both release keys provisioned and embedded in `installer/install.sh`, **both image keys (`apps/hx-agent/image-keys/{current,next}.pub`) provisioned, valid, different from each other and from the release keys** (skipped only while that directory does not exist), no test-hook feature in the workflow, every action pinned to a commit SHA, no build cache. |
| `assemble.sh` | Deterministic ustar release tarball. |
| `manifest.sh` | Canonical one-line manifest. |
| `make-test-release.sh` | A TEST-keyed release directory for local and CI tests (never a real release). |
| `openssl-minisign.sh` | minisign-compatible test keys and signatures with openssl only (test use). |
| `verify-with-installer.sh` | Verifies a signature with a shipped `install.sh`'s own function. |
| `tests/gate-pinning.sh` | Test of the SHA-pinning check of `gate.sh` over every workflow file (`sh release/tests/gate-pinning.sh`). |
| `tests/gate-image-keys.sh` | Test of the image-key check of `gate.sh` on a synthetic tree with per-run test keys (`sh release/tests/gate-image-keys.sh`). |

## Supply-chain rules (enforced by `gate.sh`)

- Every `uses:` of EVERY workflow in `.github/workflows` is pinned to a full 40-hex commit SHA (a `docker://` image to its `sha256` digest), with the tag as a trailing comment. To bump
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
  root, **and every parent directory of it that is not root-owned or is group-/other-writable** (a
  sticky directory such as `/tmp` is tolerated), and copies only regular files, bounded by those
  caps (a FIFO or a huge file is refused);
- ignores `TMPDIR` (`unset` in `main`; the self-test makes its scratch directory under `/tmp`).

## Desktop images (`images.yml`)

`.github/workflows/images.yml` builds the eight prebuilt desktop images (4 distros, xfce, basic and
developer), proves each one equivalent to a desktop built on the server, then signs and publishes.
Design: docs/architecture.md 4.3, 12 and 13; the manifest rules: docs/ipc.md 6.12 "Images
manifest". The tool is `apps/hx-imagectl`; it shares `hx_provision::images` with `hx-privd`.

Jobs: `plan` (which cells are missing or at least 7 days old, from the published manifest) ->
`image` (one cell each: build, seal, `incus publish --compression zstd`, export, then the
equivalence check; any drift fails the cell) -> `rehearse` (pull requests and non-publish runs: a
manifest signed with a per-run test key, which `hx-imagectl verify` must accept and must refuse
when tampered) or `sign` (environment `image-signing`) -> `attest` -> `publish` (`contents: write`
only here). The same supply-chain rules as `release.yml` hold: every action is pinned to a commit
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
      request and a review for `main`, and add `.github/workflows/images.yml`, `apps/hx-imagectl/`
      and `crates/hx-provision/` to CODEOWNERS (or a ruleset with the same effect).
- [ ] **Do not enable repository-wide "immutable releases"**: `images` (and `channel-*`) are moving
      releases whose assets are replaced. The `images-<build_id>` releases are immutable by
      convention: the workflow only adds to them, and refuses (fails) when an asset of that name
      already exists; it never uses `--clobber` on them.
- [ ] **`image-signing` and tags**: `images.yml` only builds `v*` tags whose commit is an ancestor of
      `main` (others are skipped with a warning), and `release.yml` fails its gate for a tag that is
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
