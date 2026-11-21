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
