# Contributing to hash-xcreen

Thanks for helping. Please read [AGENTS.md](AGENTS.md) first: it holds the rules everyone follows, including the git workflow.

## Before you start

- Work follows [docs/execution-phase.md](docs/execution-phase.md). Pick a task from the current phase, or open an issue to discuss anything outside it.
- Design changes go into [docs/architecture.md](docs/architecture.md) first, in the same branch as the code.
- New dependencies must fit [docs/tech-stack.md](docs/tech-stack.md) and pass `cargo deny`.

## Setup

Install [rustup](https://rustup.rs/). The pinned toolchain in `rust-toolchain.toml` is installed automatically the first time you run `cargo` in the repository (or run `rustup toolchain install`).

Tools used by the checks:

```bash
cargo install --locked cargo-nextest cargo-deny cargo-audit
```

## Run the checks CI runs

```bash
cargo fmt --all --check
```

```bash
cargo clippy --workspace --all-targets --locked -- -D warnings
```

```bash
cargo nextest run --workspace --locked --no-tests=pass
```

```bash
cargo deny check
```

```bash
cargo audit
```

## Branches and commits

- One branch per change, named `phase-<n>/…`, `spike/…`, `docs/…`, `fix/…` or `chore/…`.
- Commit locally as each logical change is done, using [Conventional Commits](https://www.conventionalcommits.org/).
- Merge into `main` through a pull request with CI green.

## Developer Certificate of Origin

Every commit must be signed off, certifying the [Developer Certificate of Origin](https://developercertificate.org/): that you wrote the change or otherwise have the right to submit it under the project's licence.

```bash
git commit -s
```

This adds a `Signed-off-by: Your Name <you@example.com>` line. CI rejects pull requests with commits that lack it. To sign off commits you already made on your branch:

```bash
git rebase --signoff main
```

## Licence

By contributing you agree that your contributions are licensed under the [GNU Affero General Public License v3.0 or later](LICENSE).
