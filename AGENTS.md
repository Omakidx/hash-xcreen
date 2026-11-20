# Working on hash-xcreen

Instructions for everyone working in this repository, human or agent.

## Source of truth

- [docs/execution-phase.md](docs/execution-phase.md): the plan we follow. Work on the current phase only; tick its checkboxes in the PR that finishes the work.
- [docs/architecture.md](docs/architecture.md): design decisions. Change the design there first, then the code.
- [docs/tech-stack.md](docs/tech-stack.md): approved languages, libraries and tools. Adding a dependency outside it needs a doc update in the same branch.
- [docs/userflow.md](docs/userflow.md): what the user sees.
- [docs/ipc.md](docs/ipc.md): the internal IPC contracts (`hx-privd` command set, gateway-to-session link). Change the contract there first, then the code.

## Git workflow

1. **Every change gets its own branch.** Never commit directly to `main`.
2. **Branch from an up-to-date `main`** and name the branch by the kind of work:

   | Prefix | Use | Example |
   |---|---|---|
   | `phase-<n>/` | A task or workstream from execution-phase.md | `phase-0/repo-foundations`, `phase-1/1a-protocol` |
   | `spike/` | A Phase 0 spike | `spike/s1-slint-video` |
   | `docs/` | Documentation only | `docs/git-workflow` |
   | `fix/` | Bug fix | `fix/pairing-token-expiry` |
   | `chore/` | Tooling, CI, dependencies | `chore/renovate-config` |

3. **Commit locally first, as you go.** Commit each logical change on the branch as soon as it is complete, before anything is pushed or merged.
   - Conventional Commits: `feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`, `perf:`, `ci:`.
   - Sign off every commit for the DCO: `git commit -s`.
4. **Push and merge later.** A branch is pushed and merged into `main` (through a pull request, with CI green) only when the maintainer asks. Delete the branch after it is merged.
5. **One branch, one purpose.** Don't mix unrelated changes; start another branch instead.
