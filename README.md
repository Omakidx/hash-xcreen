# hash-xcreen

A self-hosted remote desktop, written in Rust.

You point hash-xcreen at a server you control. It sets up a full Linux desktop there, streams it to the native app or your browser with very low latency, and backs it up to your Google Drive every 12 or 24 hours. If the server dies, you restore the whole desktop (apps, settings, files, AI chat history, logins) onto a new one.

> **Status:** design phase. No code yet. The plan we follow is in [docs/execution-phase.md](docs/execution-phase.md).

## What it does

- **One-step setup.** Add a server in the app (over SSH) or paste one command on the server. Incus, the desktop, the streaming service, firewall rules and backups are all set up automatically.
- **Your choice of desktop.** Ubuntu 24.04 / 26.04 or Debian 12 / 13, with XFCE in v1. Presets: **basic** or **developer** (VS Code, git, build tools, Claude Code, Codex CLI). Docker inside the desktop is an opt-in switch.
- **Fast streaming, built from scratch.** Change-driven screen capture, x264 or hardware encoding, QUIC transport, GPU decoding on the client, and a locally drawn cursor. Target: 1080p60 with at most ~40 ms added on a 4 vCPU server with no GPU.
- **Native app and web.** A Slint desktop app (Linux first) and a browser client (off by default, with passkey login).
- **Full-desktop backups.** Incremental, deduplicated, compressed and encrypted on the server before upload to Google Drive. Restore to the same server or a new one.
- **Secure by default.** SPAKE2 pairing, mutually authenticated TLS 1.3, a server-checked PIN, privilege separation on the server, and unprivileged containers.

## How it fits together

```
 hx-desktop (Slint) ─┐                      ┌─ hx-gatewayd (unprivileged, internet-facing)
                     ├── QUIC / TLS 1.3 ────┤        │
 hx-web (browser) ───┘                      │  hx-privd (root, Incus, snapshots)
                                            │        │
                                            └─ Incus container: XFCE + hx-session
                                                       │
                                            backup worker ──► Google Drive (encrypted)
```

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Components, protocol, security model, backups, testing, releases |
| [docs/tech-stack.md](docs/tech-stack.md) | Every language, library, tool and service we use, and why |
| [docs/userflow.md](docs/userflow.md) | What the user sees and does, screen by screen |
| [docs/execution-phase.md](docs/execution-phase.md) | The phased plan we follow, with tasks and exit criteria |

## Requirements

**Server:** Ubuntu 22.04 / 24.04 / 26.04 or Debian 12 / 13, x86_64, systemd. Minimum 2 vCPU, 4 GB RAM, 30 GB disk; recommended 4 vCPU, 8 GB RAM.

**Client:** Linux (v1). Windows, macOS and mobile later. Any recent Chromium- or Firefox-based browser for the web client.

**Backups:** a Google account. Free Google storage is 15 GB, shared with Gmail and Photos.

## Contributing

Contributions are welcome once Phase 1 starts. Sign off every commit with the [Developer Certificate of Origin](https://developercertificate.org/):

```bash
git commit -s
```

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/). Report security issues privately through GitHub's vulnerability reporting, not in public issues.

## Licence

[AGPL-3.0-or-later](LICENSE).
