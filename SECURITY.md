# Security policy

hash-xcreen runs as root on servers, faces the internet, and holds the keys to people's desktops and backups. We take reports seriously.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**.

Please include:

- the affected component (`hx-gatewayd`, `hx-privd`, `hx-session`, backup worker, `install.sh`, desktop or web client) and version or commit;
- steps to reproduce, or a proof of concept;
- the impact as you understand it.

We aim to acknowledge reports within 7 days, agree a fix and disclosure timeline with you, and credit you in the release notes unless you prefer otherwise.

## Supported versions

hash-xcreen is pre-1.0. Only the latest release and `main` receive security fixes.

## Scope

In scope: everything in this repository and the release artifacts built from it (binaries, packages, desktop images, the install script).

Out of scope, as described in the threat model in [docs/architecture.md](docs/architecture.md#81-threat-model): attacks that require root on the host or control of the server's hardware or hypervisor (for example the VPS provider).
