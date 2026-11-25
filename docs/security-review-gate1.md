# Gate 1 security review (2026-11-25)

The Gate 1 box "Security review findings resolved" needs a review of the whole of Phase 1. The
reviews of 2026-11-22 covered 1B (crypto and pairing), 1C (agent core and the privd command set),
1E (installer), protocol 1.3 server management, prebuilt images and the app's secret handling
([execution-phase.md](execution-phase.md), 1H). This review covers the rest, in five independent
read-only passes:

| Pass | Scope |
|---|---|
| N | Network entry and login: `hx-transport`, `hx-proto`, the gateway's accept, pairing and PIN path |
| L | Streaming and the session link: `apps/hx-agent/src/link`, the relay, `apps/hx-session`, `hx-ipc`, `hx-capture`, `hx-codec` |
| A | Desktop app: `apps/hx-desktop`, `hx-sshsetup`, the decode path |
| R | Provisioning and images: `hx-provision`, `hx-imagectl`, recipes, and PRs #63 to #72 |
| P | CI, release and signing: `.github/workflows`, `release/`, `installer/install.sh` |

Every finding below was checked against the code by the manager before it was listed. A finding
is **resolved** when its fix is merged with the regression test named in its row, or when the
maintainer accepts it in writing here.

## Findings

No Critical or High finding in the code. Two High findings depend on GitHub settings that do not
exist yet (P3, P4); they become real only if those settings are made in the wrong order.

| ID | Severity | Finding | Fix | Status |
|---|---|---|---|---|
| P1 | Medium | The images `publish` job runs a workspace-built `hx-imagectl` while holding a `contents: write` token, which can replace `channel-stable/install.sh` | Verify in a job without a write token; `publish` runs only runner tools; `gate.sh` rule | Open |
| P2 | Medium | The images `sign` job compiles the workspace (`cargo build`, every build script) in the job that later receives the image signing key | Separate secret-free manifest job; `sign` only downloads, signs, uploads; `gate.sh` rule | Open |
| N1 | Medium | 16 IPv4 addresses (or 4 IPv6 /48s) can hold all 64 pre-authentication slots for 15 s each and block every new login, pairing and revocation | Short pre-TLS phase, reserved slots for known keys, unknown keys refused after TLS when no pairing is open, per-/24 cap | Open |
| L1 | Medium | Bulk transfers above 64 MiB/s are judged a flood at either end of the session link; repeated faults end in `session_unavailable` for every device | Senders pace below the budget; session-side pending uses real readability; ipc.md §13 first | Open |
| A1 | Medium | The server can write any number of files into `~/Downloads` without consent, also during management-only sessions where nothing is shown | Refuse incoming files unless the desktop view is active and the files policy is on; caps; no downloads for management sessions | Open |
| A2 | Medium | The link confirmation can be swapped or clickjacked: a new link replaces an open dialog, and "Open link" works on the first click | Ignore links while a dialog is open, arm the button after a delay and a pointer move, rate limit, default cursor under dialogs | Open |
| A3 | Medium | Decoded frame size is unchecked: a crafted SPS makes the app allocate several GiB | `max_pixels` on the decoder, reject frames over the cap or the stream size, smaller pool | Open |
| A4 | Medium | The remote side can overwrite the local clipboard at any time, also with the app in the background; 64 MiB of text freezes the UI | Apply remote clipboard only while focused, 1 MiB text cap, coalesce | Open |
| P3 | High (settings) | Signing secrets are protected only by environment and ruleset settings that do not exist yet; the "tag is on main" check runs in the tagged commit's own workflow | Maintainer order: environments with policies, tag ruleset, branch protection, then secrets; README wording | Maintainer |
| P4 | High (settings) | A fork PR can add a job for the `hx-perf` self-hosted runner | Approval for all outside collaborators; ephemeral runner, never the production VPS; `persist-credentials: false` | Maintainer |
| N2 | Low | Two stolen device keys without the PIN reach privd's global PIN cap (10 an hour) and lock PIN login for everyone until an operator resets it | gatewayd forwards at most `max_pin_failures - 1` wrong checks per device; document in §8.1 | Open |
| N3 | Low | A malicious server can open up to 1024 video streams, each holding a frame of up to 16 MiB, in the app | Bound frames in flight in the client transport | Open |
| L2 | Low | A pause in the session's input reader turns queued frames into a burst over the frame-count limit | Session does not close the link for ctl frame-count overage; batch DROPPED reports | Open |
| L3 | Low | After a takeover the displaced device's clipboard and offered files stay in the desktop (contradicts ipc.md §18) | Withdraw clipboard and clear the file batch on a new epoch | Open |
| A5 | Low | Auto-reconnect re-sends a rejected PIN, which revokes the device after a PIN change made elsewhere | Stop reconnecting on Wrong, Backoff or NotAvailable and go to the PIN screen | Open |
| A6 | Low | Incoming transfers and UI events have no client-side bound | Semaphore on transfers, bounded event channel, latest-wins coalescing | Open |
| A7 | Low | A long host name can hide its real end in the link dialog | Cap host length, wrap the host, emphasise the registrable domain | Open |
| R1 | Low | Third-party apt sources (Mozilla PPA, Docker, VS Code) are not scoped: any package they publish wins at priority 500 | `Package: *` at low priority per origin host, raise only the intended packages; validator rule | Open |
| R2 | Low | INTERNAL errors from a failed desktop step now carry container-controlled output to the CLI and the app | Keep step and exit status in the message, the output only in the journal | Open |
| R3 | Low | The refusal of `--token` on the command line does not say the token is already in logs and history | Message tells the user to make a new token | Open |
| P5 | Low | Signing jobs collect artifacts by pattern; a known-failing cell leaves a name free for injection | Download by exact name; drop the failing 26.04 desktop cell | Open |
| P6 | Low | Release build containers are pinned by tag, not digest; `gate.sh` checks only `uses:` | Digest pins; extend the gate check | Open |
| P7 | Low | Any `v*` tag on `main` drives an image build | Require the release to exist or the tag to match the workspace version | Open |
| P8 | Low | Nothing stops re-publishing an older version on a channel | `publish` refuses a version not newer than the channel's | Open |
| L4 | Info | The session accepts resize sizes the gateway then refuses | Pixel cap in `apply_config` and `apply_view` | Open |
| L5 | Info | The gateway's Annex B check accepts NAL types 13, 15 and 20 unparsed | Refuse 13, 14, 15 and 20 | Open |
| N3i | Info | `upsert_paired` matches by device id only | Fail when the stored key differs | Open |
| I | Info | Pinning check not run in CI; no `CODEOWNERS`; xdg-open `$BROWSER` fallback; reinstate password not zeroized; eager clipboard push on focus; in-process FFmpeg | Small fixes where cheap; the rest noted as accepted residual risk | Open |

## Checked and found sound

- **Network:** nothing past `PendingSession` is reachable without a paired key; every pre-auth
  parser is bounded; no Argon2 or privd call before key authentication; PIN attempts are counted
  before checking and cannot be dodged by disconnecting or parallel connections; revocation reaches
  open sessions; the identity comes only from the TLS key of the same connection (no resumption,
  no 0-RTT); pairing secrets are single use; no network-reachable panic found.
- **Session link:** framing and protobuf pre-scan bound every allocation; no descriptor passing;
  cursor shapes fully validated; session text never forwarded to clients; all client input clamped
  twice; received files written through a directory descriptor with `O_EXCL|O_NOFOLLOW`; epoch
  gating keeps an old client out after a takeover.
- **App:** the device key lives only in the Secret Service with no file fallback; the PIN is never
  stored; server keys are never re-pinned; SSH host keys are checked before any credential; SSH
  commands quote every value; links are http(s) only and opened as one argv entry; the PR #58 fix
  holds.
- **Provisioning:** every recipe value is quoted; the only user-derived values are validated;
  passwords travel through a 0600 file; apt keys are pinned by fingerprint and scoped with
  `Signed-By`; image fetch and import have no window between verify and use; the
  `/usr/local/sbin/hx-agent` link never follows or replaces a foreign file; the setup-device
  binding holds after PR #65.
- **Release:** no `pull_request_target`, `workflow_run` or comment triggers; untrusted values go
  through `env:`; write and attestation permissions only where needed; every action pinned by SHA;
  `install.sh` fails closed on every verification error; no path ships a test key.

## Not covered

No live attack was run. Throughput and timing claims (L1, L2, A2) and FFmpeg's real allocation
(A3) are from the code. The fuzzers were not run as part of this review; Gate 1 separately needs
seven clean nights.
