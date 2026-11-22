# hx-desktop design mockups (workstream 1G)

Static HTML and CSS mockups of every screen and state of the desktop app, dark-first with a light theme. They exist so the maintainer can approve the design before any Slint UI is written (the box "Design mockups (dark-first + light) approved before UI implementation" in `docs/execution-phase.md`). They are not the app: nothing here talks to a server, and the remote desktop in the frames is a placeholder picture.

## How to view

Open `index.html` from disk (`file://`) or serve this folder with any static server (`python3 -m http.server`). Everything is self-contained: system fonts, no CDN, no network. The **Theme** control in the top bar switches Dark (default), Light and System, and is remembered per browser; `?theme=light` in the URL forces one. Resize the browser to 900 px wide to check the minimum window size.

Each framed window is one state of the app. Under most frames a note lists the **keyboard order** and the **accessibility** points. Tags: `Phase 2` (in userflow, ships later; the Phase 1 build disables or hides it), `Phase 3` (web client), `Proposed` (not in userflow or the protocol, needs a decision).

## Files

| File | Content |
|---|---|
| `index.html` | Entry page: links to every screen, conventions |
| `tokens.css` | **The whole visual system**: colour tokens for dark and light, type scale, spacing, radii, sizes. One to one with a Slint `global Tokens` |
| `mock.css` | Component styles built only from the tokens (buttons, fields, cards, dialogs, layouts) |
| `icons.css` | 41 outline icons as CSS masks (data URIs, recoloured by `currentColor`) |
| `mock.js` | The theme switch for the mockup pages only |
| `home.html`, `add-server-ssh.html`, `add-server-oneliner.html`, `progress.html`, `connect.html`, `desktop.html`, `server-details.html`, `settings.html`, `design-system.html` | The screens, below |

The HTML was produced with a throwaway script and is meant to be edited by hand from now on.

## Visual system in one paragraph

Calm and plain: flat surfaces in four steps (`bg`, `surface`, `surface-2`, `surface-3`), one blue accent, status colours (green, amber, red, blue) that always come with a word or an icon, 1 px borders, 8 px controls and 12 px cards, no gradients, no blur, no web-only effects. Type is the system font in seven sizes (12 to 34 px) and two weights; addresses, tokens and logs use the system monospace. Spacing is a 4 px base. Contrast is WCAG 2.2 AA in both themes: text 4.5 : 1, control outlines and focus rings 3 : 1, checked by script against `tokens.css` and listed in `design-system.html`. Focus is a 2 px ring with a 2 px gap on every control. The only motion is a spinner and an indeterminate bar, both off for reduced motion.

## Screen map

| Screen or state | Mockup | userflow.md | architecture |
|---|---|---|---|
| Welcome (empty state), first launch | `home.html#empty` | 1 | 11.1 Home |
| Server list, per-server status, problem cards, loading | `home.html#servers`, `#vocabulary`, `#problems`, `#loading`, `#small` | 1, 5.1, 11 | 11.1 Home |
| Add server: method (SSH, one-liner, pairing code, restore) | `add-server-ssh.html#method` | map, 2.1, 3.1, 4, 7 | 5.1 |
| SSH: address, port, user, key or password | `#conn-key`, `#conn-pw` | 2.2 | 5.1, 8.3 |
| SSH: host-key fingerprint confirmation | `#hostkey` | 2.2 | 5.1 |
| SSH: requirement checks, passed and failed | `#checks-ok`, `#checks-bad` | 2.2 | 5.2 preflight |
| Desktop: distro, desktop, preset, Docker and its warning | `#desktop`, `#desktop-docker` | 2.3, 10 | 5.2, 4.3 |
| Account: username, password and confirm (strength), PIN and confirm | `#account`, `#account-err` | 2.4 | 8.3 |
| Backups: Drive, schedule, retention, estimate, recovery key (Phase 2), Phase 1 form | `#backups`, `#recovery`, `#backups-p1` | 2.5 | 5.2, 9.7 |
| Resources: limits, port, domain, web access | `#resources` | 2.6 | 5.2 |
| Review | `#review` | 2.7 | 5.2 |
| One-liner: server address | `add-server-oneliner.html#server` | 3.2 | 5.1 |
| One-liner: command (no token), token with Copy, waiting, expired, unreachable, paired | `#waiting`, `#expired`, `#unreachable`, `#paired` | 3.3 to 3.6 | 5.1, 5.3 |
| Pairing code entry and failure | `#code`, `#code-err` | 4, map | 8.2 |
| Live progress: running, no percentage, failed with Retry, connection lost, success | `progress.html` | 2.8, 2.9 | 5.3, 5.8 |
| Connect: PIN, checking, wrong PIN, wait, last attempt, revoked, pair again, not available, unreachable, identity changed | `connect.html` | 5 | 8.2, 8.3 |
| Desktop view: toolbar hidden with hint, toolbar, Display, Quality, Keys, Transfers menus | `desktop.html#desktop` to `#transfers` | 5.3, 6 | 6.5, 11.1 |
| Stats overlay, file drag and drop, fullscreen | `#stats`, `#files`, `#fullscreen` | 6 | 6.5 |
| Reconnect overlay (and giving up), desktop not available | `#reconnect`, `#unavailable` | 5.4 | 11.1 |
| Takeover notice | `#takeover` | not in userflow | 8.1, protocol 5.7 |
| Open link? confirmation | `#openlink` | not in userflow | 8.7 |
| Server details: Overview (online, problems and update, offline) | `server-details.html#overview` | 10, 11 | 11.1 |
| Security: devices, revoke, pair a new device, change PIN, change password, web access and passkeys (Phase 3) | `#security`, `#revoke`, `#revoke-self`, `#pair`, `#pin`, `#password` | 8 | 8.3, 11.1 |
| Desktop: Docker, limits, restart, update agent, backup mode (Phase 2) | `#desktop`, `#docker`, `#restart` | 10 | 5.2, 11.1 |
| Danger zone: uninstall keep or destroy, SSH, confirm, done | `#danger`, `#uninstall-ssh`, `#uninstall-confirm`, `#uninstall-done` | 10 | 5.3 |
| Backups: timeline, Drive, schedule, alerts, keep this restore, restore dialog (Phase 2) | `#backups`, `#restore` | 7, 11 | 9 |
| App settings | `settings.html` | 12 | 11.1 |
| Tokens, contrast table, type, spacing, components, accessibility rules | `design-system.html` | 1.3 | 11.1 |

Slint feasibility: every element is a rectangle, row, column or text; controls map to `Button`, `LineEdit`, `Switch`, `ComboBox`, `Slider`, `ProgressIndicator` and a few custom components (`ServerCard`, `StageRow`, `NavItem`, the toolbar). Dialogs are a scrim plus a card. Where Slint's std-widgets differ in detail the app follows Slint and keeps the tokens.

## Open questions for the maintainer

Design decisions needed for approval:

1. **Theme default.** userflow 1.3 says the theme follows the system; the mockups open in dark because dark-first is the brief. Should a fresh install start on **System** (a light-desktop user sees light first) or on **Dark**?
2. **Phase 2 and 3 items in the Phase 1 build.** The mockups draw Backups (wizard step, Server details tab, card badges), web access and passkeys because userflow lists them. In Phase 1 they are shown disabled with a tag (the Backups step shows only "Off"). Hide them instead, or keep them visible as "coming soon"?
3. **Minimum window size** 900 x 600, and the toolbar turning icon-only below 1000 px. OK?
4. **Stage grouping.** The 19 installer stages (architecture 5.3) appear as ten rows with the real stage ids in small grey text. Is that the right level of detail?
5. **Password strength.** The wizard shows a strength meter (userflow 2.4). `hx-pwcheck` only runs inside the desktop, and no estimator is in `docs/tech-stack.md`. Which library or rule set (and what minimum length) does the client use? The mockups show the meter but only block on a mismatch, an invalid username and the PIN rule (6+ digits).
6. **Window frame.** The mockups show a plain system title bar. Slint's default is the system's own decorations; a custom title bar would need work on every desktop. Keep the system one?
7. **Device name.** App settings lets the user name this device ("Alex's desktop"), which the paired-devices list shows. Not in userflow. Keep?
8. **Remove a server from the app** (card menu, and after uninstall). Not in userflow. Needed.
9. **Retention.** architecture 9.7 gives three numbers (latest 14, 4 weekly, 6 monthly) and the installer option `--backup-keep` takes one integer 1 to 1000. The mockup follows 9.7 with three fields. Which one is right?

Behaviour not covered by userflow (all tagged `Proposed` in the mockups):

10. **Takeover notice** ("this desktop was opened on another device", offers Revoke that device, never reconnects by itself, "Take it back"). Follows protocol 5.7 and ipc.md 18; userflow 5 does not mention it. Wording and the "Take it back" action need approval.
11. **Open link? dialog.** Follows architecture 8.7; no userflow text. Design choices: full URL with the host in bold, Cancel is the default, no "always allow", only http and https.
12. **Server identity changed** (pinned key mismatch) as a blocking screen with no override. Architecture 8.2 and 8.7 imply it; userflow is silent.
13. **Pair a new device from Server details, Security.** userflow 8 lists devices and Revoke only. The mockup shows a pairing code (`K7QM-4XD2`) like `hx-agent pairing code`. The protocol's device-management message (1.2) can list and revoke but not issue a code, so an app that is already paired cannot ask for one today. Needs a protocol addition, or the screen says "run `hx-agent pairing code` on the server".
14. **Pair again after revoke.** userflow 5.2 says re-pairing needs the account password; no screen or message is specified. The mockup has a one-field "Pair again" form.
15. **SSH connection lost during an install.** Secrets are never stored (architecture 5.3), so Retry asks again for the SSH password and the account password and PIN. Confirm that is acceptable, or keep the password in memory while the app runs.
16. **Agent not reachable after the one-liner** (a cloud firewall blocks the port the installer opened). A message with "check your provider's firewall" and Try again.
17. **Reconnect gives up** after about 2 minutes with Try again and Back to Home. userflow 5.4 says only "Reconnecting...".
18. **Desktop not available** (`session_unavailable`) overlay and card state.

## Where userflow.md conflicts with, or goes beyond, the architecture and protocol

- **Uninstall from the app (userflow 10) vs root-only uninstall.** Architecture 5.3 and 8.5 make uninstall a root action that the agent's own connection cannot perform (`hx-agent uninstall`, privd's narrowed `Uninstall`). The app can only do it over SSH, as root. The mockup adds an "Uninstall needs SSH access" step; userflow 10 does not mention it.
- **Memory minimum.** userflow 2.2 says 4 GB RAM; the preflight (architecture 5.2) needs `MemTotal` of at least 3584 MiB (a "4 GB" VPS never reports 4096 MiB). The checks screen should say what the server reports and what the threshold is, so a 4 GB server does not look short.
- **Web access in the wizard.** userflow 2.6 lists "enable web access" under Resources, Advanced. In architecture 5.2 there is no such installer option and web access arrives with Phase 3, so the mockup shows the switch disabled. Domain is recorded only.
- **Backups in the install wizard.** userflow 2.5 describes the whole backup step; in Phase 1 `--backup` is recorded only and stage `backup` is `deferred` (architecture 5.2, 5.3). The mockup shows both the Phase 2 design and the Phase 1 form.
- **One-liner path.** userflow 3.5 and execution-phase 1G agree that setup after pairing (password, PIN, `CreateDesktop`, progress) needs the setup protocol that 1G still has to specify. The mockups draw the full flow, ending in "Paired, then setup continues" and the shared progress screen. The command also carries `--cpu`, `--memory`, `--docker` and the other non-secret options (architecture 5.2); whether they travel in the command or in the later setup message is a protocol decision.
- **PIN wait.** The brief and the protocol have an increasing wait between wrong PINs (protocol: `min(2^(n-1), 30)` seconds, `BACKOFF`) and `NOT_AVAILABLE`; userflow 5.2 only has the attempts-left message and the fifth-failure revoke. Both are drawn.
- **Revoked and locked devices.** The device list uses the states of ipc.md (`active`, `revoked`, `locked`). userflow 8 only says "Revoke". Reinstating a device is a server-side admin action (`ReinstateDevice`), so the app does not offer it.
- **Alerts.** userflow 11 and architecture 9.9 put ntfy and webhook alerts under Backups, Alerts (Phase 2); drawn there.
- **Quality names.** userflow 6 and architecture 11.1 agree (Auto, Sharp, Smooth). The remote resolution follows the window (RandR); the Display menu offers "Resize the remote screen to match" as a mode, which userflow 6 phrases the same way.
