# hx-desktop

The hash-xcreen desktop app (Slint). Workstream 1G. It adds servers (over SSH, with the one-liner, or with a pairing code), shows live install progress, connects with a PIN, and shows the remote desktop. Design source: `design/mockups/` (approved, with the maintainer decisions in its README); flows: `docs/userflow.md`.

## Run

```sh
cargo run -p hx-desktop                      # real servers; needs a Secret Service (GNOME Keyring, KWallet)
cargo run -p hx-desktop -- --demo            # everything fake, nothing saved, no keyring
cargo run -p hx-desktop -- --demo --screen connect-wrong --theme light
```

`--demo` runs the whole app against fakes. The PIN is `123456`. Host hints pick a story: an address containing `small` fails the requirement checks, `down` is unreachable, `fail` stops the install at `incus` once (Retry works), `lost` loses the SSH connection once, `changed` shows the identity-changed screen, `unavailable` answers NOT_AVAILABLE, `takeover` ends the session as taken over after 10 s, `drop` loses the connection once (reconnect overlay). Five wrong PINs revoke the demo device. The SSH password `wrong` is refused; a one-liner token containing `expired` is refused.

`--screen NAME` opens one state of the mockups (list: `app/showcase.rs`, `NAMES`); the screenshots and render tests use the same names. `HX_LOG=debug` turns logging on; `HX_REDUCED_MOTION=1` stops the spinner and the indeterminate bar. The theme follows the system unless forced in App settings or with `--theme`.

Without `--demo` the SSH install, pairing codes from the app, reinstate and server management answer "not part of this build yet" (`backend/real.rs`) until the integrator wires them; pairing with a token or code and the PIN session are real.

## Structure

| Path | What |
|---|---|
| `ui/tokens.slint` | `global Tokens`, one to one with `design/mockups/tokens.css`; dark, light, system |
| `ui/widgets.slint` | `Btn`, `Field`, `Toggle`, `Check`, `RadioRow`, `Segmented`, `SliderField`, `Badge`, `Banner`, `Dialog`, `Spinner`, `ProgressBar`; focus ring on every control |
| `ui/state.slint` | the view models (globals): `HomeVm`, `WizardVm`, `ProgressVm`, `ConnectVm`, `DesktopVm`, `DetailsVm`, `SettingsVm`, `Nav` |
| `ui/*.slint` | one file per screen family |
| `src/app/` | the controller: one `*_ctl.rs` per screen family, `progress.rs` (events into the ten rows), `prefs.rs`, `known_hosts.rs`, `showcase.rs` |
| `src/servers/` | the server list in `$XDG_CONFIG_HOME/hash-xcreen/servers.json` (0600); the key is pinned on first pairing, a different key is a blocking screen |
| `src/keys/` | the device key in the Secret Service through `keyring`; a missing service is a clear error screen, never a file |
| `src/session/` | `connect` (PIN state machine), `lifecycle` (close reasons, reconnect schedule, takeover), `net` (pair, PIN login, live session, device management), `desk` (the `Desk` and `Connector` seams) |
| `src/video/` | decode thread (FFmpeg H.264 to RGBA), frame ring, stats, the `Presenter` trait and `CpuPresenter` |
| `src/input/` | physical keys as USB HID usages, pointer mapping, scroll, the toolbar chord |
| `src/clipboard/`, `src/files/`, `src/links/` | clipboard policy without echo; limit check, safe names, activity; the open-link check (http and https only) |
| `src/wizard/` | the wizard state machine and field rules |
| `src/details/` | device rows, revoke rules, dialogs, the Danger zone flow |
| `src/backend/` | the traits below, the demo fakes, the real-or-unavailable set |

## Seams for the integrator

All in `src/backend/mod.rs` (and `session/desk.rs`); `Backends` holds one of each. `demo::backends(pace)` fills it with fakes, `real::backends(handle, device_name)` with what exists today.

* `InstallEngine`: `probe_host_key(&SshTarget) -> HostKey`, `preflight(&SshTarget, &SshAuth, &HostKey) -> Preflight`, `install(InstallRequest) -> Box<dyn InstallRun>` (events: stage, step with optional percent, warn, log, image path, connection lost, failed, finished), `uninstall(UninstallRequest)`. Adapter over `hx-sshsetup`.
* `SetupClient`: `pair(&ServerAddr, device, &Secret token or code) -> PairedInfo`, `start_setup(..., SetupRequest) -> Box<dyn InstallRun>`. The real `pair` exists; `start_setup` waits for `hx_crypto::setup`.
* `DeviceAdmin`: `create_pairing_code(&AdminContext)`, `reinstate(&AdminContext, &Secret)`.
* `ServerControl`: overview numbers, change PIN and password, restart, Docker, limits, agent update. No protocol message exists yet; this is the contract the Server details screens need.
* `session::Connector`: `connect(&Link, pin, on_secure, Wiring) -> Established` (one PIN attempt per call), `probe`. Real: `RealConnector`.

Listing and revoking devices, the PIN login, pairing, takeover and the live session use the 1.2 messages directly (`session/net.rs`).

## Video

Software decode with FFmpeg into RGBA, shown as a Slint `Image` from a `SharedPixelBuffer` (`CpuPresenter`). A GPU path (VAAPI to DMA-BUF to OpenGL, spike S1) implements `video::Presenter`; no other code changes. No GPU code is here.

## Tests

```sh
cargo nextest run -p hx-desktop                       # unit and UI tests
cargo nextest run -p hx-desktop --run-ignored only    # the headless session test against a real gatewayd (needs Xvfb)
```

Screenshots: `DISPLAY=:20 cargo run -p hx-desktop -- --demo --screen NAME` and `import -window root out.png`.
