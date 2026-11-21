//! `hx-gatewayd`: the internet-facing, unprivileged gateway.
//!
//! It terminates QUIC and WebSocket (`hx-transport`), authenticates every connection (pairing
//! over SPAKE2, then pinned key plus PIN, `hx-crypto`), owns the device registry, applies the
//! one-active-client and takeover policy, serves the client-facing device management of
//! protocol 1.2 and the root-only admin socket, and talks to the root `hx-privd` for everything
//! that needs privilege or the pepper. Relaying media between a client and the desktop is the
//! next round's work and plugs in behind [`desktop`].
//!
//! # Map
//!
//! | Module | Role |
//! |---|---|
//! | [`server`] | [`server::Gateway::start`]: wires everything, accepts pending sessions |
//! | [`verifier`] | `HMAC(pepper, Argon2id(secret))` records, their file, `PepperEnrol`, and `PrivdPinVerifier` (the authenticator's PIN check) |
//! | [`privd_client`] | the async client of `hx-privd` (role `Gateway`) |
//! | [`session`] | one authorized connection's control loop, claiming, takeover (ipc.md 18) |
//! | [`takeover`] | takeover policy and the 3-per-10-minutes limit |
//! | [`devices`] | list, revoke, change notices, audit events (protocol 5.9) |
//! | [`desktop`] | **the seam** for the session link, its stub, and the privd supervisor |
//! | [`admin`] | the root-only admin socket (ipc.md 9) |
//! | [`live`] | the set of live sessions and its caps |
//! | [`config`] | the configuration file |
//! | [`cli`] | the command line, with the test-only flag behind a feature |
//! | [`harden`] | `mlockall`, no core dumps, the seccomp allowlist |
//!
//! # Secrets
//!
//! Nothing here logs or formats a PIN, token, code, key or verifier. The types that carry them
//! (`hx_crypto::Pin`, `hx_ipc::secret::Secret`, `zeroize::Zeroizing`) redact `Debug` and wipe
//! on drop; errors carry no request content; peer-supplied text is sanitized before it is
//! logged. The pepper never enters this process.

pub mod admin;
pub mod cli;
pub mod config;
pub mod desktop;
pub mod devices;
pub mod harden;
pub(crate) mod ipc_io;
pub mod live;
pub mod privd_client;
pub mod server;
pub mod session;
pub mod takeover;
pub mod util;
pub mod verifier;
