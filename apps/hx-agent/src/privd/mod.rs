//! hx-privd: the root daemon serving the fixed command set of ipc.md Part 1 over
//! `/run/hx/privd.sock`. See `README.md` in this directory for the public library API, the
//! on-disk state and the operating notes.
//!
//! # Layers
//!
//! | Module | Role |
//! |---|---|
//! | [`activation`] | `sd_listen_fds` by hand (the crate's one audited `unsafe` block) and a path-binding fallback for tests |
//! | [`hardening`] | `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `mlockall` (all safe `rustix` calls) |
//! | [`identity`], [`config`] | the gateway uid from the compiled-in user name, the account-policy self-checks, fixed paths |
//! | [`server`] | accept, `SO_PEERCRED` role, `Decoder::read_from` over `NoCmsgReader`, secrets, cancel, deadlines |
//! | [`daemon`], [`auth`] | admission: authorization (class, `gateway_denied`, phase gates), rate limits, dispatch, audit |
//! | [`cmd`] | the commands, one module per group |
//! | [`state`], [`limiter`], [`pepper`], [`audit`] | persistent phase and registry, failure caps and lockout, the pepper, the audit log |
//! | [`runner`], [`probe`] | the closed set of host tools and host facts, behind traits |
//! | [`cancel`], [`progress`] | cancellation and per-desktop locks, lossy progress frames |
//! | [`update`] | self-update: manifest, keys, extraction, switch, health check (ipc.md 6.12) |
//! | [`image`] | prebuilt desktop images: keys, `choose`, fetch, offline import, cache (ipc.md 6.5, 6.12) |
//! | [`backup`] | the backup job runner: relay, Drive session, crash recovery (ipc.md Part 3) |

pub mod activation;
pub mod audit;
pub mod auth;
pub mod backup;
pub mod cancel;
pub mod clock;
pub mod cmd;
pub mod config;
pub mod daemon;
pub mod error;
pub mod hardening;
pub mod identity;
pub mod image;
pub mod limiter;
pub mod log;
pub mod peergroups;
pub mod pepper;
pub mod probe;
pub mod progress;
pub mod rescue;
pub mod runner;
pub mod server;
pub mod state;
pub mod timefmt;
pub mod update;
pub mod usage;

#[cfg(any(test, feature = "test-support"))]
pub mod testing;

pub use config::PrivdConfig;
pub use daemon::{Ctx, Daemon, Deps};
pub use error::CmdError;
pub use server::{ServeOptions, serve};

/// Whether a string is safe to write into an audit line as a desktop id.
pub(crate) use hx_ipc::privd::is_valid_desktop_id as is_safe_desktop_id;
