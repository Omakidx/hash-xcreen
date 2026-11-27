//! The Drive helper: the `drive` role of `hx-backup-worker` (docs/ipc.md §24 and §29).
//!
//! The only process that speaks HTTPS to Google and holds the Drive token. It serves `hx-privd`
//! only, over the repository link, one connection at a time, on the socket systemd activates
//! (`hx-drive.socket`), and exits 60 s after the last connection closes.
//!
//! | Module | What it does |
//! |---|---|
//! | [`creds`] | The fixed OAuth client file and the `drive-token` credential. |
//! | [`connector`] | TCP and TLS 1.3 to the two Google hosts, global unicast addresses only. |
//! | [`transport`] | The one HTTP path: host check, permanent delete, upload pacing, what Drive answered. |
//! | [`rate`] | The upload-rate bucket (`SetUploadRate`). |
//! | [`retry`] | Classes of failure (§31), the retrier, the daily-limit gate, the timing. |
//! | [`lease`] | The repository lease rules (§29). |
//! | [`gdrive`] | The repository over OpenDAL's `gdrive` service. |
//! | [`server`] | One link session. |
//! | [`run`](mod@run) | Activation, one connection at a time, `SO_PEERCRED`, the idle exit. |

pub mod connector;
pub mod creds;
pub mod gdrive;
pub mod lease;
pub mod rate;
pub mod retry;
pub mod run;
pub mod server;
pub mod transport;

use std::path::PathBuf;
use std::time::Duration;

pub use run::{RoleConfig, run};

/// Everything a link session needs from the process.
#[derive(Debug, Clone)]
pub struct DriveConfig {
    /// The fixed OAuth client.
    pub client: creds::ClientConfig,
    /// `$CREDENTIALS_DIRECTORY` (where `drive-token` is).
    pub credentials_dir: Option<PathBuf>,
    /// How the HTTP client is built.
    pub http: transport::HttpConfig,
    /// Retry and timeout durations.
    pub timing: retry::Timing,
    /// A connection on which privd is silent this long is closed (the worker's 60 s, §32).
    pub silence: Duration,
    /// The host's name, for the lease's `hostname_hint`.
    pub hostname: Vec<u8>,
}
