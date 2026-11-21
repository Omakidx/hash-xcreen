//! In-container session daemon: capture, encode, audio, clipboard and input. Holds no secrets.
//!
//! Started by `hx-session.service` through `hx-session.socket` (`docs/ipc.md` section 11): the
//! listening socket arrives as fd 3 and the daemon never creates or binds a path. The unit sets
//! `DISPLAY` and `XAUTHORITY`; optional overrides for tests and unusual installs:
//!
//! * `HX_SESSION_RECEIVED_DIR`: where received files go (default `/var/lib/hx-session/received`);
//! * `HX_SESSION_MAX_FILE_BYTES`: a lower file-size limit than the default 4 GiB.
//!
//! The daemon never launches user-facing programs.

use hx_session::link::{Server, SessionConfig, activation};
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut cfg = SessionConfig::new(None);
    if let Some(dir) = std::env::var_os("HX_SESSION_RECEIVED_DIR") {
        cfg.received_dir = PathBuf::from(dir);
    }
    if let Some(Ok(max)) = std::env::var("HX_SESSION_MAX_FILE_BYTES")
        .ok()
        .map(|v| v.parse::<u64>())
    {
        cfg.max_file_bytes = cfg.max_file_bytes.min(max);
    }
    let listener = match activation::listener_from_env() {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "hx-session {}: {e}; the daemon is started through hx-session.socket",
                env!("CARGO_PKG_VERSION")
            );
            return ExitCode::from(2);
        }
    };
    match Server::new(listener, cfg).and_then(Server::run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hx-session: {e}");
            ExitCode::FAILURE
        }
    }
}
