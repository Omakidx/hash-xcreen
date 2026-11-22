//! The post-pairing setup of the one-liner path (protocol 1.3, `docs/protocol.md` 5.10 and
//! `docs/ipc.md` 5.5): what gatewayd does behind the `INTENT_SETUP` connection.
//!
//! | Module | Role |
//! |---|---|
//! | [`store`] | [`store::SetupStore`]: the persisted window mirror and setup binding (`/var/lib/hx-gatewayd/setup`, 0600, atomic) |
//! | [`coordinator`] | [`SetupCoordinator`]: the window, the binding, the one job, the [`hx_crypto::SetupGate`], `set_pin` / `start` / `cancel` / `finish` |
//! | [`job`] | the job itself: validation, the privd steps on the dedicated lane, progress and error mapping |
//! | [`conn`] | one authorized `INTENT_SETUP` connection's control loop |
//!
//! # Secrets
//!
//! The PIN and the password are copied into `Zeroizing` buffers as soon as they are read from
//! the message, which is then dropped. The PIN lives until `PepperEnrol` answers; the password
//! until the `CreateDesktop` (or `SetUserPassword`) secret frame is written, and nothing is
//! cached across a disconnect, a job end or a restart. Nothing in this module logs, formats or
//! returns a secret: errors and acks carry field names and fixed texts only.

pub mod conn;
pub mod coordinator;
pub mod job;
pub mod store;

use std::time::Duration;

use hx_crypto::PinParams;

pub use coordinator::{SetupCoordinator, SetupStatus};

/// Less than this much window left refuses `start` with `WINDOW_TOO_SHORT`: the 45-minute
/// `CreateDesktop` maximum plus a margin (docs/ipc.md 5.1).
pub const MIN_WINDOW_REMAINING_S: u64 = 50 * 60;
/// `start` requests accepted per hour per server.
pub const STARTS_PER_HOUR: usize = 6;
/// `set_pin` attempts per hour per server (they only repeat while `PepperEnrol` fails).
pub const PIN_ATTEMPTS_PER_HOUR: usize = 10;
/// Requests per second per connection, and the burst.
pub const REQUESTS_PER_SECOND: f64 = 2.0;
/// The burst of [`REQUESTS_PER_SECOND`].
pub const REQUEST_BURST: f64 = 8.0;
/// A setup connection with no running job closes after this long without traffic.
pub const IDLE_CLOSE: Duration = Duration::from_secs(600);
/// Control writes are bounded to this.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// Tunables; [`SetupSettings::new`] has the production values.
#[derive(Debug, Clone)]
pub struct SetupSettings {
    /// The desktop the job creates (`main`).
    pub desktop_id: String,
    /// Argon2id cost of the PIN and password verifiers (the SSH path's default).
    pub params: PinParams,
    /// Wait between `FinishSetup` retries (2 s).
    pub finish_retry_wait: Duration,
    /// [`IDLE_CLOSE`].
    pub idle_close: Duration,
    /// Bound on the privd calls of admission, facts and `finish`.
    pub privd_timeout: Duration,
}

impl SetupSettings {
    /// The production settings for `desktop_id`.
    pub fn new(desktop_id: impl Into<String>) -> Self {
        Self {
            desktop_id: desktop_id.into(),
            params: PinParams::DEFAULT,
            finish_retry_wait: Duration::from_secs(2),
            idle_close: IDLE_CLOSE,
            privd_timeout: Duration::from_secs(5),
        }
    }
}
