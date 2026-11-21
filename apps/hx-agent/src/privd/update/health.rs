//! The post-update health check (ipc.md 6.12).
//!
//! An update counts as healthy when, within the window (90 s):
//!
//! 1. privd answers on its socket after the re-exec;
//! 2. gatewayd is active with the **same** `MainPID` for 30 s (a crash loop changes the pid and
//!    restarts the clock);
//! 3. gatewayd's **admin** socket answers `Status`. The admin socket is used because it sits
//!    outside the pre-authentication connection limits: an internet flood that fills the public
//!    listener cannot make an update look unhealthy.
//!
//! The link state and a loopback `Hello` are reported in `Status` but are **never** criteria: an
//! unreachable container or a full pre-auth table is not evidence that the new binaries are bad.

use std::time::{Duration, Instant};

use hx_ipc::text::sanitize_text;

use super::UpdateDeps;
use super::system::Unit;

/// Timing of the check. The defaults are the contract's; tests shrink them.
#[derive(Debug, Clone, Copy)]
pub struct HealthPolicy {
    /// All three conditions must hold within this long of the switch.
    pub window: Duration,
    /// How long gatewayd's `MainPID` must stay unchanged.
    pub stable: Duration,
    /// Pause between polls.
    pub poll: Duration,
}

impl Default for HealthPolicy {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(90),
            stable: Duration::from_secs(30),
            poll: Duration::from_secs(1),
        }
    }
}

/// What the check must see to believe the new binaries are the ones running.
#[derive(Debug, Clone, Copy)]
pub struct Expect<'a> {
    /// The version privd and gatewayd must report (`HelloAck.privd_version`,
    /// `Status.gatewayd_version`; a release's `CARGO_PKG_VERSION` equals its manifest version).
    pub version: &'a str,
    /// gatewayd's `MainPID` before the update: a gatewayd that still has it was not restarted
    /// into the new binary.
    pub old_gateway_pid: Option<u32>,
}

/// Runs the check for at most `budget` (the part of the window not yet used). `Err` carries the
/// reason, in privd's own words.
pub async fn check(
    deps: &UpdateDeps,
    policy: &HealthPolicy,
    budget: Duration,
    expect: &Expect<'_>,
) -> Result<(), String> {
    let deadline = Instant::now() + budget;
    let left = || deadline.saturating_duration_since(Instant::now());

    // 1. privd answers, and is the new one.
    let mut privd_seen: Option<String> = None;
    loop {
        match deps.probe.privd_answers().await {
            Some(v) if v == expect.version => break,
            Some(v) => privd_seen = Some(v),
            None => {}
        }
        if left().is_zero() {
            return Err(match privd_seen {
                Some(v) => format!("privd answers as version {v}, not {}", expect.version),
                None => "privd did not answer on its socket after the re-exec".into(),
            });
        }
        tokio::time::sleep(policy.poll.min(left())).await;
    }

    // 2. gatewayd is active with a stable MainPID.
    let mut pid = 0u32;
    let mut since = Instant::now();
    let mut not_restarted = false;
    loop {
        match deps.systemd.state(Unit::Gatewayd).await {
            // Still the process that ran before the update: not restarted into the new binary.
            Ok(s) if s.active && Some(s.main_pid) == expect.old_gateway_pid => {
                not_restarted = true;
                pid = 0;
                since = Instant::now();
            }
            Ok(s) if s.active && s.main_pid != 0 => {
                not_restarted = false;
                if s.main_pid != pid {
                    pid = s.main_pid;
                    since = Instant::now();
                }
                if since.elapsed() >= policy.stable {
                    break;
                }
            }
            _ => {
                pid = 0;
                since = Instant::now();
            }
        }
        if left().is_zero() {
            return Err(if not_restarted {
                "gatewayd was not restarted: it still has its pre-update MainPID".to_string()
            } else {
                format!(
                    "gatewayd was not active with a stable MainPID for {} s",
                    policy.stable.as_secs()
                )
            });
        }
        tokio::time::sleep(policy.poll.min(left())).await;
    }

    // 3. the admin socket answers Status, and reports the new version.
    let mut seen: Option<String> = None;
    loop {
        match deps.probe.gatewayd_status().await {
            Some(v) if v == expect.version => return Ok(()),
            Some(v) => seen = Some(v),
            None => {}
        }
        if left().is_zero() {
            return Err(match seen {
                Some(v) => format!(
                    "gatewayd reports version `{}`, not {}",
                    sanitize_text(&v, 32),
                    expect.version
                ),
                None => "gatewayd's admin socket did not answer Status".into(),
            });
        }
        tokio::time::sleep(policy.poll.min(left())).await;
    }
}
