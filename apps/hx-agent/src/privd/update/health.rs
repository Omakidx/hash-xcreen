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

/// Runs the check for at most `budget` (the part of the window not yet used). `Err` carries the
/// reason, in privd's own words.
pub async fn check(
    deps: &UpdateDeps,
    policy: &HealthPolicy,
    budget: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + budget;
    let left = || deadline.saturating_duration_since(Instant::now());

    // 1. privd answers.
    loop {
        if deps.probe.privd_answers().await {
            break;
        }
        if left().is_zero() {
            return Err("privd did not answer on its socket after the re-exec".into());
        }
        tokio::time::sleep(policy.poll.min(left())).await;
    }

    // 2. gatewayd is active with a stable MainPID.
    let mut pid = 0u32;
    let mut since = Instant::now();
    loop {
        match deps.systemd.state(Unit::Gatewayd).await {
            Ok(s) if s.active && s.main_pid != 0 => {
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
            return Err(format!(
                "gatewayd was not active with a stable MainPID for {} s",
                policy.stable.as_secs()
            ));
        }
        tokio::time::sleep(policy.poll.min(left())).await;
    }

    // 3. the admin socket answers Status.
    loop {
        if deps.probe.gatewayd_status().await {
            return Ok(());
        }
        if left().is_zero() {
            return Err("gatewayd's admin socket did not answer Status".into());
        }
        tokio::time::sleep(policy.poll.min(left())).await;
    }
}
