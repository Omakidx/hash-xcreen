//! The authorized client connections that are alive, for the admin `Status`, for counting the
//! sessions a revocation closes, for `CloseSessions`, and for the per-device and total caps
//! that bound what an authenticated peer can hold open.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use hx_crypto::DeviceId;
use hx_proto::channel::CloseCode;
use hx_transport::Connection;

/// Live sessions at most, in total.
pub const MAX_LIVE_SESSIONS: usize = 32;
/// Live sessions at most per device.
pub const MAX_SESSIONS_PER_DEVICE: usize = 4;

/// Why a connection was not registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Full;

/// The set of live sessions.
#[derive(Default)]
pub struct LiveSessions {
    next: AtomicU64,
    map: Mutex<HashMap<u64, (DeviceId, Connection)>>,
}

/// Removes its session from the set when dropped.
pub struct LiveGuard {
    live: Arc<LiveSessions>,
    token: u64,
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        self.live
            .map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.token);
    }
}

impl LiveGuard {
    /// This session's token (unique for the life of the process).
    pub fn token(&self) -> u64 {
        self.token
    }
}

impl LiveSessions {
    /// A new empty set.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Registers `conn` for `device`, or refuses when a cap is reached.
    pub fn register(
        self: &Arc<Self>,
        device: DeviceId,
        conn: Connection,
    ) -> Result<LiveGuard, Full> {
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        if map.len() >= MAX_LIVE_SESSIONS
            || map.values().filter(|(d, _)| *d == device).count() >= MAX_SESSIONS_PER_DEVICE
        {
            return Err(Full);
        }
        let token = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        map.insert(token, (device, conn));
        Ok(LiveGuard {
            live: self.clone(),
            token,
        })
    }

    /// Sessions alive now.
    pub fn count(&self) -> usize {
        self.map.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Sessions alive now for `device`.
    pub fn count_for(&self, device: &DeviceId) -> usize {
        self.map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .filter(|(d, _)| d == device)
            .count()
    }

    fn connections(&self) -> Vec<Connection> {
        self.map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .map(|(_, c)| c.clone())
            .collect()
    }

    /// Closes every live session of `device` with `code` and returns how many were closed.
    /// This does not depend on the sessions' own loops, so a session that is busy (claiming
    /// the desktop, waiting on privd) is closed at once when its device is revoked.
    pub async fn close_device(&self, device: &DeviceId, code: CloseCode, reason: &str) -> usize {
        let conns: Vec<Connection> = self
            .map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .filter(|(d, _)| d == device)
            .map(|(_, c)| c.clone())
            .collect();
        let n = conns.len();
        let tasks: Vec<_> = conns
            .into_iter()
            .map(|c| {
                let reason = reason.to_owned();
                tokio::spawn(async move { c.close(code, &reason).await })
            })
            .collect();
        for t in tasks {
            let _ = t.await;
        }
        n
    }

    /// Closes every live session with `code` and returns how many were closed.
    pub async fn close_all(&self, code: CloseCode, reason: &str) -> usize {
        let conns = self.connections();
        let n = conns.len();
        // Closing waits for delivery; do it concurrently so one slow peer does not hold up the
        // rest.
        let reason = reason.to_owned();
        let tasks: Vec<_> = conns
            .into_iter()
            .map(|c| {
                let reason = reason.clone();
                tokio::spawn(async move { c.close(code, &reason).await })
            })
            .collect();
        for t in tasks {
            let _ = t.await;
        }
        n
    }
}
