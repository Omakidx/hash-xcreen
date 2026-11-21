//! Cancellation of a running request, and the locks that serialize work (ipc.md 4 and 8).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use super::error::CmdError;

/// Why a request is being stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReason {
    /// A `Cancel` frame for this request.
    Cancelled,
    /// The deadline passed.
    Deadline,
    /// The connection closed.
    Closed,
}

impl CancelReason {
    /// The error a cancelled command ends with.
    pub fn error(self) -> CmdError {
        match self {
            Self::Deadline => CmdError::deadline(),
            _ => CmdError::cancelled(),
        }
    }
}

struct Inner {
    reason: AtomicU8,
    notify: Notify,
}

/// A request's cancellation flag. Cloning shares it.
#[derive(Clone)]
pub struct CancelToken(Arc<Inner>);

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelToken {
    /// A token that has not fired.
    pub fn new() -> Self {
        Self(Arc::new(Inner {
            reason: AtomicU8::new(0),
            notify: Notify::new(),
        }))
    }

    /// Fires the token. The first reason wins.
    pub fn cancel(&self, reason: CancelReason) {
        let v = match reason {
            CancelReason::Cancelled => 1,
            CancelReason::Deadline => 2,
            CancelReason::Closed => 3,
        };
        if self
            .0
            .reason
            .compare_exchange(0, v, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.0.notify.notify_waiters();
        }
    }

    /// The reason, if the token has fired.
    pub fn reason(&self) -> Option<CancelReason> {
        match self.0.reason.load(Ordering::SeqCst) {
            1 => Some(CancelReason::Cancelled),
            2 => Some(CancelReason::Deadline),
            3 => Some(CancelReason::Closed),
            _ => None,
        }
    }

    /// Completes when the token fires.
    pub async fn cancelled(&self) -> CancelReason {
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            // Register before checking, so a `cancel` between the check and the await is seen.
            notified.as_mut().enable();
            if let Some(r) = self.reason() {
                return r;
            }
            notified.await;
        }
    }
}

/// Most waiters per lock; the next is refused at once (ipc.md 8).
pub const MAX_WAITERS: usize = 4;
/// How long a command waits for its lock before `RESOURCE_EXHAUSTED`.
pub const LOCK_WAIT: Duration = Duration::from_secs(10);

struct Lock {
    sem: Arc<Semaphore>,
    waiters: AtomicUsize,
}

impl Lock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            sem: Arc::new(Semaphore::new(1)),
            waiters: AtomicUsize::new(0),
        })
    }
}

/// What a lock protects.
#[derive(Debug, Clone, Copy)]
pub enum LockKey<'a> {
    /// The one host lock (`SetupHost`, `Uninstall`, `ApplyUpdate`, `UpgradeIncus`).
    Host,
    /// One desktop id.
    Desktop(&'a str),
}

/// A held lock; released on drop.
#[derive(Debug)]
pub struct Guard(#[allow(dead_code)] OwnedSemaphorePermit);

/// The host lock and one lock per desktop id.
pub struct Locks {
    host: Arc<Lock>,
    desktops: Mutex<HashMap<String, Arc<Lock>>>,
}

impl Default for Locks {
    fn default() -> Self {
        Self::new()
    }
}

struct WaiterGuard<'a>(&'a AtomicUsize);

impl Drop for WaiterGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Locks {
    /// No lock is held.
    pub fn new() -> Self {
        Self {
            host: Lock::new(),
            desktops: Mutex::new(HashMap::new()),
        }
    }

    fn lock_for(&self, key: LockKey<'_>) -> Arc<Lock> {
        match key {
            LockKey::Host => self.host.clone(),
            LockKey::Desktop(id) => {
                let mut map = self.desktops.lock().unwrap_or_else(|e| e.into_inner());
                if map.len() > 64 {
                    map.retain(|_, l| Arc::strong_count(l) > 1);
                }
                map.entry(id.to_string()).or_insert_with(Lock::new).clone()
            }
        }
    }

    /// Takes the lock: immediately if free; otherwise waits up to `wait`, but at most
    /// [`MAX_WAITERS`] commands wait (the next is refused at once). A `cancel` while waiting ends
    /// the wait with the cancellation error.
    pub async fn acquire(
        &self,
        key: LockKey<'_>,
        cancel: &CancelToken,
        wait: Duration,
    ) -> Result<Guard, CmdError> {
        let lock = self.lock_for(key);
        if let Ok(p) = lock.sem.clone().try_acquire_owned() {
            return Ok(Guard(p));
        }
        if lock.waiters.fetch_add(1, Ordering::SeqCst) >= MAX_WAITERS {
            lock.waiters.fetch_sub(1, Ordering::SeqCst);
            return Err(CmdError::exhausted(
                "too many commands are waiting for this desktop",
                1000,
            ));
        }
        let _w = WaiterGuard(&lock.waiters);
        tokio::select! {
            p = lock.sem.clone().acquire_owned() => match p {
                Ok(p) => Ok(Guard(p)),
                Err(_) => Err(CmdError::internal("lock closed")),
            },
            () = tokio::time::sleep(wait) => Err(CmdError::exhausted(
                "another command is running on this desktop",
                u32::try_from(wait.as_millis()).unwrap_or(10_000),
            )),
            r = cancel.cancelled() => Err(r.error()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn token_fires_once_and_wakes_waiters() {
        let t = CancelToken::new();
        assert_eq!(t.reason(), None);
        let t2 = t.clone();
        let h = tokio::spawn(async move { t2.cancelled().await });
        tokio::task::yield_now().await;
        t.cancel(CancelReason::Deadline);
        t.cancel(CancelReason::Cancelled);
        assert_eq!(h.await.unwrap(), CancelReason::Deadline);
        assert_eq!(t.reason(), Some(CancelReason::Deadline));
        assert_eq!(t.cancelled().await, CancelReason::Deadline);
    }

    #[tokio::test]
    async fn a_desktop_has_a_single_in_flight_slot() {
        let locks = Arc::new(Locks::new());
        let c = CancelToken::new();
        let g = locks
            .acquire(LockKey::Desktop("main"), &c, LOCK_WAIT)
            .await
            .unwrap();
        // Another desktop and the host lock are independent.
        let _other = locks
            .acquire(LockKey::Desktop("two"), &c, LOCK_WAIT)
            .await
            .unwrap();
        let _host = locks.acquire(LockKey::Host, &c, LOCK_WAIT).await.unwrap();
        // The same desktop waits, then times out with RESOURCE_EXHAUSTED and a retry hint.
        let e = locks
            .acquire(LockKey::Desktop("main"), &c, Duration::from_millis(30))
            .await
            .unwrap_err();
        assert_eq!(e.code, hx_ipc::privd::pb::ErrorCode::ResourceExhausted);
        assert!(e.retry_after_ms > 0 && e.retryable);
        drop(g);
        locks
            .acquire(LockKey::Desktop("main"), &c, Duration::from_millis(30))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn at_most_four_waiters_then_immediate_refusal() {
        let locks = Arc::new(Locks::new());
        let c = CancelToken::new();
        let _held = locks
            .acquire(LockKey::Desktop("main"), &c, LOCK_WAIT)
            .await
            .unwrap();
        let mut waiters = Vec::new();
        for _ in 0..MAX_WAITERS {
            let (l, c) = (locks.clone(), c.clone());
            waiters.push(tokio::spawn(async move {
                l.acquire(LockKey::Desktop("main"), &c, Duration::from_millis(500))
                    .await
                    .map(|_| ())
            }));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let started = std::time::Instant::now();
        let e = locks
            .acquire(LockKey::Desktop("main"), &c, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(e.code, hx_ipc::privd::pb::ErrorCode::ResourceExhausted);
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "refused at once"
        );
        for w in waiters {
            assert!(w.await.unwrap().is_err());
        }
    }

    #[tokio::test]
    async fn cancel_ends_a_lock_wait() {
        let locks = Arc::new(Locks::new());
        let c = CancelToken::new();
        let _held = locks
            .acquire(LockKey::Host, &CancelToken::new(), LOCK_WAIT)
            .await
            .unwrap();
        let (l, c2) = (locks.clone(), c.clone());
        let h = tokio::spawn(async move { l.acquire(LockKey::Host, &c2, LOCK_WAIT).await });
        tokio::time::sleep(Duration::from_millis(30)).await;
        c.cancel(CancelReason::Cancelled);
        let e = h.await.unwrap().unwrap_err();
        assert_eq!(e.code, hx_ipc::privd::pb::ErrorCode::Cancelled);
    }
}
