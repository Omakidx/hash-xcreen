//! The seam between the gateway and the desktop: where the session link plugs in.
//!
//! This round the gateway owns the client side (QUIC and WebSocket, pairing, login, takeover,
//! device management). Relaying media between a client connection and the desktop is the next
//! round's job, once the gateway side of the session link (`apps/hx-agent/src/link`) and
//! `hx-session` exist. Everything the gateway needs from the link is behind two traits so that
//! round adds an implementation and changes nothing else:
//!
//! * [`DesktopLink`]: "give this client the desktop". [`DesktopLink::attach`] is step (4) of the
//!   takeover sequence (`docs/ipc.md` section 18): it increments the link's `epoch` and sends
//!   `start{epoch, config}` for the new client, and from then on the implementation owns the
//!   media relay for that client (it holds the client's [`hx_transport::Connection`] in the
//!   [`AttachRequest`]).
//! * [`LinkClient`]: the handle of one attached client, used by the gateway for what the client
//!   sends on the control channel and for the takeover steps (1) and (2).
//!
//! [`UnavailableLink`] is the stub used until the link exists: every `attach` answers
//! [`LinkError::Unavailable`], so a client that asks to view the desktop is told "desktop
//! unavailable" (`Goodbye{BUSY}`) while login, pairing and device management work.
//!
//! # Contract for implementations
//!
//! * `attach` is called with the gateway's per-desktop lock held and at most once at a time; it
//!   must not block on the old client (the gateway has already stopped and detached it).
//! * `release_input` and `cancel_in_flight` are called on the **old** client's handle, in this
//!   order, bounded to 2 s each; then `detach(Displaced)`; the old client is then told it was
//!   displaced and its connection is closed; then `attach` runs for the new one. After
//!   `detach(Displaced)` nothing from the old client may reach the session (only the current
//!   `epoch` sends input, ipc.md 18).
//! * `detach(Left)` is called when a client's connection ended or its device was revoked; when
//!   the last client leaves the implementation sends `stop` and keeps the link 30 s (ipc.md 18).
//! * `detach` is idempotent and must not fail.
//! * Nothing here may trust session-supplied text or bytes (ipc.md 19.1); the gateway never
//!   forwards session text to a client except through validated, numeric messages.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use hx_crypto::DeviceId;
use hx_ipc::admin::pb::LinkState;
use hx_proto::pb;
use hx_proto::version::Negotiated;
use hx_transport::Connection;

use super::privd_client::PrivdClient;

/// A boxed future, so that the traits below are usable as `dyn`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why the desktop cannot be given to a client.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// The desktop or its link is not available (not created, stopped, link down, session
    /// outdated). The client is told "desktop unavailable" and may retry.
    #[error("desktop unavailable")]
    Unavailable,
    /// The link failed while attaching.
    #[error("link failure: {0}")]
    Failed(String),
}

/// What the link receives when a client is attached.
pub struct AttachRequest {
    /// The client's authorized connection: the link's relay sends video, cursor and audio on
    /// it and reads input, mouse and transfers from it.
    pub connection: Connection,
    /// The client's device id.
    pub device_id: DeviceId,
    /// The device name, sanitized (for logs; never a decision).
    pub device_name: String,
    /// What was negotiated with this client (features, codecs, file limit).
    pub negotiated: Negotiated,
    /// The first `ViewConfig` the client sent (validated against `negotiated`).
    pub view: pb::ViewConfig,
}

/// Why a client's handle is being released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachReason {
    /// The client left, or its connection or device ended. The link may stop after its
    /// keep-alive when it was the last client.
    Left,
    /// Another client took over; the link keeps running for the newcomer.
    Displaced,
}

/// The desktop as the gateway sees it. One implementation per desktop; v1 has one desktop.
pub trait DesktopLink: Send + Sync + 'static {
    /// Gives the desktop to `request`'s client (takeover step 4). See the module contract.
    fn attach(
        &self,
        request: AttachRequest,
    ) -> BoxFuture<'_, Result<std::sync::Arc<dyn LinkClient>, LinkError>>;

    /// The link's state for the admin `Status` (informational; never a rollback criterion).
    fn state(&self) -> LinkState;
}

/// The handle of one attached client.
pub trait LinkClient: Send + Sync {
    /// A new `ViewConfig` from the client (each replaces the previous one).
    fn view_config(&self, config: pb::ViewConfig) -> BoxFuture<'_, ()>;
    /// The client lost sync and wants a fresh full image.
    fn request_keyframe(&self, last_decoded_frame: u32) -> BoxFuture<'_, ()>;
    /// The client's decode statistics (about once a second).
    fn client_stats(&self, stats: pb::ClientStats) -> BoxFuture<'_, ()>;
    /// Takeover step (1): stop forwarding this client's input and send `input{release_all}` to
    /// the session.
    fn release_input(&self) -> BoxFuture<'_, ()>;
    /// Takeover step (2): cancel this client's in-flight frames and abort its transfers.
    fn cancel_in_flight(&self) -> BoxFuture<'_, ()>;
    /// Releases the handle. Idempotent.
    fn detach(&self, reason: DetachReason) -> BoxFuture<'_, ()>;
}

/// Wraps the handle a link returned: once it is detached (the client left, was displaced or was
/// revoked) every further call is ignored, whatever the implementation does. A displaced
/// client's session loop can still deliver a `ViewConfig` for a moment; it must reach nothing.
pub struct GuardedClient {
    inner: std::sync::Arc<dyn LinkClient>,
    detached: std::sync::atomic::AtomicBool,
}

impl GuardedClient {
    /// Wraps `inner`.
    pub fn new(inner: std::sync::Arc<dyn LinkClient>) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            inner,
            detached: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn live(&self) -> bool {
        !self.detached.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl LinkClient for GuardedClient {
    fn view_config(&self, config: pb::ViewConfig) -> BoxFuture<'_, ()> {
        if self.live() {
            self.inner.view_config(config)
        } else {
            Box::pin(async {})
        }
    }
    fn request_keyframe(&self, last: u32) -> BoxFuture<'_, ()> {
        if self.live() {
            self.inner.request_keyframe(last)
        } else {
            Box::pin(async {})
        }
    }
    fn client_stats(&self, stats: pb::ClientStats) -> BoxFuture<'_, ()> {
        if self.live() {
            self.inner.client_stats(stats)
        } else {
            Box::pin(async {})
        }
    }
    fn release_input(&self) -> BoxFuture<'_, ()> {
        if self.live() {
            self.inner.release_input()
        } else {
            Box::pin(async {})
        }
    }
    fn cancel_in_flight(&self) -> BoxFuture<'_, ()> {
        if self.live() {
            self.inner.cancel_in_flight()
        } else {
            Box::pin(async {})
        }
    }
    fn detach(&self, reason: DetachReason) -> BoxFuture<'_, ()> {
        // Once, whatever the caller does.
        if self
            .detached
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            Box::pin(async {})
        } else {
            self.inner.detach(reason)
        }
    }
}

/// The stub link of this round: there is no desktop to relay yet.
#[derive(Debug, Default)]
pub struct UnavailableLink;

impl DesktopLink for UnavailableLink {
    fn attach(
        &self,
        _request: AttachRequest,
    ) -> BoxFuture<'_, Result<std::sync::Arc<dyn LinkClient>, LinkError>> {
        Box::pin(async { Err(LinkError::Unavailable) })
    }

    fn state(&self) -> LinkState {
        LinkState::SessionUnavailable
    }
}

/// Why [`DesktopSupervisor::ensure_ready`] could not make the desktop ready (the text is for
/// logs; the client is only told "desktop unavailable").
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct NotReady(pub String);

struct SupervisorState {
    link_provisioned: bool,
    last_start: Option<Instant>,
}

/// Keeps the desktop up for the gateway through privd (`GetDesktop`, `StartDesktop`,
/// `ProvisionSessionLink`, `docs/ipc.md` sections 6.6, 6.7 and 6.11), before a client is given
/// to the link. All of these are class `A`/`R` commands the `Gateway` role may call.
pub struct DesktopSupervisor {
    privd: PrivdClient,
    desktop_id: String,
    state: tokio::sync::Mutex<SupervisorState>,
}

/// A stopped desktop is started at most this often (privd rate limits `StartDesktop`).
const START_INTERVAL: Duration = Duration::from_secs(30);

impl DesktopSupervisor {
    /// A supervisor of `desktop_id`.
    pub fn new(privd: PrivdClient, desktop_id: String) -> Self {
        Self {
            privd,
            desktop_id,
            state: tokio::sync::Mutex::new(SupervisorState {
                link_provisioned: false,
                last_start: None,
            }),
        }
    }

    /// Makes sure the desktop exists and runs, and that its link socket is provisioned.
    pub async fn ensure_ready(&self) -> Result<(), NotReady> {
        use hx_ipc::privd::pb::DesktopState as S;
        let mut st = self.state.lock().await;
        let desktop = self
            .privd
            .get_desktop(&self.desktop_id)
            .await
            .map_err(|e| NotReady(format!("GetDesktop: {e}")))?
            .ok_or_else(|| NotReady("the desktop does not exist".into()))?;
        match S::try_from(desktop.state).unwrap_or(S::Unspecified) {
            S::Running | S::Ready => {}
            S::Stopped => {
                if st.last_start.is_some_and(|t| t.elapsed() < START_INTERVAL) {
                    return Err(NotReady("the desktop is starting".into()));
                }
                st.last_start = Some(Instant::now());
                let power = self
                    .privd
                    .start_desktop(&self.desktop_id)
                    .await
                    .map_err(|e| NotReady(format!("StartDesktop: {e}")))?;
                if !power.running {
                    return Err(NotReady("the desktop did not start".into()));
                }
                st.link_provisioned = false;
            }
            S::Starting | S::Creating => return Err(NotReady("the desktop is starting".into())),
            S::Failed | S::Unspecified => return Err(NotReady("the desktop is not usable".into())),
        }
        let provisioned = desktop.session.as_ref().is_some_and(|s| s.link_provisioned);
        if !(provisioned || st.link_provisioned) {
            self.privd
                .provision_session_link(&self.desktop_id)
                .await
                .map_err(|e| NotReady(format!("ProvisionSessionLink: {e}")))?;
            st.link_provisioned = true;
        }
        Ok(())
    }
}

/// A [`DesktopLink`] that records what the gateway does to it, for the tests of this crate and
/// of the next round's relay. Not for production use.
#[doc(hidden)]
pub mod recording {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// What happened, in order.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Event {
        /// `attach` for this device name.
        Attach(String),
        /// `release_input` on the client attached for this device name.
        ReleaseInput(String),
        /// `cancel_in_flight` on that client.
        CancelInFlight(String),
        /// `detach` with its reason.
        Detach(String, DetachReason),
        /// `view_config` forwarded.
        View(String),
        /// `request_keyframe` forwarded.
        Keyframe(String),
        /// `client_stats` forwarded.
        Stats(String),
    }

    /// A working fake link.
    #[derive(Default)]
    pub struct RecordingLink {
        /// The events so far.
        pub events: Arc<Mutex<Vec<Event>>>,
        /// Make `attach` fail with `Unavailable` when set.
        pub unavailable: Arc<Mutex<bool>>,
    }

    impl RecordingLink {
        /// The events so far.
        pub fn log(&self) -> Vec<Event> {
            self.events.lock().unwrap().clone()
        }
    }

    struct Client {
        name: String,
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl Client {
        fn push(&self, e: Event) {
            self.events.lock().unwrap().push(e);
        }
    }

    impl LinkClient for Client {
        fn view_config(&self, _config: pb::ViewConfig) -> BoxFuture<'_, ()> {
            self.push(Event::View(self.name.clone()));
            Box::pin(async {})
        }
        fn request_keyframe(&self, _last: u32) -> BoxFuture<'_, ()> {
            self.push(Event::Keyframe(self.name.clone()));
            Box::pin(async {})
        }
        fn client_stats(&self, _stats: pb::ClientStats) -> BoxFuture<'_, ()> {
            self.push(Event::Stats(self.name.clone()));
            Box::pin(async {})
        }
        fn release_input(&self) -> BoxFuture<'_, ()> {
            self.push(Event::ReleaseInput(self.name.clone()));
            Box::pin(async {})
        }
        fn cancel_in_flight(&self) -> BoxFuture<'_, ()> {
            self.push(Event::CancelInFlight(self.name.clone()));
            Box::pin(async {})
        }
        fn detach(&self, reason: DetachReason) -> BoxFuture<'_, ()> {
            self.push(Event::Detach(self.name.clone(), reason));
            Box::pin(async {})
        }
    }

    impl DesktopLink for RecordingLink {
        fn attach(
            &self,
            request: AttachRequest,
        ) -> BoxFuture<'_, Result<Arc<dyn LinkClient>, LinkError>> {
            let unavailable = *self.unavailable.lock().unwrap();
            let events = self.events.clone();
            Box::pin(async move {
                if unavailable {
                    return Err(LinkError::Unavailable);
                }
                events
                    .lock()
                    .unwrap()
                    .push(Event::Attach(request.device_name.clone()));
                Ok(Arc::new(Client {
                    name: request.device_name,
                    events,
                }) as Arc<dyn LinkClient>)
            })
        }

        fn state(&self) -> LinkState {
            LinkState::Up
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Default)]
    struct Count {
        calls: AtomicU32,
        detaches: Mutex<Vec<DetachReason>>,
    }
    impl LinkClient for Count {
        fn view_config(&self, _: pb::ViewConfig) -> BoxFuture<'_, ()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {})
        }
        fn request_keyframe(&self, _: u32) -> BoxFuture<'_, ()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {})
        }
        fn client_stats(&self, _: pb::ClientStats) -> BoxFuture<'_, ()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {})
        }
        fn release_input(&self) -> BoxFuture<'_, ()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {})
        }
        fn cancel_in_flight(&self) -> BoxFuture<'_, ()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {})
        }
        fn detach(&self, r: DetachReason) -> BoxFuture<'_, ()> {
            self.detaches.lock().unwrap().push(r);
            Box::pin(async {})
        }
    }

    #[tokio::test]
    async fn a_detached_handle_ignores_everything_and_detaches_once() {
        let inner = std::sync::Arc::new(Count::default());
        let g = GuardedClient::new(inner.clone());
        g.view_config(pb::ViewConfig::default()).await;
        g.release_input().await;
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
        g.detach(DetachReason::Displaced).await;
        g.detach(DetachReason::Left).await;
        g.view_config(pb::ViewConfig::default()).await;
        g.request_keyframe(1).await;
        g.client_stats(pb::ClientStats::default()).await;
        g.release_input().await;
        g.cancel_in_flight().await;
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            2,
            "nothing after detach"
        );
        assert_eq!(*inner.detaches.lock().unwrap(), [DetachReason::Displaced]);
    }
}
