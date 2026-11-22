//! One authorized `INTENT_SETUP` connection (protocol 5.10, "Server state machine").
//!
//! The connection is control-only. It starts `KeyOnly` (admitted on its key, no PIN exists
//! yet: only `set_pin` and `goodbye` work) or `SetupAuthorized` (a PIN was proven, or chosen
//! with `set_pin` on this connection). It never owns the job: when it ends, the job goes on.

use std::time::Duration;

use hx_crypto::DeviceRecord;
use hx_proto::channel::CloseCode;
use hx_proto::message::MgmtDirection;
use hx_proto::pb::{self, control_message::Message as Ctl};
use hx_transport::Connection;
use tokio::sync::broadcast;
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::coordinator::{Event, SetupCoordinator, ack};
use super::{REQUEST_BURST, REQUESTS_PER_SECOND, SEND_TIMEOUT};
use crate::gateway::session::GOODBYE_FLUSH;

/// After `setup finished`, how long the server waits for the client to close first.
const FINISH_GRACE: Duration = Duration::from_millis(400);

enum Exit {
    /// The peer is gone.
    Gone,
    /// Close with this code and reason (after letting the peer read what was sent).
    Close(CloseCode, &'static str),
}

/// A token bucket: [`REQUESTS_PER_SECOND`], burst [`REQUEST_BURST`].
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn new() -> Self {
        Self {
            tokens: REQUEST_BURST,
            at: Instant::now(),
        }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.at).as_secs_f64();
        self.at = now;
        self.tokens = (self.tokens + elapsed * REQUESTS_PER_SECOND).min(REQUEST_BURST);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

async fn send(conn: &Connection, body: pb::setup_message::Body, request_id: u32) -> Result<(), Exit> {
    let m = pb::ControlMessage::new(Ctl::Setup(pb::SetupMessage {
        request_id,
        body: Some(body),
    }));
    match tokio::time::timeout(SEND_TIMEOUT, conn.send_control(&m)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(Exit::Gone),
        // A client that does not read: the write may be half done, so the connection cannot
        // be used any more. The job is not affected.
        Err(_) => Err(Exit::Close(CloseCode::Busy, "not reading")),
    }
}

impl SetupCoordinator {
    /// Serves one authorized setup connection until it ends. `pin_verified` is true when the
    /// device proved the PIN on this connection; false when it was admitted on its key alone
    /// (no PIN exists: it may only set one).
    pub async fn serve(&self, conn: Connection, device: DeviceRecord, pin_verified: bool) {
        // One live setup connection: a newer one replaces the older.
        let (gen_id, old) = {
            let mut st = self.sh.lock();
            st.conn_gen += 1;
            let g = st.conn_gen;
            (g, st.conn.replace((g, conn.clone())))
        };
        if let Some((_, old)) = old {
            tokio::spawn(async move { old.close(CloseCode::NoError, "replaced").await });
        }
        let exit = self.run(&conn, &device, pin_verified).await;
        {
            let mut st = self.sh.lock();
            if st.conn.as_ref().is_some_and(|(g, _)| *g == gen_id) {
                st.conn = None;
            }
        }
        match exit {
            Exit::Gone => {}
            Exit::Close(code, reason) => {
                // A QUIC close discards what the peer has not read yet.
                if code != CloseCode::ProtocolError {
                    // A ping round trip proves the peer's transport has read everything sent
                    // before it (the control stream is ordered); then a short grace lets the
                    // client close first, so the final ack and result are never lost.
                    let _ = conn.ping(GOODBYE_FLUSH).await;
                    if reason == "setup finished" {
                        let _ = tokio::time::timeout(FINISH_GRACE, conn.closed()).await;
                    }
                }
                conn.close(code, reason).await;
            }
        }
    }

    async fn run(&self, conn: &Connection, device: &DeviceRecord, pin_verified: bool) -> Exit {
        // Subscribed before the first state is built, so no event is missed.
        let mut events = self.sh.events.subscribe();
        let mut authorized = pin_verified;
        let mut bucket = Bucket::new();
        let mut last_activity = Instant::now();
        let id = device.id;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let state = self.state_for_new_connection().await;
        if let Err(e) = send(conn, pb::setup_message::Body::State(state), 0).await {
            return e;
        }
        loop {
            tokio::select! {
                biased;
                _ = conn.closed() => return Exit::Gone,
                ev = events.recv() => {
                    let r = match ev {
                        Ok(ev) => self.on_event(conn, &id, &ev).await,
                        // Missed events: the full state is authoritative.
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            let s = self.sh.snapshot();
                            send(conn, pb::setup_message::Body::State(s), 0).await.map(|()| false)
                        }
                        Err(broadcast::error::RecvError::Closed) => return Exit::Gone,
                    };
                    match r {
                        Ok(true) => return Exit::Close(CloseCode::NoError, "setup finished"),
                        Ok(false) => last_activity = Instant::now(),
                        Err(e) => return e,
                    }
                }
                msg = conn.recv_control() => {
                    let m = match msg {
                        Ok(m) => m,
                        Err(_) => return Exit::Gone,
                    };
                    last_activity = Instant::now();
                    if !bucket.take() {
                        return Exit::Close(CloseCode::Busy, "too many requests");
                    }
                    match self.on_message(conn, &id, m, &mut authorized).await {
                        Ok(true) => return Exit::Close(CloseCode::NoError, "setup finished"),
                        Ok(false) => {}
                        Err(e) => return e,
                    }
                }
                _ = tick.tick() => {
                    let running = self.sh.job_running();
                    if !self.sh.is_bound(&id) && !running {
                        return Exit::Close(CloseCode::SetupClosed, "setup is closed");
                    }
                    if !running && last_activity.elapsed() >= self.sh.settings.idle_close {
                        return Exit::Close(CloseCode::NoError, "idle");
                    }
                }
            }
        }
    }

    /// Pushes an event to the client. `Ok(true)` ends the connection (the job finished setup).
    async fn on_event(
        &self,
        conn: &Connection,
        me: &hx_crypto::DeviceId,
        ev: &Event,
    ) -> Result<bool, Exit> {
        use pb::setup_message::Body as B;
        match ev {
            Event::State => {
                send(conn, B::State(self.sh.snapshot()), 0).await?;
                Ok(false)
            }
            Event::Progress(p) => {
                send(conn, B::Progress(p.clone()), 0).await?;
                Ok(false)
            }
            Event::Result(r) => {
                let finished = r.finished;
                send(conn, B::Result(r.clone()), 0).await?;
                if !finished && !self.sh.is_bound(me) {
                    // The window is gone with no setup to report on.
                    return Err(Exit::Close(CloseCode::SetupClosed, "setup is closed"));
                }
                Ok(finished)
            }
            Event::Kick { device, code, reason } => {
                if device.as_ref().is_none_or(|d| d == me) {
                    return Err(Exit::Close(*code, reason));
                }
                Ok(false)
            }
        }
    }

    /// Handles one client message. `Ok(true)` ends the connection (setup finished).
    async fn on_message(
        &self,
        conn: &Connection,
        me: &hx_crypto::DeviceId,
        m: pb::ControlMessage,
        authorized: &mut bool,
    ) -> Result<bool, Exit> {
        use pb::SetupAckStatus as S;
        use pb::setup_message::Body as B;
        let violation = |why: &'static str| Err(Exit::Close(CloseCode::ProtocolError, why));
        let setup = match m.message {
            Some(Ctl::Setup(s)) => s,
            Some(Ctl::Goodbye(_)) => return Err(Exit::Close(CloseCode::NoError, "goodbye")),
            Some(Ctl::Ping(_) | Ctl::Pong(_)) => return Ok(false),
            _ => return violation("unexpected message on a setup connection"),
        };
        if setup.direction() != Some(MgmtDirection::ClientToServer) {
            return violation("a server-only setup body from a client");
        }
        let rid = setup.request_id;
        let Some(body) = setup.body else {
            return violation("setup message without a body");
        };
        let answer = match body {
            B::SetPin(p) => {
                // Copied into zeroizing memory at once; the message is dropped here.
                let pin = Zeroizing::new(p.pin.to_vec());
                drop(p);
                let a = self.set_pin(pin).await;
                if a.status == S::Ok as i32 {
                    *authorized = true;
                }
                a
            }
            // KeyOnly: everything but `set_pin` waits for a PIN.
            B::Start(_) | B::Cancel(_) | B::Finish(_) if !*authorized => ack(S::PinRequired),
            B::Start(s) => self.start(me, s),
            B::Cancel(_) => self.cancel(),
            B::Finish(_) => self.finish().await,
            _ => return violation("unexpected setup body"),
        };
        // `set_pin` after the PIN exists is `PIN_ALREADY_SET` even when authorized, which
        // `SetupCoordinator::set_pin` answers itself.
        let finished_now = answer.status == S::Ok as i32 && self.sh.lock().finished;
        send(conn, B::Ack(answer), rid).await?;
        // The state is pushed by the coordinator's events; a finish ends the connection.
        Ok(finished_now && !self.sh.job_running())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bucket_allows_a_burst_then_two_per_second() {
        let mut b = Bucket::new();
        for _ in 0..8 {
            assert!(b.take());
        }
        assert!(!b.take(), "the burst is spent");
        b.at -= Duration::from_millis(600);
        assert!(b.take(), "one token after 0.6 s");
        assert!(!b.take());
        b.at -= Duration::from_secs(10);
        for _ in 0..8 {
            assert!(b.take());
        }
        assert!(!b.take(), "never more than the burst");
    }
}
