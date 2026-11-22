//! What to do when a session ends: reconnect, give up, or stop and tell the user.
//!
//! * `TAKEN_OVER` never reconnects (it would displace the other device in turn): the takeover
//!   notice offers "Revoke that device" and "Take it back" (protocol 5.7).
//! * A network drop shows the Reconnecting overlay, retries with a growing wait and gives up
//!   after two minutes ("Cannot reconnect", Try again, Back to Home).
//! * `UNAUTHORIZED` means the device was removed: the Connect screen's revoked state.

use std::time::Duration;

use hx_proto::channel::CloseCode;
use hx_proto::pb::Goodbye;
use hx_transport::CloseInfo;

/// How long the app keeps trying before it offers to stop.
pub const GIVE_UP_AFTER: Duration = Duration::from_secs(120);

/// Why a session ended, as far as the user needs to know.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// The connection dropped: reconnect.
    Network,
    /// Another device took over.
    TakenOver {
        /// The other device's sanitised name (may be empty).
        name: String,
        /// First 8 hex digits of its id (empty if the server did not say).
        id_short: String,
        /// Its full id (16 bytes), for "Revoke that device".
        id: Option<[u8; 16]>,
    },
    /// This device was removed from the server.
    Revoked,
    /// The server is stopping or restarting: reconnect like a network drop.
    Shutdown,
    /// The server cannot take the session; the desktop is not available.
    DesktopUnavailable,
    /// This side closed it.
    Local,
}

/// Classifies a close, using the `Goodbye` that came before it if there was one.
pub fn classify_close(info: Option<&CloseInfo>, goodbye: Option<&Goodbye>) -> CloseReason {
    let code = match (goodbye, info) {
        (Some(g), _) => CloseCode::from_code(u64::from(g.code)),
        (None, Some(i)) => i.code,
        (None, None) => return CloseReason::Network,
    };
    if info.is_some_and(|i| !i.by_peer) && code == CloseCode::NoError {
        return CloseReason::Local;
    }
    match code {
        CloseCode::TakenOver => {
            let (name, id_short, id) = match goodbye {
                Some(g) => takeover_peer(g),
                None => (String::new(), String::new(), None),
            };
            CloseReason::TakenOver { name, id_short, id }
        }
        CloseCode::Unauthorized => CloseReason::Revoked,
        CloseCode::Shutdown => CloseReason::Shutdown,
        CloseCode::Busy | CloseCode::InternalError => CloseReason::DesktopUnavailable,
        CloseCode::NoError => CloseReason::Local,
        _ => CloseReason::Network,
    }
}

/// The takeover peer from a `Goodbye`, validated: a name longer than 64 bytes or with control or
/// bidirectional characters is dropped, a bad id length is dropped (protocol 5.7).
pub fn takeover_peer(g: &Goodbye) -> (String, String, Option<[u8; 16]>) {
    let name = if g.peer_device_name.len() <= hx_proto::channel::MAX_DEVICE_NAME
        && hx_proto::message::device_name_problem(&g.peer_device_name).is_none()
    {
        g.peer_device_name.clone()
    } else {
        String::new()
    };
    let id: Option<[u8; 16]> = <[u8; 16]>::try_from(&g.peer_device_id[..]).ok();
    let short = id
        .map(|i| i.iter().take(4).map(|b| format!("{b:02x}")).collect::<String>())
        .unwrap_or_default();
    (name, short, id)
}

/// What to do next after a drop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Next {
    /// Try again after `wait`; this is attempt number `attempt` (1-based).
    Retry {
        /// Attempt number.
        attempt: u32,
        /// Wait before it.
        wait: Duration,
    },
    /// Stop trying: offer Try again and Back to Home.
    GiveUp,
}

/// The reconnect schedule. Time is passed in, so tests need no clock.
#[derive(Debug, Default)]
pub struct Reconnect {
    attempts: u32,
    waited: Duration,
}

impl Reconnect {
    /// A new outage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Wait before attempt `n` (1-based): 1, 2, 4, 8, then 10 seconds.
    pub fn wait_for(n: u32) -> Duration {
        Duration::from_secs([1, 2, 4, 8, 10][(n.saturating_sub(1) as usize).min(4)])
    }

    /// The next step. `elapsed` is the time since the outage began.
    pub fn next(&mut self, elapsed: Duration) -> Next {
        if elapsed >= GIVE_UP_AFTER {
            return Next::GiveUp;
        }
        self.attempts += 1;
        let wait = Self::wait_for(self.attempts).min(GIVE_UP_AFTER - elapsed);
        self.waited += wait;
        Next::Retry {
            attempt: self.attempts,
            wait,
        }
    }

    /// Attempts started so far.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }
}

/// Whether a reason is followed by an automatic reconnect.
pub fn reconnects(r: &CloseReason) -> bool {
    matches!(r, CloseReason::Network | CloseReason::Shutdown)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(code: CloseCode, by_peer: bool) -> CloseInfo {
        CloseInfo {
            code,
            reason: String::new(),
            by_peer,
        }
    }

    #[test]
    fn takeover_never_reconnects_and_carries_the_peer() {
        let g = Goodbye {
            code: CloseCode::TakenOver.code(),
            message: "x".into(),
            peer_device_name: "Maya's laptop".into(),
            peer_device_id: bytes::Bytes::from(vec![0xab; 16]),
        };
        let r = classify_close(Some(&info(CloseCode::TakenOver, true)), Some(&g));
        match &r {
            CloseReason::TakenOver { name, id_short, id } => {
                assert_eq!(name, "Maya's laptop");
                assert_eq!(id_short, "abababab");
                assert_eq!(*id, Some([0xab; 16]));
            }
            other => panic!("{other:?}"),
        }
        assert!(!reconnects(&r));
    }

    #[test]
    fn takeover_without_goodbye_is_still_a_takeover() {
        let r = classify_close(Some(&info(CloseCode::TakenOver, true)), None);
        assert!(matches!(r, CloseReason::TakenOver { ref name, id: None, .. } if name.is_empty()));
    }

    #[test]
    fn a_bad_peer_name_or_id_is_dropped_not_shown() {
        let g = Goodbye {
            code: CloseCode::TakenOver.code(),
            message: String::new(),
            peer_device_name: "evil\u{202e}name".into(),
            peer_device_id: bytes::Bytes::from(vec![1; 5]),
        };
        let (n, s, i) = takeover_peer(&g);
        assert!(n.is_empty() && s.is_empty() && i.is_none());
        let g = Goodbye {
            peer_device_name: "x".repeat(65),
            ..Default::default()
        };
        assert!(takeover_peer(&g).0.is_empty());
    }

    #[test]
    fn close_codes_map_to_reasons() {
        let c = |code, peer| classify_close(Some(&info(code, peer)), None);
        assert_eq!(c(CloseCode::Unauthorized, true), CloseReason::Revoked);
        assert_eq!(c(CloseCode::Shutdown, true), CloseReason::Shutdown);
        assert_eq!(c(CloseCode::Busy, true), CloseReason::DesktopUnavailable);
        assert_eq!(c(CloseCode::NoError, false), CloseReason::Local);
        assert_eq!(c(CloseCode::ProtocolError, true), CloseReason::Network);
        assert_eq!(classify_close(None, None), CloseReason::Network);
        assert!(reconnects(&CloseReason::Network));
        assert!(!reconnects(&CloseReason::Revoked));
    }

    #[test]
    fn schedule_grows_then_gives_up_after_two_minutes() {
        let mut r = Reconnect::new();
        let waits: Vec<u64> = (0..6)
            .map(|_| match r.next(Duration::ZERO) {
                Next::Retry { wait, .. } => wait.as_secs(),
                Next::GiveUp => panic!(),
            })
            .collect();
        assert_eq!(waits, vec![1, 2, 4, 8, 10, 10]);
        assert_eq!(r.next(Duration::from_secs(119)), Next::Retry { attempt: 7, wait: Duration::from_secs(1) });
        assert_eq!(r.next(Duration::from_secs(120)), Next::GiveUp);
        assert_eq!(r.next(Duration::from_secs(500)), Next::GiveUp);
    }
}
