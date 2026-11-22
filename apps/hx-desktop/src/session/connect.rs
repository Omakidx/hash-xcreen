//! The Connect screen as a state machine (design/mockups/connect.html, userflow 5).
//!
//! Two steps, secure connection then PIN. Every attempt that starts counts on the server, so the
//! form is disabled while one runs. The server decides: wrong PIN with the attempts left, a wait
//! (`BACKOFF`, not counted), `REVOKED` after the fifth wrong PIN, `NOT_AVAILABLE`, or a pinned
//! key that does not match (never an override).

use std::time::Duration;

use hx_crypto::Error;
use hx_proto::pb::RefuseReason;

/// What a PIN attempt or a connection attempt came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The PIN was accepted.
    Accepted,
    /// Wrong PIN.
    Wrong {
        /// Attempts left before the device is revoked.
        attempts_left: u32,
        /// Required wait.
        retry_after: Duration,
    },
    /// Too soon after a failure; not counted.
    Backoff {
        /// Remaining wait.
        retry_after: Duration,
    },
    /// This device was removed from the server.
    Revoked,
    /// The server cannot verify a PIN right now; not counted.
    NotAvailable {
        /// Wait before trying again.
        retry_after: Duration,
    },
    /// The server did not answer.
    Unreachable(String),
    /// The server presented another key than the pinned one.
    IdentityChanged,
    /// Anything else, with a sentence.
    Failed(String),
}

/// Maps the client library's error onto the screen outcomes.
pub fn classify_error(e: &Error) -> Outcome {
    match e {
        Error::WrongPin {
            attempts_left,
            retry_after,
        } => Outcome::Wrong {
            attempts_left: *attempts_left,
            retry_after: *retry_after,
        },
        Error::Backoff { retry_after } => Outcome::Backoff {
            retry_after: *retry_after,
        },
        Error::Revoked => Outcome::Revoked,
        Error::PinNotAvailable => Outcome::NotAvailable {
            retry_after: Duration::from_secs(60),
        },
        Error::InvalidKey => Outcome::IdentityChanged,
        Error::Tls(_) => Outcome::IdentityChanged,
        Error::Transport(hx_transport::Error::PeerRejected(_) | hx_transport::Error::Tls(_)) => {
            Outcome::IdentityChanged
        }
        // The server's refusal text is one fixed string for unknown, revoked and no-PIN cases.
        Error::Refused {
            reason: RefuseReason::Unauthorized,
            ..
        } => Outcome::Revoked,
        Error::Refused { message, .. } => Outcome::Failed(sanitize(message)),
        Error::Timeout(_) | Error::Transport(_) | Error::PairingClosed => {
            Outcome::Unreachable(sanitize(&e.to_string()))
        }
        other => Outcome::Failed(sanitize(&other.to_string())),
    }
}

/// Server text is untrusted: strip control and bidirectional characters, cap the length.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(200)
        .collect()
}

/// The state shown by the Connect screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// The PIN form. `notice` is the message above it.
    Entering(Option<Notice>),
    /// Opening the secure connection.
    Connecting,
    /// Connected securely; the server checks the PIN.
    CheckingPin,
    /// Waiting out a backoff; the form is back when it ends.
    Waiting {
        /// Seconds left.
        secs: u64,
        /// Attempts left, if known.
        attempts_left: Option<u32>,
    },
    /// Fifth wrong PIN or removed from the server.
    Revoked,
    /// The pairing form after "Pair again".
    PairAgain,
    /// Server cannot check PINs.
    NotAvailable {
        /// Seconds until Try again is offered.
        secs: u64,
    },
    /// No answer.
    Unreachable(String),
    /// Pinned key mismatch. Blocking.
    IdentityChanged,
    /// The PIN was accepted.
    Connected,
}

/// The message above the PIN form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    /// "Incorrect PIN, N attempts left".
    Wrong {
        /// Attempts left.
        attempts_left: u32,
    },
}

/// Text for the wrong-PIN notice, with the "last attempt" wording of the mockup.
pub fn wrong_pin_text(attempts_left: u32) -> (String, String) {
    if attempts_left == 1 {
        (
            "Incorrect PIN, 1 attempt left".into(),
            "The next wrong PIN removes this device from the server. Pairing it again needs the account password.".into(),
        )
    } else {
        (
            format!("Incorrect PIN, {attempts_left} attempts left"),
            "Five wrong PINs in a row remove this device from the server.".into(),
        )
    }
}

/// Drives the screen.
#[derive(Debug)]
pub struct Machine {
    state: State,
    /// Attempts started in this machine (every one counts on the server).
    pub attempts_started: u32,
}

impl Default for Machine {
    fn default() -> Self {
        Self::new()
    }
}

impl Machine {
    /// A fresh PIN form.
    pub fn new() -> Self {
        Self {
            state: State::Entering(None),
            attempts_started: 0,
        }
    }

    /// Current state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// True when Connect may be pressed.
    pub fn can_submit(&self) -> bool {
        matches!(self.state, State::Entering(_))
    }

    /// The user pressed Connect (or Enter). Returns false if an attempt is already running.
    pub fn submit(&mut self) -> bool {
        if !self.can_submit() {
            return false;
        }
        self.attempts_started += 1;
        self.state = State::Connecting;
        true
    }

    /// The secure connection is up.
    pub fn secure(&mut self) {
        if self.state == State::Connecting {
            self.state = State::CheckingPin;
        }
    }

    /// An outcome arrived (from either step).
    pub fn outcome(&mut self, o: Outcome) {
        self.state = match o {
            Outcome::Accepted => State::Connected,
            Outcome::Wrong {
                attempts_left,
                retry_after,
            } => {
                if retry_after.is_zero() {
                    State::Entering(Some(Notice::Wrong { attempts_left }))
                } else {
                    State::Waiting {
                        secs: ceil_secs(retry_after),
                        attempts_left: Some(attempts_left),
                    }
                }
            }
            Outcome::Backoff { retry_after } => State::Waiting {
                secs: ceil_secs(retry_after),
                attempts_left: None,
            },
            Outcome::Revoked => State::Revoked,
            Outcome::NotAvailable { retry_after } => State::NotAvailable {
                secs: ceil_secs(retry_after),
            },
            Outcome::Unreachable(m) => State::Unreachable(m),
            Outcome::IdentityChanged => State::IdentityChanged,
            Outcome::Failed(m) => State::Unreachable(m),
        };
    }

    /// One second passed. Returns true when a countdown ended and the form is back.
    pub fn tick_second(&mut self) -> bool {
        match &mut self.state {
            State::Waiting {
                secs,
                attempts_left,
            } => {
                *secs = secs.saturating_sub(1);
                if *secs == 0 {
                    let left = *attempts_left;
                    self.state =
                        State::Entering(left.map(|attempts_left| Notice::Wrong { attempts_left }));
                    true
                } else {
                    false
                }
            }
            State::NotAvailable { secs } => {
                *secs = secs.saturating_sub(1);
                false
            }
            _ => false,
        }
    }

    /// "Try again" after NotAvailable or Unreachable.
    pub fn retry(&mut self) -> bool {
        match self.state {
            State::NotAvailable { secs: 0 } | State::Unreachable(_) => {
                self.state = State::Entering(None);
                true
            }
            _ => false,
        }
    }

    /// "Pair again" on the revoked screen.
    pub fn pair_again(&mut self) -> bool {
        if self.state == State::Revoked {
            self.state = State::PairAgain;
            true
        } else {
            false
        }
    }

    /// The user cancelled: back to a fresh form (the caller leaves the screen).
    pub fn cancel(&mut self) {
        self.state = State::Entering(None);
    }
}

fn ceil_secs(d: Duration) -> u64 {
    d.as_millis().div_ceil(1000).max(1) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(m: &mut Machine, o: Outcome) {
        assert!(m.submit());
        m.secure();
        assert_eq!(*m.state(), State::CheckingPin);
        m.outcome(o);
    }

    #[test]
    fn a_second_attempt_cannot_start_while_one_runs() {
        let mut m = Machine::new();
        assert!(m.submit());
        assert!(!m.submit());
        m.secure();
        assert!(!m.submit());
        assert_eq!(m.attempts_started, 1);
    }

    #[test]
    fn wrong_pin_returns_to_the_form_with_the_count_from_the_server() {
        let mut m = Machine::new();
        run(
            &mut m,
            Outcome::Wrong {
                attempts_left: 4,
                retry_after: Duration::ZERO,
            },
        );
        assert_eq!(
            *m.state(),
            State::Entering(Some(Notice::Wrong { attempts_left: 4 }))
        );
        assert_eq!(wrong_pin_text(4).0, "Incorrect PIN, 4 attempts left");
        assert!(wrong_pin_text(1).0.ends_with("1 attempt left"));
        assert!(wrong_pin_text(1).1.contains("account password"));
    }

    #[test]
    fn wrong_pin_with_a_wait_counts_down_then_reenables_the_form() {
        let mut m = Machine::new();
        run(
            &mut m,
            Outcome::Wrong {
                attempts_left: 2,
                retry_after: Duration::from_millis(2500),
            },
        );
        assert_eq!(
            *m.state(),
            State::Waiting {
                secs: 3,
                attempts_left: Some(2)
            }
        );
        assert!(!m.can_submit());
        assert!(!m.tick_second());
        assert!(!m.tick_second());
        assert!(m.tick_second());
        assert_eq!(
            *m.state(),
            State::Entering(Some(Notice::Wrong { attempts_left: 2 }))
        );
        assert!(m.can_submit());
    }

    #[test]
    fn backoff_is_not_an_attempt_and_waits() {
        let mut m = Machine::new();
        run(
            &mut m,
            Outcome::Backoff {
                retry_after: Duration::from_secs(8),
            },
        );
        assert_eq!(
            *m.state(),
            State::Waiting {
                secs: 8,
                attempts_left: None
            }
        );
        for _ in 0..7 {
            assert!(!m.tick_second());
        }
        assert!(m.tick_second());
        assert_eq!(*m.state(), State::Entering(None));
    }

    #[test]
    fn revoked_is_final_until_pair_again() {
        let mut m = Machine::new();
        run(&mut m, Outcome::Revoked);
        assert_eq!(*m.state(), State::Revoked);
        assert!(!m.can_submit(), "the PIN cannot be tried again");
        assert!(!m.retry());
        assert!(m.pair_again());
        assert_eq!(*m.state(), State::PairAgain);
    }

    #[test]
    fn not_available_offers_try_again_only_after_the_wait() {
        let mut m = Machine::new();
        run(
            &mut m,
            Outcome::NotAvailable {
                retry_after: Duration::from_secs(2),
            },
        );
        assert!(!m.retry());
        m.tick_second();
        m.tick_second();
        assert!(m.retry());
        assert_eq!(*m.state(), State::Entering(None));
    }

    #[test]
    fn unreachable_and_identity_changed() {
        let mut m = Machine::new();
        assert!(m.submit());
        m.outcome(Outcome::Unreachable("no answer".into()));
        assert!(m.retry());
        assert!(m.submit());
        m.outcome(Outcome::IdentityChanged);
        assert_eq!(*m.state(), State::IdentityChanged);
        assert!(!m.retry(), "no override");
        assert!(!m.can_submit());
    }

    #[test]
    fn accepted_connects() {
        let mut m = Machine::new();
        run(&mut m, Outcome::Accepted);
        assert_eq!(*m.state(), State::Connected);
    }

    #[test]
    fn library_errors_map_to_outcomes() {
        assert_eq!(
            classify_error(&Error::WrongPin {
                attempts_left: 3,
                retry_after: Duration::from_secs(1)
            }),
            Outcome::Wrong {
                attempts_left: 3,
                retry_after: Duration::from_secs(1)
            }
        );
        assert_eq!(classify_error(&Error::Revoked), Outcome::Revoked);
        assert!(matches!(
            classify_error(&Error::PinNotAvailable),
            Outcome::NotAvailable { .. }
        ));
        assert_eq!(classify_error(&Error::InvalidKey), Outcome::IdentityChanged);
        assert_eq!(
            classify_error(&Error::Transport(hx_transport::Error::PeerRejected(
                "x".into()
            ))),
            Outcome::IdentityChanged
        );
        assert!(matches!(
            classify_error(&Error::Refused {
                reason: RefuseReason::Unauthorized,
                message: "not authorized".into()
            }),
            Outcome::Revoked
        ));
        assert!(matches!(
            classify_error(&Error::Timeout("x")),
            Outcome::Unreachable(_)
        ));
    }

    #[test]
    fn server_text_is_sanitised() {
        assert_eq!(sanitize("a\u{202e}b\nc"), "abc");
        assert_eq!(sanitize(&"x".repeat(500)).len(), 200);
    }
}
