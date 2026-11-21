//! Lane preamble and version negotiation (`docs/ipc.md` section 12.2).
//!
//! ```text
//!  0       4        5        6      7
//! +--------+--------+--------+------+------+----------------+
//! | "HXLK" | major  | minor  | lane | 0x00 | link_id (16 B) |   gateway -> session
//! +--------+--------+--------+------+------+----------------+
//! ```
//!
//! The session answers with the first 8 bytes only, `minor` lowered to its own if that is lower.
//! Same major, different minor is accepted and the negotiated minor is the lower one; a
//! different major is refused by closing the connection (the gateway then records
//! `session_outdated` and asks privd for `InstallSession`).

use std::io::Read;

use thiserror::Error;

use super::{LINK_MAJOR, LINK_MINOR, Lane};
use crate::error::ReadError;

/// The four magic bytes.
pub const MAGIC: [u8; 4] = *b"HXLK";
/// Bytes of the version and lane part, the whole answer.
pub const PREAMBLE_LEN: usize = 8;
/// Bytes of the random `link_id`.
pub const LINK_ID_LEN: usize = 16;
/// Bytes the gateway sends on connect: preamble plus `link_id`.
pub const CLIENT_PREAMBLE_LEN: usize = PREAMBLE_LEN + LINK_ID_LEN;

/// Preamble and `info` must complete within this long of connect, else the gateway closes.
pub const PREAMBLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// The session drops a link whose extra lanes do not arrive within this long of `ctl`.
pub const EXTRA_LANES_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Why a preamble was refused. Every variant closes the connection and is a violation on the
/// gateway (`docs/ipc.md` section 19.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PreambleError {
    /// The first four bytes are not `HXLK`.
    #[error("bad preamble magic")]
    BadMagic,
    /// The lane id is outside 1 to 3.
    #[error("bad lane id {0}")]
    BadLane(u8),
    /// The reserved byte is not zero.
    #[error("reserved preamble byte is not zero")]
    ReservedNotZero,
    /// A different major version: the gateway marks the session outdated.
    #[error("link major version mismatch: ours {ours}, theirs {theirs}")]
    MajorMismatch {
        /// Our major.
        ours: u8,
        /// The peer's major.
        theirs: u8,
    },
    /// The answer does not match what was sent (lane changed, or a higher minor than offered).
    #[error("preamble answer does not match the offer")]
    AnswerMismatch,
}

/// Failure of a blocking preamble read.
#[derive(Debug, Error)]
pub enum PreambleReadError {
    /// The bytes were read but are not acceptable.
    #[error(transparent)]
    Preamble(#[from] PreambleError),
    /// The transport failed, ended early, or delivered a control message.
    #[error(transparent)]
    Read(#[from] ReadError),
}

/// The 8-byte version and lane part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preamble {
    /// Major version.
    pub major: u8,
    /// Minor version.
    pub minor: u8,
    /// The lane this connection is.
    pub lane: Lane,
}

impl Preamble {
    /// Our own preamble for `lane` (version `LINK_MAJOR.LINK_MINOR`).
    pub fn ours(lane: Lane) -> Self {
        Self {
            major: LINK_MAJOR,
            minor: LINK_MINOR,
            lane,
        }
    }

    /// The 8 wire bytes.
    pub fn encode(&self) -> [u8; PREAMBLE_LEN] {
        let mut b = [0; PREAMBLE_LEN];
        b[..4].copy_from_slice(&MAGIC);
        b[4] = self.major;
        b[5] = self.minor;
        b[6] = self.lane.id();
        b
    }

    /// Parses the 8 bytes: magic, lane in 1 to 3, reserved byte zero. The version is not judged
    /// here; use [`Preamble::answer`] or [`Preamble::check_answer`].
    pub fn decode(b: &[u8; PREAMBLE_LEN]) -> Result<Self, PreambleError> {
        if b[..4] != MAGIC {
            return Err(PreambleError::BadMagic);
        }
        let lane = Lane::from_id(b[6]).ok_or(PreambleError::BadLane(b[6]))?;
        if b[7] != 0 {
            return Err(PreambleError::ReservedNotZero);
        }
        Ok(Self {
            major: b[4],
            minor: b[5],
            lane,
        })
    }

    /// The session's answer to the gateway's offer `self`: same lane, `minor` lowered to
    /// `local_minor` if that is lower. A different major is [`PreambleError::MajorMismatch`]
    /// and the connection must be closed without an answer.
    pub fn answer(&self, local_major: u8, local_minor: u8) -> Result<Self, PreambleError> {
        if self.major != local_major {
            return Err(PreambleError::MajorMismatch {
                ours: local_major,
                theirs: self.major,
            });
        }
        Ok(Self {
            major: local_major,
            minor: self.minor.min(local_minor),
            lane: self.lane,
        })
    }

    /// The gateway's check of the session's `answer` to the offer `self`. Returns the negotiated
    /// minor.
    pub fn check_answer(&self, answer: &Preamble) -> Result<u8, PreambleError> {
        if answer.major != self.major {
            return Err(PreambleError::MajorMismatch {
                ours: self.major,
                theirs: answer.major,
            });
        }
        if answer.lane != self.lane || answer.minor > self.minor {
            return Err(PreambleError::AnswerMismatch);
        }
        Ok(answer.minor)
    }
}

/// What the gateway sends on every lane: the preamble and the link id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientPreamble {
    /// Version and lane.
    pub preamble: Preamble,
    /// Random per link, identical on the three lanes.
    pub link_id: [u8; LINK_ID_LEN],
}

impl ClientPreamble {
    /// The 24 wire bytes.
    pub fn encode(&self) -> [u8; CLIENT_PREAMBLE_LEN] {
        let mut b = [0; CLIENT_PREAMBLE_LEN];
        b[..PREAMBLE_LEN].copy_from_slice(&self.preamble.encode());
        b[PREAMBLE_LEN..].copy_from_slice(&self.link_id);
        b
    }

    /// Parses the 24 bytes.
    pub fn decode(b: &[u8; CLIENT_PREAMBLE_LEN]) -> Result<Self, PreambleError> {
        let mut head = [0; PREAMBLE_LEN];
        head.copy_from_slice(&b[..PREAMBLE_LEN]);
        let mut link_id = [0; LINK_ID_LEN];
        link_id.copy_from_slice(&b[PREAMBLE_LEN..]);
        Ok(Self {
            preamble: Preamble::decode(&head)?,
            link_id,
        })
    }
}

/// Reads and parses the gateway's 24-byte preamble (session side). Pass a
/// [`crate::recv::NoCmsgReader`] for a socket.
pub fn read_client_preamble<R: Read>(r: &mut R) -> Result<ClientPreamble, PreambleReadError> {
    let mut b = [0; CLIENT_PREAMBLE_LEN];
    r.read_exact(&mut b).map_err(ReadError::from)?;
    Ok(ClientPreamble::decode(&b)?)
}

/// Reads and parses the session's 8-byte answer (gateway side).
pub fn read_answer<R: Read>(r: &mut R) -> Result<Preamble, PreambleReadError> {
    let mut b = [0; PREAMBLE_LEN];
    r.read_exact(&mut b).map_err(ReadError::from)?;
    Ok(Preamble::decode(&b)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_answer() {
        let c = ClientPreamble {
            preamble: Preamble::ours(Lane::Media),
            link_id: [7; 16],
        };
        let bytes = c.encode();
        assert_eq!(&bytes[..4], b"HXLK");
        assert_eq!(bytes[6], 2);
        assert_eq!(ClientPreamble::decode(&bytes).unwrap(), c);
        let a = c.preamble.answer(1, 0).unwrap();
        assert_eq!(c.preamble.check_answer(&a), Ok(0));
    }

    #[test]
    fn minor_is_lowered_and_major_refused() {
        let offer = Preamble {
            major: 1,
            minor: 5,
            lane: Lane::Ctl,
        };
        assert_eq!(offer.answer(1, 2).unwrap().minor, 2);
        assert_eq!(offer.answer(1, 9).unwrap().minor, 5);
        assert_eq!(
            offer.answer(2, 0),
            Err(PreambleError::MajorMismatch { ours: 2, theirs: 1 })
        );
        // A session that answers with a higher minor than offered, or another lane, is refused.
        let bad_minor = Preamble { minor: 6, ..offer };
        assert_eq!(
            offer.check_answer(&bad_minor),
            Err(PreambleError::AnswerMismatch)
        );
        let bad_lane = Preamble {
            lane: Lane::Bulk,
            ..offer
        };
        assert_eq!(
            offer.check_answer(&bad_lane),
            Err(PreambleError::AnswerMismatch)
        );
        let bad_major = Preamble { major: 2, ..offer };
        assert!(matches!(
            offer.check_answer(&bad_major),
            Err(PreambleError::MajorMismatch { .. })
        ));
    }

    #[test]
    fn malformed_preambles() {
        let good = Preamble::ours(Lane::Ctl).encode();
        let mut b = good;
        b[0] = b'X';
        assert_eq!(Preamble::decode(&b), Err(PreambleError::BadMagic));
        for lane in [0u8, 4, 255] {
            let mut b = good;
            b[6] = lane;
            assert_eq!(Preamble::decode(&b), Err(PreambleError::BadLane(lane)));
        }
        let mut b = good;
        b[7] = 1;
        assert_eq!(Preamble::decode(&b), Err(PreambleError::ReservedNotZero));
    }

    #[test]
    fn truncated_read_is_an_io_error_not_a_panic() {
        let bytes = ClientPreamble {
            preamble: Preamble::ours(Lane::Ctl),
            link_id: [1; 16],
        }
        .encode();
        let mut short = &bytes[..10];
        assert!(matches!(
            read_client_preamble(&mut short),
            Err(PreambleReadError::Read(ReadError::Io(_)))
        ));
        let mut full = &bytes[..];
        assert!(read_client_preamble(&mut full).is_ok());
    }
}
