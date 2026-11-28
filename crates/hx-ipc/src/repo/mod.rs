//! The repository link (`docs/ipc.md` Part 3, sections 23 to 36): the wire codec between the
//! backup worker, `hx-privd` and the Drive helper.
//!
//! ```text
//! worker  <-- worker link -->  hx-privd  <-- Drive link -->  Drive helper
//! ```
//!
//! Both links speak the same framing (section 25) with three kinds, and both ends of both links
//! are hostile to the other as far as this crate is concerned: the worker and the Drive helper
//! are low-trust processes, so **every byte they send is untrusted input to privd**, and the
//! worker treats what privd sends as untrusted too, because it validates the job again
//! (section 28). Every limit is checked before anything is allocated; any violation is an error
//! that the caller treats as `WORKER_PROTOCOL` (privd) or as the end of the job (worker): close
//! the link.
//!
//! * [`pb`]: the `hx.repo.v1` messages (`RepoFrame` and everything in it);
//! * [`Endpoint`] and [`RepoFramePolicy`]: which end receives, and the kinds and lengths it
//!   accepts. **Kind 1** (a `RepoFrame`, at most 65 536) is accepted everywhere, **kind 2** (a
//!   secret, at most 8 192) only by the worker, **kind 3** (data, at most 1 048 586) everywhere;
//! * [`decode`], [`encode_message`], [`encode_secret`], [`encode_data_header`]: frames to
//!   [`Incoming`] values and back, validating before anything is returned or sent
//!   ([`validate_frame`]), with the repeated-field pre-scan of `docs/ipc.md` section 8 ahead of
//!   `prost`;
//! * [`LinkState`]: the stateful rules (handshake, request ids, outstanding limits, data
//!   streams, listing, job result), sans I/O;
//! * [`policy`]: the per-job operation table of section 30;
//! * `limits` items re-exported here: every size, count and time limit.
//!
//! # Reading a link
//!
//! ```
//! use hx_ipc::frame::Decoder;
//! use hx_ipc::repo::{self, Endpoint, Incoming, LinkState, RepoFramePolicy, pb};
//!
//! // privd greets the worker; the worker's side of the socket decodes it.
//! let hello = pb::RepoFrame {
//!     frame: Some(pb::repo_frame::Frame::Hello(pb::Hello {
//!         major: repo::VERSION_MAJOR,
//!         minor: repo::VERSION_MINOR,
//!         job_id: vec![7; 16].into(),
//!     })),
//! };
//! let wire = repo::encode_message(&hello, Endpoint::Worker).unwrap();
//!
//! let mut decoder = Decoder::new(RepoFramePolicy::new(Endpoint::Worker));
//! let mut link = LinkState::new(Endpoint::Worker);
//! let mut input = &wire[..]; // for a socket: hx_ipc::recv::NoCmsgReader(&stream)
//! let raw = decoder.read_from(&mut input).unwrap().unwrap();
//! let incoming = repo::decode(raw, Endpoint::Worker).unwrap();
//! link.received(&incoming).unwrap();
//! assert!(matches!(incoming, Incoming::Message(f) if f == hello));
//! ```
//!
//! # Relaying data without copying
//!
//! A kind-3 body is parsed by splitting the decoder's buffer ([`DataFrame::from_body`]), so the
//! payload privd forwards is the very allocation `recvmsg` filled. To forward it, write
//! [`encode_data_header`] (14 bytes) and the payload with one vectored write. privd reads the
//! next chunk of a stream only after it has written the previous one (section 25).
//!
//! # Not here
//!
//! * sockets, timeouts and sleeping (the time limits are constants for the I/O layer);
//! * `SO_PEERCRED` (the worker link's peer is the Incus proxy forwarder, root; the Drive link's
//!   peer is checked by uid on `hx-drive.sock`, section 24);
//! * what privd does with a verdict (kill the helper, audit, back off), the SHA-256 check of
//!   writes, Drive semantics and the lease.

use bytes::BytesMut;
use prost::Message;
use zeroize::Zeroizing;

use crate::error::FrameError;
use crate::frame::{FramePolicy, RawFrame, encode_frame};
use crate::secret::SecretFrame;

mod data;
mod limits;
mod link;
pub mod policy;
mod validate;

pub use data::{DataFrame, encode_data, encode_data_header};
pub use limits::*;
pub use link::{D, Disposition, LinkError, LinkState};
pub use policy::{Verdict, check_job_op, check_op};
pub use validate::{check_result_shape, validate_frame, validate_request, validate_secret};

/// Generated `hx.repo.v1` types.
pub use crate::generated_repo::hx::repo::v1 as pb;

/// The four places a repository-link frame can be received.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endpoint {
    /// The backup worker, on the worker link: receives `Hello`, `Job`, secrets, `RepoResponse`,
    /// `Cancel`, `Ping`, `Pong`, `Bye` and data.
    Worker,
    /// privd, on the worker link: receives `HelloAck`, `RepoRequest` (the worker's operations
    /// only), `Progress`, `JobResult`, `Ping`, `Pong`, `Bye` and data.
    PrivdWorkerLink,
    /// privd, on the Drive link: receives `HelloAck`, `RepoResponse` (including `QuotaResult`),
    /// `Event`, `Ping`, `Pong`, `Bye` and data.
    PrivdDriveLink,
    /// The Drive helper: receives `Hello`, `RepoRequest` (including `OpenRepo`, `Quota` and
    /// `SetUploadRate`), `CancelRequest`, `Ping`, `Pong`, `Bye` and data.
    DriveHelper,
}

impl Endpoint {
    /// All four, for tests and fuzz targets.
    pub const ALL: [Endpoint; 4] = [
        Endpoint::Worker,
        Endpoint::PrivdWorkerLink,
        Endpoint::PrivdDriveLink,
        Endpoint::DriveHelper,
    ];

    /// The other end of the same link.
    pub fn peer(self) -> Endpoint {
        match self {
            Endpoint::Worker => Endpoint::PrivdWorkerLink,
            Endpoint::PrivdWorkerLink => Endpoint::Worker,
            Endpoint::PrivdDriveLink => Endpoint::DriveHelper,
            Endpoint::DriveHelper => Endpoint::PrivdDriveLink,
        }
    }

    /// True for the two ends that are hx-privd.
    pub fn is_privd(self) -> bool {
        matches!(self, Endpoint::PrivdWorkerLink | Endpoint::PrivdDriveLink)
    }

    /// True for the two ends of the worker link.
    pub fn on_worker_link(self) -> bool {
        matches!(self, Endpoint::Worker | Endpoint::PrivdWorkerLink)
    }
}

/// Framing limits of the repository link for the receiving `endpoint` (section 25): kind 1 at
/// most 65 536 everywhere, kind 2 at most 8 192 and only at the worker, kind 3 at most
/// 1 048 586 everywhere.
///
/// Only kind 2 is [sensitive](FramePolicy::is_sensitive) (its partial buffer is zeroized if the
/// decoder is dropped mid-frame). Kind 3 is not: its payload is encrypted repository data, see
/// [`DataFrame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepoFramePolicy {
    endpoint: Endpoint,
}

impl RepoFramePolicy {
    /// The policy for the receiving `endpoint`.
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// The endpoint this policy decodes for.
    pub fn endpoint(&self) -> Endpoint {
        self.endpoint
    }
}

impl FramePolicy for RepoFramePolicy {
    fn absolute_max_length(&self) -> u32 {
        MAX_DATA_LENGTH
    }

    fn max_length(&self, kind: u8) -> Result<u32, FrameError> {
        match kind {
            KIND_MESSAGE => Ok(MAX_MESSAGE_LENGTH),
            KIND_DATA => Ok(MAX_DATA_LENGTH),
            KIND_SECRET if self.endpoint == Endpoint::Worker => Ok(MAX_SECRET_LENGTH),
            KIND_SECRET => Err(FrameError::KindNotAllowed(kind)),
            _ => Err(FrameError::UnknownKind(kind)),
        }
    }

    fn is_sensitive(&self, kind: u8) -> bool {
        kind == KIND_SECRET
    }
}

/// A decoded, validated incoming frame.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // one value per received frame; boxing would only add an allocation
pub enum Incoming {
    /// A kind-1 protobuf frame.
    Message(pb::RepoFrame),
    /// A kind-2 raw secret (worker only).
    Secret(SecretFrame),
    /// A kind-3 data frame.
    Data(DataFrame),
}

/// Decodes and validates one frame received at `endpoint`.
///
/// For a kind-1 frame: the repeated fields are counted on the wire, the protobuf must decode,
/// exactly one variant must be set, the variant must be one that may travel towards `endpoint`,
/// and the contract's field rules must hold ([`validate_frame`]). A kind-2 frame is parsed (the
/// input buffer is zeroized) and checked: only the worker accepts it, `request_id` 0, slot 0 or
/// 1, 16 to 1 024 bytes. A kind-3 frame is split without copying ([`DataFrame::from_body`]).
///
/// The stateful rules are [`LinkState`]'s: pass the result to [`LinkState::received`].
pub fn decode(raw: RawFrame, endpoint: Endpoint) -> Result<Incoming, FrameError> {
    match raw.kind {
        KIND_MESSAGE => {
            if raw.body.len() >= MAX_MESSAGE_LENGTH as usize {
                return Err(FrameError::TooLong {
                    length: u32::try_from(raw.body.len().saturating_add(1)).unwrap_or(u32::MAX),
                    max: MAX_MESSAGE_LENGTH,
                });
            }
            // Refuse a variant that may not travel here before decoding any of it, then bound
            // repeated-field counts before prost allocates an element per occurrence.
            crate::prescan::check_repo_direction(&raw.body, |n| {
                validate::variant_number_travels_to(n, endpoint)
            })?;
            crate::prescan::check_repo_frame(&raw.body)?;
            let frame = pb::RepoFrame::decode(raw.body.as_ref())
                .map_err(|e| FrameError::Decode(e.to_string()))?;
            validate_frame(&frame, endpoint)?;
            Ok(Incoming::Message(frame))
        }
        KIND_SECRET if endpoint == Endpoint::Worker => {
            let frame = SecretFrame::from_body(raw.body)?;
            validate_secret(&frame)?;
            Ok(Incoming::Secret(frame))
        }
        KIND_SECRET => Err(FrameError::KindNotAllowed(KIND_SECRET)),
        KIND_DATA => Ok(Incoming::Data(DataFrame::from_body(raw.body)?)),
        k => Err(FrameError::UnknownKind(k)),
    }
}

/// Encodes a kind-1 frame for the peer at `to`, after checking it would be accepted there.
pub fn encode_message(frame: &pb::RepoFrame, to: Endpoint) -> Result<Vec<u8>, FrameError> {
    validate_frame(frame, to)?;
    let body = frame.encode_to_vec();
    encode_frame(KIND_MESSAGE, &body, MAX_MESSAGE_LENGTH)
}

/// Encodes a kind-2 secret frame (privd to the worker). `request_id` is 0 (the job: v1 has no
/// per-request secrets), `slot` 0 or 1, the secret 16 to 1 024 bytes. The result is zeroized on
/// drop.
///
/// **Write the result to the worker link only after [`LinkState::sent_secret`] returned `Ok` for
/// the same slot**: the tracker is what makes sure the secret is the next one the `Job` declared,
/// that the link is the worker link and that the job exists.
pub fn encode_secret(
    request_id: u64,
    slot: u8,
    secret: &[u8],
) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    if request_id != 0 {
        return Err(FrameError::Invalid("secret.request_id"));
    }
    if usize::from(slot) >= MAX_SECRET_SLOTS {
        return Err(FrameError::Invalid("secret.slot"));
    }
    if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&secret.len()) {
        return Err(FrameError::Invalid("secret.length"));
    }
    let body = SecretFrame::encode_body(request_id, slot, secret);
    let framed = encode_frame(KIND_SECRET, &body, MAX_SECRET_LENGTH)?;
    Ok(Zeroizing::new(framed))
}

/// A kind-1 frame's protobuf body as a [`RawFrame`], for tests and fuzz targets that build one
/// by hand.
pub fn message_raw_frame(frame: &pb::RepoFrame) -> RawFrame {
    RawFrame {
        kind: KIND_MESSAGE,
        body: BytesMut::from(frame.encode_to_vec().as_slice()),
    }
}
