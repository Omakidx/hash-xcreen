//! The shared frame shape of `docs/ipc.md` section 4 and section 13:
//!
//! ```text
//! +----------------+---------+------------------------+
//! | length (u32 LE)| kind u8 | body (length - 1 bytes)|
//! +----------------+---------+------------------------+
//! ```
//!
//! `length` counts the kind byte and the body. One [`Decoder`] serves privd, the admin socket and
//! every link lane; a [`FramePolicy`] says which kinds are valid and how long each may be.
//!
//! **Every limit is checked before anything is allocated.** The decoder checks `length` against
//! the policy's absolute maximum as soon as the four prefix bytes are in, checks the kind byte
//! and the per-kind maximum as soon as the fifth byte is in, and only then allocates the body
//! (zero-initialised, so the allocation costs address space but no memory until bytes arrive;
//! under `mlockall(MCL_FUTURE)`, which privd and gatewayd use, the pages are locked and resident
//! as soon as the allocation is made, so a large frame costs its full size at once).

use std::io::{self, Read};

use bytes::BytesMut;
use zeroize::Zeroize;

use crate::error::{FrameError, ReadError};

/// Bytes of the length prefix.
pub const LENGTH_PREFIX_LEN: usize = 4;
/// Bytes before the body: length prefix plus kind byte.
pub const PREFIX_LEN: usize = LENGTH_PREFIX_LEN + 1;

/// What a receiver accepts on one stream in one direction.
pub trait FramePolicy {
    /// The largest `length` any kind may have here. `0` means the stream must stay silent: any
    /// received byte is [`FrameError::ForbiddenDirection`].
    fn absolute_max_length(&self) -> u32;

    /// The largest `length` for `kind`, or an error if the kind is unknown
    /// ([`FrameError::UnknownKind`]) or not valid on this stream
    /// ([`FrameError::KindNotAllowed`]).
    fn max_length(&self, kind: u8) -> Result<u32, FrameError>;

    /// True if frames of this kind carry secrets: their partial buffers are zeroized when the
    /// decoder is dropped mid-frame.
    fn is_sensitive(&self, _kind: u8) -> bool {
        false
    }
}

/// One complete frame as received. The body has not been interpreted.
#[derive(PartialEq, Eq)]
pub struct RawFrame {
    /// The kind byte.
    pub kind: u8,
    /// The body, `length - 1` bytes. Call `freeze()` for a zero-copy `Bytes`.
    pub body: BytesMut,
}

/// Shows the kind and the length only: a kind-2 body is a secret, and no body byte of any kind
/// belongs in a log line.
impl std::fmt::Debug for RawFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawFrame")
            .field("kind", &self.kind)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
enum Stage {
    Prefix,
    Body,
}

/// Incremental, allocation-bounded frame decoder (sans I/O, plus [`Decoder::read_from`] for
/// blocking readers).
///
/// After any error the decoder is poisoned: the connection must be closed.
pub struct Decoder<P: FramePolicy> {
    policy: P,
    stage: Stage,
    head: [u8; PREFIX_LEN],
    have: usize,
    kind: u8,
    sensitive: bool,
    body: BytesMut,
    filled: usize,
    poisoned: bool,
}

/// Shows the state and counters only, never buffered bytes (they may be a secret).
impl<P: FramePolicy> std::fmt::Debug for Decoder<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoder")
            .field("stage", &self.stage)
            .field("kind", &self.kind)
            .field("filled", &self.filled)
            .field("body_len", &self.body.len())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl<P: FramePolicy> Decoder<P> {
    /// A decoder at a frame boundary.
    pub fn new(policy: P) -> Self {
        Self {
            policy,
            stage: Stage::Prefix,
            head: [0; PREFIX_LEN],
            have: 0,
            kind: 0,
            sensitive: false,
            body: BytesMut::new(),
            filled: 0,
            poisoned: false,
        }
    }

    /// The policy in force.
    pub fn policy(&self) -> &P {
        &self.policy
    }

    /// True between frames: nothing of the next frame has arrived.
    pub fn at_boundary(&self) -> bool {
        matches!(self.stage, Stage::Prefix) && self.have == 0
    }

    /// How many more bytes are needed to finish the current unit (the rest of the prefix, or the
    /// rest of the body). A reader that reads exactly this much never over-reads into the next
    /// frame.
    pub fn wants(&self) -> usize {
        match self.stage {
            Stage::Prefix => PREFIX_LEN - self.have,
            Stage::Body => self.body.len() - self.filled,
        }
    }

    /// Call when the stream ended: `Ok` at a frame boundary, [`FrameError::Truncated`] inside a
    /// frame.
    pub fn finish(&self) -> Result<(), FrameError> {
        if self.at_boundary() {
            Ok(())
        } else {
            Err(FrameError::Truncated)
        }
    }

    /// Feed bytes. Returns how many were consumed and the frame if one completed; it never
    /// consumes beyond the end of the current frame, so call it again with the remainder.
    ///
    /// Errors poison the decoder.
    pub fn feed(&mut self, data: &[u8]) -> Result<(usize, Option<RawFrame>), FrameError> {
        self.guard()?;
        if data.is_empty() {
            return Ok((0, None));
        }
        let mut used = 0;
        loop {
            match self.stage {
                Stage::Prefix => {
                    let take = (PREFIX_LEN - self.have).min(data.len() - used);
                    self.head[self.have..self.have + take]
                        .copy_from_slice(&data[used..used + take]);
                    used += take;
                    if let Some(frame) = self.commit_prefix(take)? {
                        return Ok((used, Some(frame)));
                    }
                }
                Stage::Body => {
                    let take = (self.body.len() - self.filled).min(data.len() - used);
                    self.body[self.filled..self.filled + take]
                        .copy_from_slice(&data[used..used + take]);
                    used += take;
                    if let Some(frame) = self.commit_body(take) {
                        return Ok((used, Some(frame)));
                    }
                }
            }
            if used == data.len() {
                return Ok((used, None));
            }
        }
    }

    /// Read until one frame completes. `Ok(None)` is a clean end of stream at a frame boundary;
    /// an end inside a frame is [`FrameError::Truncated`].
    ///
    /// Reads exactly what the current frame still needs and straight into the frame's own
    /// buffer. For a socket pass a [`crate::recv::NoCmsgReader`] so control messages are refused.
    pub fn read_from<R: Read>(&mut self, r: &mut R) -> Result<Option<RawFrame>, ReadError> {
        self.guard()?;
        loop {
            let read = match self.stage {
                Stage::Prefix => r.read(&mut self.head[self.have..PREFIX_LEN]),
                Stage::Body => r.read(&mut self.body[self.filled..]),
            };
            let n = match read {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    let e = ReadError::from(e);
                    if matches!(e, ReadError::Ancillary(_)) {
                        // A descriptor or control message is a violation: never reuse the stream.
                        self.poisoned = true;
                        self.zeroize_partial();
                    }
                    return Err(e);
                }
            };
            if n == 0 {
                return match self.finish() {
                    Ok(()) => Ok(None),
                    Err(e) => Err(self.poison(e).into()),
                };
            }
            let done = match self.stage {
                Stage::Prefix => self.commit_prefix(n)?,
                Stage::Body => self.commit_body(n),
            };
            if let Some(frame) = done {
                return Ok(Some(frame));
            }
        }
    }

    fn guard(&self) -> Result<(), FrameError> {
        if self.poisoned {
            Err(FrameError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn poison(&mut self, e: FrameError) -> FrameError {
        self.poisoned = true;
        self.zeroize_partial();
        e
    }

    /// `n` more prefix bytes are in `head`.
    fn commit_prefix(&mut self, n: usize) -> Result<Option<RawFrame>, FrameError> {
        // A silent direction accepts nothing: the first byte that arrives is the violation.
        if self.policy.absolute_max_length() == 0 {
            return Err(self.poison(FrameError::ForbiddenDirection));
        }
        let before = self.have;
        self.have += n;
        // The length is complete once four bytes are in: check it before waiting for the kind.
        if before < LENGTH_PREFIX_LEN && self.have >= LENGTH_PREFIX_LEN {
            let length =
                u32::from_le_bytes([self.head[0], self.head[1], self.head[2], self.head[3]]);
            if length == 0 {
                return Err(self.poison(FrameError::ZeroLength));
            }
            let abs = self.policy.absolute_max_length();
            if length > abs {
                return Err(self.poison(FrameError::TooLong { length, max: abs }));
            }
        }
        if self.have < PREFIX_LEN {
            return Ok(None);
        }
        let length = u32::from_le_bytes([self.head[0], self.head[1], self.head[2], self.head[3]]);
        let kind = self.head[LENGTH_PREFIX_LEN];
        let max = match self.policy.max_length(kind) {
            Ok(m) => m,
            Err(e) => return Err(self.poison(e)),
        };
        if length > max {
            return Err(self.poison(FrameError::TooLong { length, max }));
        }
        self.kind = kind;
        self.sensitive = self.policy.is_sensitive(kind);
        self.have = 0;
        let body_len = (length - 1) as usize;
        if body_len == 0 {
            return Ok(Some(RawFrame {
                kind,
                body: BytesMut::new(),
            }));
        }
        // Allocation happens only here, after both limit checks. (Under `mlockall(MCL_FUTURE)`
        // the zeroed buffer is locked, resident memory immediately, not on first touch.)
        self.body = BytesMut::zeroed(body_len);
        self.filled = 0;
        self.stage = Stage::Body;
        Ok(None)
    }

    /// `n` more body bytes are in `body`.
    fn commit_body(&mut self, n: usize) -> Option<RawFrame> {
        self.filled += n;
        if self.filled < self.body.len() {
            return None;
        }
        self.stage = Stage::Prefix;
        self.filled = 0;
        Some(RawFrame {
            kind: self.kind,
            body: std::mem::take(&mut self.body),
        })
    }

    fn zeroize_partial(&mut self) {
        if self.sensitive {
            self.body.as_mut().zeroize();
        }
    }
}

impl<P: FramePolicy> Drop for Decoder<P> {
    fn drop(&mut self) {
        self.zeroize_partial();
    }
}

/// The five prefix bytes for a frame of `kind` with a `body_len`-byte body, checked against
/// `max_length` (the receiver's limit for this kind). Refuses a frame the peer would refuse, so
/// a local bug surfaces here and not as a dropped connection.
pub fn encode_prefix(
    kind: u8,
    body_len: usize,
    max_length: u32,
) -> Result<[u8; PREFIX_LEN], FrameError> {
    let length = body_len
        .checked_add(1)
        .and_then(|l| u32::try_from(l).ok())
        .ok_or(FrameError::TooLong {
            length: u32::MAX,
            max: max_length,
        })?;
    if length > max_length {
        return Err(FrameError::TooLong {
            length,
            max: max_length,
        });
    }
    let mut out = [0; PREFIX_LEN];
    out[..LENGTH_PREFIX_LEN].copy_from_slice(&length.to_le_bytes());
    out[LENGTH_PREFIX_LEN] = kind;
    Ok(out)
}

/// A whole frame in one buffer: prefix, then `body`.
pub fn encode_frame(kind: u8, body: &[u8], max_length: u32) -> Result<Vec<u8>, FrameError> {
    let prefix = encode_prefix(kind, body.len(), max_length)?;
    let mut out = Vec::with_capacity(PREFIX_LEN + body.len());
    out.extend_from_slice(&prefix);
    out.extend_from_slice(body);
    Ok(out)
}
