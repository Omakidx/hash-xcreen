//! A blocking, deadline-bounded framed connection over a unix socket, shared by the privd and
//! the gatewayd admin clients (same framing, `docs/ipc.md` sections 4 and 9).
//!
//! * Frames are read only with [`Decoder::read_from`] over a [`NoCmsgReader`] (`recvmsg`, so a
//!   descriptor or other control message is a violation, never installed).
//! * Every read and write is bounded by a deadline; nothing waits forever.
//! * The frame buffer is filled directly by `recvmsg` and the decoder owns it, so a reply (which
//!   may contain the pairing code) makes no copy that we keep.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use hx_ipc::privd::{PrivdPolicy, Side};
use hx_ipc::recv::recv_no_cmsg;
use hx_ipc::{Decoder, RawFrame, ReadError};

use super::error::CliError;

/// Reads with `recvmsg` until `deadline`.
struct DeadlineReader<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline"));
        }
        self.stream.set_read_timeout(Some(left))?;
        recv_no_cmsg(self.stream, buf)
    }
}

/// One connection.
pub struct Wire {
    stream: UnixStream,
    decoder: Decoder<PrivdPolicy>,
    what: &'static str,
}

fn io_message(what: &str, e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::NotFound => format!("{what} is not running (its socket does not exist)"),
        io::ErrorKind::ConnectionRefused => {
            format!("{what} is not accepting connections (is its unit running?)")
        }
        io::ErrorKind::PermissionDenied => {
            format!("{what}: permission denied on its socket (run as root)")
        }
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => format!("{what} timed out"),
        k => format!("{what}: {k}"),
    }
}

impl Wire {
    /// Connects to the socket at `path`, but only after checking that it is the daemon's:
    ///
    /// 1. the socket file is a socket (not a symlink) owned by `expected_uid`, and its directory is
    ///    a real directory owned by `expected_uid` and not writable by group or others, so nobody
    ///    else could have put a socket there (a socket that is not ours would otherwise receive
    ///    the pairing token, the Linux password's verifier input and every command);
    /// 2. after `connect`, `SO_PEERCRED` says the listener belongs to `expected_uid`.
    ///
    /// Nothing is written before both hold. `what` names the peer in messages ("hx-privd").
    pub fn connect(path: &Path, what: &'static str, expected_uid: u32) -> Result<Self, CliError> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let refuse = |why: &str| CliError::Failed(format!("refusing to talk to {what}: {why}"));
        let unavailable = |e: &io::Error| CliError::Unavailable(io_message(what, e));
        let meta = std::fs::symlink_metadata(path).map_err(|e| unavailable(&e))?;
        if !meta.file_type().is_socket() || meta.uid() != expected_uid {
            return Err(refuse(
                "its socket is not a socket owned by the expected user (a symlink is refused)",
            ));
        }
        if let Some(dir) = path.parent() {
            let d = std::fs::symlink_metadata(dir).map_err(|e| unavailable(&e))?;
            if !d.is_dir() || d.uid() != expected_uid || d.mode() & 0o022 != 0 {
                return Err(refuse(
                    "the socket's directory is not owned by the expected user or is writable by others",
                ));
            }
        }
        let stream = UnixStream::connect(path).map_err(|e| unavailable(&e))?;
        let cred = hx_ipc::peer::peer_credentials(&stream).map_err(|e| unavailable(&e))?;
        if cred.uid != expected_uid {
            return Err(refuse(&format!(
                "the process behind the socket runs as uid {}, expected {expected_uid}",
                cred.uid
            )));
        }
        Ok(Self {
            stream,
            decoder: Decoder::new(PrivdPolicy::new(Side::Client)),
            what,
        })
    }

    /// Writes `bytes` completely, within `limit`.
    pub fn send(&mut self, bytes: &[u8], limit: Duration) -> Result<(), CliError> {
        self.stream
            .set_write_timeout(Some(limit.max(Duration::from_millis(1))))
            .map_err(|e| CliError::Unavailable(io_message(self.what, &e)))?;
        self.stream
            .write_all(bytes)
            .and_then(|()| self.stream.flush())
            .map_err(|e| CliError::Unavailable(io_message(self.what, &e)))
    }

    /// Reads one frame before `deadline`. A closed connection is `Unavailable`; a broken frame
    /// is a protocol violation (`Failed`).
    pub fn recv(&mut self, deadline: Instant) -> Result<RawFrame, CliError> {
        let mut reader = DeadlineReader {
            stream: &self.stream,
            deadline,
        };
        match self.decoder.read_from(&mut reader) {
            Ok(Some(raw)) => Ok(raw),
            Ok(None) => Err(CliError::Unavailable(format!(
                "{} closed the connection",
                self.what
            ))),
            Err(ReadError::Io(e)) => Err(CliError::Unavailable(io_message(self.what, &e))),
            Err(violation) => Err(CliError::Failed(format!(
                "{} broke the protocol: {violation}",
                self.what
            ))),
        }
    }
}
