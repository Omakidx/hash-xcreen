//! Reading from a unix socket with `recvmsg`, refusing descriptors and other control messages.
//!
//! `docs/ipc.md` section 3 ("No descriptor passing") and section 19.1 rule 8: every frame is read
//! with `recvmsg`, and a control message or `MSG_CTRUNC` is a violation. A plain `recv`/`read`
//! would let a peer make the kernel install an `SCM_RIGHTS` descriptor in this process without
//! the process noticing.
//!
//! The call passes a **zero-length** ancillary buffer. For `SCM_RIGHTS` the kernel then installs
//! no descriptor at all (it discards the in-flight ones) and sets `MSG_CTRUNC`, which this module
//! turns into [`AncillaryData`]. A buffer with room would instead put the descriptor in the
//! process's table before we could refuse it.

use std::io::{self, IoSliceMut, Read};
use std::os::fd::AsFd;

use rustix::net::{RecvAncillaryBuffer, RecvFlags, ReturnFlags, recvmsg};

use crate::error::AncillaryData;

/// One `recvmsg` into `buf`. Returns the byte count (`0` is end of stream, as for `read`).
///
/// Errors: `io::ErrorKind::WouldBlock` and `Interrupted` pass through unchanged (so this works
/// inside a tokio `AsyncFd::try_io` closure); a control message or `MSG_CTRUNC` is an
/// `io::ErrorKind::InvalidData` error that wraps [`AncillaryData`] (see
/// [`crate::ReadError::from`]). The bytes that came with such a message are discarded by the
/// caller closing the connection.
pub fn recv_no_cmsg<Fd: AsFd>(fd: Fd, buf: &mut [u8]) -> io::Result<usize> {
    let mut control = RecvAncillaryBuffer::default();
    let msg = recvmsg(
        fd,
        &mut [IoSliceMut::new(buf)],
        &mut control,
        RecvFlags::empty(),
    )?;
    if msg.flags.contains(ReturnFlags::CTRUNC) || control.drain().next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, AncillaryData));
    }
    Ok(msg.bytes)
}

/// A `std::io::Read` adapter over a unix stream socket that reads with [`recv_no_cmsg`].
///
/// Use it (not the bare socket) under [`crate::frame::Decoder::read_from`] on every socket of
/// privd, the admin socket and the session link.
#[derive(Debug)]
pub struct NoCmsgReader<S>(pub S);

impl<S: AsFd> Read for NoCmsgReader<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        recv_no_cmsg(&self.0, buf)
    }
}
