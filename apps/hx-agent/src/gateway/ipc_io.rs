//! Async reading of framed internal-IPC sockets (`docs/ipc.md` sections 4 and 19.1, rule 8).
//!
//! Every frame is read with `recvmsg` through [`hx_ipc::recv::NoCmsgReader`] and
//! [`hx_ipc::frame::Decoder::read_from`], inside tokio's `try_io` so that the readiness of the
//! socket is honoured and no intermediate buffer holds the bytes (a kind-2 frame carries a
//! secret). A control message or `MSG_CTRUNC` is a violation, never silently dropped.

use std::io;

use hx_ipc::frame::{Decoder, FramePolicy, RawFrame};
use hx_ipc::{NoCmsgReader, ReadError};
use tokio::io::Interest;
use tokio::net::UnixStream;

/// Reads until one complete frame is decoded. `Ok(None)` is a clean end of stream at a frame
/// boundary. Cancel-safe: a partly received frame stays in `decoder`.
pub(crate) async fn read_frame<P: FramePolicy>(
    stream: &UnixStream,
    decoder: &mut Decoder<P>,
) -> Result<Option<RawFrame>, ReadError> {
    loop {
        stream.readable().await.map_err(ReadError::Io)?;
        let attempt = stream.try_io(Interest::READABLE, || {
            match decoder.read_from(&mut NoCmsgReader(stream)) {
                Ok(frame) => Ok(Ok(frame)),
                // A would-block read keeps the partial frame inside the decoder.
                Err(ReadError::Io(e)) => Err(e),
                Err(violation) => Ok(Err(violation)),
            }
        });
        match attempt {
            Ok(result) => return result,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(ReadError::Io(e)),
        }
    }
}
