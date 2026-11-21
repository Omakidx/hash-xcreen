//! Real `socketpair` tests of the `recvmsg` rule (docs/ipc.md section 3 and section 19.1 rule 8):
//! a control message, here `SCM_RIGHTS`, must be refused and must not install a descriptor.

use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

use hx_ipc::error::{AncillaryData, FrameError, ReadError};
use hx_ipc::frame::{Decoder, FramePolicy, encode_frame};
use hx_ipc::recv::{NoCmsgReader, recv_no_cmsg};
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

struct P;
impl FramePolicy for P {
    fn absolute_max_length(&self) -> u32 {
        1_000
    }
    fn max_length(&self, kind: u8) -> Result<u32, FrameError> {
        if kind == 1 {
            Ok(1_000)
        } else {
            Err(FrameError::UnknownKind(kind))
        }
    }
}

/// Sends `data` together with one file descriptor.
fn send_with_fd(sock: &UnixStream, data: &[u8], fd: &UnixStream) {
    let fds = [fd.as_fd()];
    let mut space = [std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    assert!(ancillary.push(SendAncillaryMessage::ScmRights(&fds)));
    let n = sendmsg(
        sock,
        &[std::io::IoSlice::new(data)],
        &mut ancillary,
        SendFlags::empty(),
    )
    .unwrap();
    assert_eq!(n, data.len());
}

#[test]
fn plain_frames_pass_through_the_reader() {
    let (mut a, b) = UnixStream::pair().unwrap();
    a.write_all(&encode_frame(1, b"hello", 1_000).unwrap())
        .unwrap();
    let mut d = Decoder::new(P);
    let f = d.read_from(&mut NoCmsgReader(&b)).unwrap().unwrap();
    assert_eq!((f.kind, &f.body[..]), (1, &b"hello"[..]));
    drop(a);
    assert!(
        d.read_from(&mut NoCmsgReader(&b)).unwrap().is_none(),
        "clean end of stream"
    );
}

#[test]
fn an_scm_rights_descriptor_is_refused_and_not_installed() {
    let (a, b) = UnixStream::pair().unwrap();
    // The descriptor under test: one end of another socketpair. If the receiver installed a copy
    // of it, closing our own copy would not end the other side.
    let (carried, witness) = UnixStream::pair().unwrap();
    witness.set_nonblocking(true).unwrap();
    send_with_fd(&a, &encode_frame(1, b"hello", 1_000).unwrap(), &carried);
    drop(carried);

    let mut d = Decoder::new(P);
    let err = d.read_from(&mut NoCmsgReader(&b)).unwrap_err();
    assert!(
        matches!(err, ReadError::Ancillary(AncillaryData)),
        "{err:?}"
    );
    assert!(err.is_violation());
    // The decoder must not hand out the frame that came with the descriptor: the caller closes
    // the connection on this error.

    // Nothing holds the carried descriptor any more: the witness sees end of stream.
    let mut w = &witness;
    let mut buf = [0u8; 1];
    match w.read(&mut buf) {
        Ok(0) => {}
        other => panic!("the descriptor was installed in the receiver: {other:?}"),
    }
}

#[test]
fn recv_no_cmsg_reports_the_violation_as_invalid_data() {
    let (a, b) = UnixStream::pair().unwrap();
    let (carried, _witness) = UnixStream::pair().unwrap();
    send_with_fd(&a, b"x", &carried);
    let mut buf = [0u8; 8];
    let e = recv_no_cmsg(&b, &mut buf).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidData);
    assert!(
        e.get_ref()
            .and_then(|i| i.downcast_ref::<AncillaryData>())
            .is_some()
    );
}

#[test]
fn a_descriptor_in_the_middle_of_a_stream_is_still_caught() {
    let (mut a, b) = UnixStream::pair().unwrap();
    let (carried, _w) = UnixStream::pair().unwrap();
    a.write_all(&encode_frame(1, b"one", 1_000).unwrap())
        .unwrap();
    let mut d = Decoder::new(P);
    assert!(d.read_from(&mut NoCmsgReader(&b)).unwrap().is_some());
    send_with_fd(&a, &encode_frame(1, b"two", 1_000).unwrap(), &carried);
    assert!(matches!(
        d.read_from(&mut NoCmsgReader(&b)),
        Err(ReadError::Ancillary(_))
    ));
}

#[test]
fn an_oversize_frame_over_a_real_socket_is_refused_without_reading_the_body() {
    let (mut a, b) = UnixStream::pair().unwrap();
    a.write_all(&u32::MAX.to_le_bytes()).unwrap();
    let mut d = Decoder::new(P);
    assert!(matches!(
        d.read_from(&mut NoCmsgReader(&b)),
        Err(ReadError::Frame(FrameError::TooLong { .. }))
    ));
}

#[test]
fn the_decoder_is_poisoned_after_a_descriptor_arrives() {
    let (a, b) = UnixStream::pair().unwrap();
    let (carried, _w) = UnixStream::pair().unwrap();
    send_with_fd(&a, &encode_frame(1, b"x", 1_000).unwrap(), &carried);
    let mut d = Decoder::new(P);
    assert!(matches!(
        d.read_from(&mut NoCmsgReader(&b)),
        Err(ReadError::Ancillary(_))
    ));
    let wire = encode_frame(1, b"y", 1_000).unwrap();
    assert!(matches!(
        d.read_from(&mut &wire[..]),
        Err(ReadError::Frame(FrameError::Poisoned))
    ));
}

#[test]
fn msg_trunc_is_a_violation() {
    // Datagram sockets can truncate; the stream-only reader refuses that as well.
    let (a, b) = std::os::unix::net::UnixDatagram::pair().unwrap();
    a.send(&[1u8; 64]).unwrap();
    let mut small = [0u8; 8];
    let e = recv_no_cmsg(&b, &mut small).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidData);
}

#[test]
fn a_read_timeout_is_a_transport_error_not_a_violation() {
    let (_a, b) = UnixStream::pair().unwrap();
    b.set_read_timeout(Some(std::time::Duration::from_millis(30)))
        .unwrap();
    let mut d = Decoder::new(P);
    match d.read_from(&mut NoCmsgReader(&b)) {
        Err(e @ ReadError::Io(_)) => assert!(!e.is_violation()),
        other => panic!("{other:?}"),
    }
}
