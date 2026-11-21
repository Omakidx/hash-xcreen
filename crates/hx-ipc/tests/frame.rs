//! Framing tests that need no feature: limits before allocation, truncation, poisoning, silent
//! directions, chunked feeding.

use std::io::Read;

use hx_ipc::error::{FrameError, ReadError};
use hx_ipc::frame::{Decoder, FramePolicy, encode_frame, encode_prefix};
use proptest::prelude::*;

/// kind 1 up to 100, kind 2 up to 10 (sensitive), kind 9 defined but not allowed here.
#[derive(Clone, Copy)]
struct Test {
    silent: bool,
}

impl FramePolicy for Test {
    fn absolute_max_length(&self) -> u32 {
        if self.silent { 0 } else { 100 }
    }
    fn max_length(&self, kind: u8) -> Result<u32, FrameError> {
        match kind {
            1 => Ok(100),
            2 => Ok(10),
            9 => Err(FrameError::KindNotAllowed(9)),
            k => Err(FrameError::UnknownKind(k)),
        }
    }
    fn is_sensitive(&self, kind: u8) -> bool {
        kind == 2
    }
}

fn dec() -> Decoder<Test> {
    Decoder::new(Test { silent: false })
}

#[test]
fn debug_output_never_contains_body_bytes() {
    // Kind 2 is the sensitive kind of the test policy. 0xAB = 171 would print as "171".
    let wire = encode_frame(2, &[0xAB; 8], 100).unwrap();
    let mut d = dec();
    // Mid-frame: header and three body bytes are in.
    d.feed(&wire[..8]).unwrap();
    let shown = format!("{d:?}");
    assert!(!shown.contains("171") && !shown.contains("ab"), "{shown}");
    let (_, f) = d.feed(&wire[8..]).unwrap();
    let f = f.unwrap();
    let shown = format!("{f:?}");
    assert!(!shown.contains("171"), "{shown}");
    assert!(
        shown.contains("body_len: 8") && shown.contains("kind: 2"),
        "{shown}"
    );
}

#[test]
fn decodes_one_frame_exactly() {
    let wire = encode_frame(1, b"hello", 100).unwrap();
    assert_eq!(wire.len(), 5 + 5);
    let mut d = dec();
    let (used, frame) = d.feed(&wire).unwrap();
    assert_eq!(used, wire.len());
    let f = frame.unwrap();
    assert_eq!(f.kind, 1);
    assert_eq!(&f.body[..], b"hello");
    assert!(d.at_boundary());
    assert!(d.finish().is_ok());
}

#[test]
fn feed_stops_at_the_end_of_a_frame() {
    let mut wire = encode_frame(1, b"ab", 100).unwrap();
    wire.extend(encode_frame(1, b"cd", 100).unwrap());
    let mut d = dec();
    let (used, f1) = d.feed(&wire).unwrap();
    assert_eq!(&f1.unwrap().body[..], b"ab");
    let (used2, f2) = d.feed(&wire[used..]).unwrap();
    assert_eq!(used + used2, wire.len());
    assert_eq!(&f2.unwrap().body[..], b"cd");
}

#[test]
fn an_empty_body_is_a_valid_frame() {
    let wire = encode_frame(1, b"", 100).unwrap();
    assert_eq!(wire.len(), 5);
    let (_, f) = dec().feed(&wire).unwrap();
    assert!(f.unwrap().body.is_empty());
}

#[test]
fn zero_length_is_rejected_at_four_bytes() {
    let mut d = dec();
    assert_eq!(d.feed(&[0, 0, 0, 0]).unwrap_err(), FrameError::ZeroLength);
    assert_eq!(d.feed(&[1]).unwrap_err(), FrameError::Poisoned);
}

#[test]
fn an_absurd_length_is_rejected_from_the_prefix_alone() {
    // Four bytes announcing 4 GiB - 1: refused before the kind byte even arrives, so nothing
    // could have been allocated for the body.
    let mut d = dec();
    let err = d.feed(&u32::MAX.to_le_bytes()).unwrap_err();
    assert_eq!(
        err,
        FrameError::TooLong {
            length: u32::MAX,
            max: 100
        }
    );
    // The same for a length just over the limit.
    let mut d = dec();
    assert_eq!(
        d.feed(&101u32.to_le_bytes()).unwrap_err(),
        FrameError::TooLong {
            length: 101,
            max: 100
        }
    );
}

#[test]
fn per_kind_limit_is_checked_when_the_kind_arrives() {
    // length 11 is within the absolute maximum (100) but over kind 2's limit (10).
    let mut d = dec();
    let mut head = 11u32.to_le_bytes().to_vec();
    head.push(2);
    assert_eq!(
        d.feed(&head).unwrap_err(),
        FrameError::TooLong {
            length: 11,
            max: 10
        }
    );
}

#[test]
fn unknown_and_disallowed_kinds() {
    let mut d = dec();
    let mut head = 2u32.to_le_bytes().to_vec();
    head.push(77);
    assert_eq!(d.feed(&head).unwrap_err(), FrameError::UnknownKind(77));
    let mut d = dec();
    let mut head = 2u32.to_le_bytes().to_vec();
    head.push(9);
    assert_eq!(d.feed(&head).unwrap_err(), FrameError::KindNotAllowed(9));
}

#[test]
fn truncated_frames_are_reported_at_end_of_stream() {
    let wire = encode_frame(1, b"hello", 100).unwrap();
    for cut in 1..wire.len() {
        let mut d = dec();
        let (used, frame) = d.feed(&wire[..cut]).unwrap();
        assert_eq!(used, cut);
        assert!(frame.is_none());
        assert_eq!(d.finish(), Err(FrameError::Truncated), "cut at {cut}");
        let mut input = &wire[..cut];
        let mut d = dec();
        assert!(matches!(
            d.read_from(&mut input),
            Err(ReadError::Frame(FrameError::Truncated))
        ));
    }
    let mut empty: &[u8] = &[];
    assert!(
        dec().read_from(&mut empty).unwrap().is_none(),
        "clean end at a boundary"
    );
}

#[test]
fn a_silent_direction_rejects_the_first_byte_only() {
    let mut d = Decoder::new(Test { silent: true });
    // No data: no violation (EOF at a boundary is clean).
    let mut empty: &[u8] = &[];
    assert!(d.read_from(&mut empty).unwrap().is_none());
    // One byte is a violation.
    assert_eq!(d.feed(&[0]).unwrap_err(), FrameError::ForbiddenDirection);
    let mut one: &[u8] = &[0];
    let mut d = Decoder::new(Test { silent: true });
    assert!(matches!(
        d.read_from(&mut one),
        Err(ReadError::Frame(FrameError::ForbiddenDirection))
    ));
}

#[test]
fn read_from_reads_no_more_than_the_frame_needs() {
    struct Counting<'a> {
        data: &'a [u8],
        max_request: usize,
    }
    impl Read for Counting<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.max_request = self.max_request.max(buf.len());
            let n = buf.len().min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }
    let mut wire = encode_frame(1, &[7; 30], 100).unwrap();
    let tail = encode_frame(1, b"next", 100).unwrap();
    wire.extend(&tail);
    let mut r = Counting {
        data: &wire,
        max_request: 0,
    };
    let mut d = dec();
    let f = d.read_from(&mut r).unwrap().unwrap();
    assert_eq!(f.body.len(), 30);
    assert_eq!(r.data, &tail[..], "the next frame was not touched");
    assert!(r.max_request <= 30);
}

#[test]
fn encoders_refuse_what_the_peer_would_refuse() {
    assert!(encode_prefix(1, 99, 100).is_ok());
    assert_eq!(
        encode_prefix(1, 100, 100).unwrap_err(),
        FrameError::TooLong {
            length: 101,
            max: 100
        }
    );
    assert!(encode_frame(1, &[0; 200], 100).is_err());
}

proptest! {
    /// Any frame survives any chunking of the byte stream.
    #[test]
    fn chunked_round_trip(
        bodies in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..99), 1..6),
        chunk in 1usize..40,
    ) {
        let mut wire = Vec::new();
        for b in &bodies {
            wire.extend(encode_frame(1, b, 100).unwrap());
        }
        let mut d = dec();
        let mut got = Vec::new();
        for piece in wire.chunks(chunk) {
            let mut rest = piece;
            while !rest.is_empty() {
                let (used, f) = d.feed(rest).unwrap();
                rest = &rest[used..];
                if let Some(f) = f { got.push(f.body.to_vec()); }
            }
        }
        prop_assert_eq!(got, bodies);
        prop_assert!(d.finish().is_ok());
    }

    /// Arbitrary bytes never panic and never produce a frame larger than the limit.
    #[test]
    fn arbitrary_input_is_total(data in proptest::collection::vec(any::<u8>(), 0..400)) {
        let mut d = dec();
        let mut rest = &data[..];
        while !rest.is_empty() {
            match d.feed(rest) {
                Ok((used, f)) => {
                    prop_assert!(used > 0);
                    if let Some(f) = f { prop_assert!(f.body.len() < 100); }
                    rest = &rest[used..];
                }
                Err(_) => break,
            }
        }
    }
}
