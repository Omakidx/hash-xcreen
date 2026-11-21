#![cfg(all(feature = "privd", feature = "link"))]
//! Allocation bound of decoding hostile bodies: a body full of empty repeated elements must be
//! rejected without the 10 to 40 times amplification that prost would otherwise allocate
//! before any count limit could be checked.
//!
//! One test function, so the counting allocator measures one thing at a time.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

use bytes::BytesMut;
use hx_ipc::frame::RawFrame;
use hx_ipc::link::frames;
use hx_ipc::link::{Lane, LinkPolicy, Role};
use hx_ipc::privd::{self, Side};
use hx_ipc::{admin, link};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// Allocations (and growths) of at least `BIG_FROM` bytes; 0 disables counting.
static BIG_FROM: AtomicUsize = AtomicUsize::new(0);
static BIG_COUNT: AtomicUsize = AtomicUsize::new(0);

fn note_big(size: usize) {
    let t = BIG_FROM.load(SeqCst);
    if t != 0 && size >= t {
        BIG_COUNT.fetch_add(1, SeqCst);
    }
}

#[allow(unsafe_code)]
// SAFETY: forwards every call to the system allocator unchanged and only counts bytes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        note_big(l.size());
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let now = LIVE.fetch_add(l.size(), SeqCst) + l.size();
            PEAK.fetch_max(now, SeqCst);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), SeqCst);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        note_big(new);
        let q = unsafe { System.realloc(p, l, new) };
        if !q.is_null() {
            if new >= l.size() {
                let now = LIVE.fetch_add(new - l.size(), SeqCst) + (new - l.size());
                PEAK.fetch_max(now, SeqCst);
            } else {
                LIVE.fetch_sub(l.size() - new, SeqCst);
            }
        }
        q
    }
}

#[global_allocator]
static A: Counting = Counting;

/// Peak extra bytes allocated while `f` runs.
fn peak_during<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let base = LIVE.load(SeqCst);
    PEAK.store(base, SeqCst);
    let r = f();
    (r, PEAK.load(SeqCst).saturating_sub(base))
}

fn field(number: u32, wire: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![((number << 3) | wire) as u8];
    if wire == 2 {
        let mut n = payload.len();
        loop {
            let b = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                v.push(b);
                break;
            }
            v.push(b | 0x80);
        }
    }
    v.extend_from_slice(payload);
    v
}

fn repeated(number: u32, item: &[u8], total: usize) -> Vec<u8> {
    let one = field(number, 2, item);
    one.repeat(total / one.len())
}

/// A decode may allocate at most this much beyond the body itself.
const SLACK: usize = 16 * 1024;

#[test]
fn worst_case_bodies_are_rejected_without_amplification() {
    // privd Request with ~65 KB of empty secret_slots (field 3 of Request, field 3 of Frame).
    let request = repeated(3, &[], 65_000);
    let body = field(3, 2, &request);
    assert!(body.len() <= 65_535);
    let raw = RawFrame {
        kind: privd::KIND_MESSAGE,
        body: BytesMut::from(&body[..]),
    };
    let (r, peak) = peak_during(|| privd::decode(raw, Side::Server));
    assert!(r.is_err());
    assert!(
        peak <= SLACK,
        "privd request: {peak} bytes for a {} byte body",
        body.len()
    );
    // Sensitivity: the same body decoded by prost alone is a large multiple of its size.
    use prost::Message;
    let (_, unguarded) =
        peak_during(|| privd::pb::Frame::decode(&body[..]).map(|f| f.encoded_len()));
    assert!(
        unguarded > 10 * body.len(),
        "prost alone allocates {unguarded}"
    );

    // setup_host.extra_host_addresses full of empty strings (Request 15 -> 4 -> repeated 1).
    let addrs = repeated(1, &[], 65_000);
    let host = field(4, 2, &addrs);
    let request = field(15, 2, &host);
    let body = field(3, 2, &request);
    let raw = RawFrame {
        kind: privd::KIND_MESSAGE,
        body: BytesMut::from(&body[..]),
    };
    let (r, peak) = peak_during(|| privd::decode(raw, Side::Server));
    assert!(r.is_err());
    assert!(peak <= SLACK, "extra_host_addresses: {peak}");

    // admin Request with many slots.
    let request = repeated(3, &[], 65_000);
    let body = field(3, 2, &request);
    let raw = RawFrame {
        kind: privd::KIND_MESSAGE,
        body: BytesMut::from(&body[..]),
    };
    let (r, peak) = peak_during(|| admin::decode(raw, Side::Server));
    assert!(r.is_err());
    assert!(peak <= SLACK, "admin: {peak}");

    // link Info with ~320 KB of codecs, unpacked and packed.
    let p = LinkPolicy::new(Role::Gateway, Lane::Ctl);
    let unpacked: Vec<u8> = [0x18u8, 0x01].repeat(160_000);
    let packed = field(3, 2, &vec![1u8; 320_000]);
    for (label, info) in [("unpacked", unpacked), ("packed", packed)] {
        let body = field(1, 2, &info);
        let raw = RawFrame {
            kind: link::KIND_SESSION_TO_GATEWAY,
            body: BytesMut::from(&body[..]),
        };
        let (r, peak) = peak_during(|| frames::parse(&p, raw, 1 << 30));
        assert!(r.is_err(), "{label}");
        assert!(peak <= SLACK, "info codecs {label}: {peak}");
    }

    // link frame_feedback with ~16 KB of empty results.
    let p = LinkPolicy::new(Role::Session, Lane::Ctl);
    let feedback = repeated(1, &[], 16_000);
    let body = field(7, 2, &feedback);
    let raw = RawFrame {
        kind: link::KIND_GATEWAY_TO_SESSION,
        body: BytesMut::from(&body[..]),
    };
    let (r, peak) = peak_during(|| frames::parse(&p, raw, 1 << 30));
    assert!(r.is_err());
    assert!(peak <= SLACK, "frame_feedback: {peak}");

    // The kind-2 path makes exactly the copies documented in the crate docs: the frame's own
    // buffer (filled straight from the reader) and the `Secret`. Anything else (a scratch read
    // buffer, a growth by reallocation, a protobuf copy) would add a big allocation here.
    use hx_ipc::frame::Decoder;
    use hx_ipc::privd::{Incoming, PrivdPolicy};
    let secret = vec![0x5Au8; 8_000];
    let wire = privd::encode_secret(7, 0, &secret).unwrap();
    let mut decoder = Decoder::new(PrivdPolicy::new(Side::Server));
    BIG_COUNT.store(0, SeqCst);
    BIG_FROM.store(4_000, SeqCst);
    let raw = decoder.read_from(&mut &wire[..]).unwrap().unwrap();
    let got = privd::decode(raw, Side::Server).unwrap();
    BIG_FROM.store(0, SeqCst);
    assert!(matches!(got, Incoming::Secret(_)));
    assert_eq!(
        BIG_COUNT.load(SeqCst),
        2,
        "frame buffer + Secret, no other copy of the secret"
    );
}
