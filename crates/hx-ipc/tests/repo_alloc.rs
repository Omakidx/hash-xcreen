#![cfg(feature = "repo")]
//! Allocation behaviour of the repository link's decode paths, measured with a counting
//! allocator: a 64 KiB body of empty repeated elements must be refused without the 10 to 40
//! times amplification `prost` would otherwise allocate (`docs/ipc.md` section 8, "Memory"); a
//! kind-2 frame makes exactly two copies of the secret and leaves none behind unzeroized; a
//! kind-3 frame's payload is the decoder's own buffer.
//!
//! One test function, so the counting allocator measures one thing at a time.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

use bytes::BytesMut;
use hx_ipc::frame::{Decoder, RawFrame};
use hx_ipc::repo::{self, DataFrame, Endpoint, Incoming, RepoFramePolicy};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// Allocations (and growths) of at least `BIG_FROM` bytes; 0 disables counting.
static BIG_FROM: AtomicUsize = AtomicUsize::new(0);
static BIG_COUNT: AtomicUsize = AtomicUsize::new(0);
/// While set, every block freed (up to 4 KiB) is scanned for a run of the marker byte.
static SCAN: AtomicBool = AtomicBool::new(false);
static LEAKED: AtomicUsize = AtomicUsize::new(0);
const MARKER: u8 = 0xA5;

fn note_big(size: usize) {
    let t = BIG_FROM.load(SeqCst);
    if t != 0 && size >= t {
        BIG_COUNT.fetch_add(1, SeqCst);
    }
}

#[allow(unsafe_code)]
fn scan_freed(p: *mut u8, size: usize) {
    if SCAN.load(SeqCst) && (64..=4096).contains(&size) {
        // SAFETY: `p` is a live block of `size` bytes that is about to be freed.
        let block = unsafe { std::slice::from_raw_parts(p, size) };
        let mut run = 0;
        for b in block {
            run = if *b == MARKER { run + 1 } else { 0 };
            if run >= 64 {
                LEAKED.fetch_add(1, SeqCst);
                break;
            }
        }
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
        scan_freed(p, l.size());
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

fn varint(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn field(number: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![((number << 3) | 2) as u8];
    varint(payload.len(), &mut v);
    v.extend_from_slice(payload);
    v
}

/// `total` bytes of repeated empty elements of field `number`.
fn empties(number: u32, total: usize) -> Vec<u8> {
    field(number, &[]).repeat(total / 2)
}

/// `path` is the chain of field numbers from the frame down to the repeated field, the last
/// one repeated: a body of `total` bytes of empty elements of it.
fn nested(path: &[u32], total: usize) -> Vec<u8> {
    let (last, outer) = path.split_last().unwrap();
    let mut body = empties(*last, total);
    for n in outer.iter().rev() {
        body = field(*n, &body);
    }
    body
}

/// A decode may allocate at most this much beyond the body itself.
const SLACK: usize = 16 * 1024;

fn refused(body: &[u8], endpoint: Endpoint, what: &str) {
    assert!(
        body.len() <= 65_535,
        "{what}: the body must fit a kind-1 frame"
    );
    let raw = RawFrame {
        kind: repo::KIND_MESSAGE,
        body: BytesMut::from(body),
    };
    let (r, peak) = peak_during(|| repo::decode(raw, endpoint));
    assert!(r.is_err(), "{what}: must be refused");
    assert!(
        peak <= SLACK,
        "{what}: {peak} bytes for a {} byte body",
        body.len()
    );
}

#[test]
fn worst_case_bodies_are_refused_without_amplification_and_secrets_are_not_copied() {
    // Every repeated field of the schema, as one body of ~65 000 bytes of empty elements.
    // (path from RepoFrame: job=3 / backup=11 / manifest=1 / container_config=5 and so on)
    let w = Endpoint::Worker;
    let p = Endpoint::PrivdWorkerLink;
    let d = Endpoint::PrivdDriveLink;
    refused(&nested(&[3, 3], 65_000), w, "job.secret_slots");
    refused(&nested(&[3, 11, 2], 65_000), w, "backup.excludes");
    refused(&nested(&[3, 11, 4], 65_000), w, "backup.tags");
    refused(
        &nested(&[3, 11, 1, 5], 65_000),
        w,
        "manifest.container_config",
    );
    refused(&nested(&[3, 15, 1], 65_000), w, "forget_prune.forget");
    refused(&nested(&[3, 17, 2], 65_000), w, "keys.remove_key_ids");
    refused(&nested(&[5, 2, 1], 65_000), w, "list_page.entries (worker)");
    refused(&nested(&[5, 2, 1], 65_000), d, "list_page.entries (drive)");
    refused(&nested(&[7, 9], 65_000), p, "result.key_ids");
    refused(&nested(&[7, 11], 65_000), p, "result.snapshots");

    // The same elements split over many occurrences of the enclosing message: protobuf merges
    // them, so the limit must hold over the sum and not per occurrence.
    let one_slot = field(3, &[]);
    let job = field(3, &one_slot.repeat(2));
    refused(
        &job.repeat(10_000),
        w,
        "job.secret_slots over many Job occurrences",
    );
    let page = field(5, &field(2, &field(1, &[]).repeat(1)));
    refused(
        &page.repeat(10_000),
        w,
        "list_page.entries over many occurrences",
    );

    // Sensitivity: the same snapshot body decoded by prost alone is a large multiple of its size.
    use prost::Message;
    let body = nested(&[7, 11], 65_000);
    let (_, unguarded) =
        peak_during(|| repo::pb::RepoFrame::decode(&body[..]).map(|f| f.encoded_len()));
    assert!(
        unguarded > 10 * body.len(),
        "prost alone allocates {unguarded}"
    );

    // The kind-2 path makes exactly the copies documented: the frame's own buffer (filled
    // straight from the reader) and the `Secret`. Anything else (a scratch read buffer, a growth
    // by reallocation, a protobuf copy) would add a big allocation here.
    let secret = vec![0x5Au8; 1_000];
    let wire = repo::encode_secret(0, 0, &secret).unwrap();
    let mut decoder = Decoder::new(RepoFramePolicy::new(Endpoint::Worker));
    BIG_COUNT.store(0, SeqCst);
    BIG_FROM.store(900, SeqCst);
    let raw = decoder.read_from(&mut &wire[..]).unwrap().unwrap();
    let got = repo::decode(raw, Endpoint::Worker).unwrap();
    BIG_FROM.store(0, SeqCst);
    assert!(matches!(got, Incoming::Secret(_)));
    assert_eq!(
        BIG_COUNT.load(SeqCst),
        2,
        "frame buffer + Secret, no other copy of the secret"
    );
    drop(got);

    // And every copy is zeroized before it is freed: the sender's buffers, the decoder's frame
    // buffer, and the Secret. First prove that the detector sees an unzeroized free.
    LEAKED.store(0, SeqCst);
    SCAN.store(true, SeqCst);
    drop(std::hint::black_box(vec![MARKER; 200]));
    SCAN.store(false, SeqCst);
    assert_eq!(
        LEAKED.load(SeqCst),
        1,
        "the detector must see a plain Vec freed unzeroized"
    );

    let secret = vec![MARKER; 200];
    let leaks = |label: &str, f: &dyn Fn()| {
        LEAKED.store(0, SeqCst);
        SCAN.store(true, SeqCst);
        f();
        SCAN.store(false, SeqCst);
        assert_eq!(
            LEAKED.load(SeqCst),
            0,
            "{label}: an unzeroized copy of the secret was freed"
        );
    };
    leaks("encode", &|| {
        drop(repo::encode_secret(0, 1, &secret).unwrap());
    });
    let wire = repo::encode_secret(0, 1, &secret).unwrap();
    leaks("decode", &|| {
        let mut decoder = Decoder::new(RepoFramePolicy::new(Endpoint::Worker));
        let raw = decoder.read_from(&mut &wire[..]).unwrap().unwrap();
        let got = repo::decode(raw, Endpoint::Worker).unwrap();
        assert!(matches!(got, Incoming::Secret(_)));
    });
    leaks("cut short", &|| {
        let mut half = Decoder::new(RepoFramePolicy::new(Endpoint::Worker));
        half.feed(&wire[..100]).unwrap();
        drop(half);
    });
    let mut hostile = 0u64.to_le_bytes().to_vec();
    hostile.push(2); // slot 2 does not exist
    hostile.extend_from_slice(&secret);
    leaks("refused", &|| {
        let raw = RawFrame {
            kind: repo::KIND_SECRET,
            body: BytesMut::from(&hostile[..]),
        };
        assert!(repo::decode(raw, Endpoint::Worker).is_err());
    });
    zeroize::Zeroize::zeroize(&mut hostile);
    drop(wire);
    drop(secret);

    // A data frame's payload is the decoder's own buffer: one big allocation (the decoder's),
    // no copy when it is parsed, and a payload view into it.
    let payload = vec![0x42u8; 1_048_576];
    let wire = repo::encode_data(5, false, &payload).unwrap();
    let mut decoder = Decoder::new(RepoFramePolicy::new(Endpoint::PrivdWorkerLink));
    BIG_COUNT.store(0, SeqCst);
    BIG_FROM.store(512 * 1024, SeqCst);
    let raw = decoder.read_from(&mut &wire[..]).unwrap().unwrap();
    let base = raw.body.as_ptr();
    let frame = DataFrame::from_body(raw.body).unwrap();
    BIG_FROM.store(0, SeqCst);
    assert_eq!(BIG_COUNT.load(SeqCst), 1, "only the decoder's own buffer");
    assert_eq!(frame.payload.as_ptr(), base.wrapping_add(9));
    assert_eq!(frame.payload.len(), 1_048_576);
}
