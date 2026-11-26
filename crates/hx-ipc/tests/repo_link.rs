#![cfg(feature = "repo")]
//! The stateful rules of the repository link (`docs/ipc.md` sections 25 to 27 and 29): handshake,
//! job and secrets, request ids and outstanding limits, data streams, listing, job result. Each
//! scenario runs against **both ends** of a link at once: what one end sends the other receives,
//! and the two [`LinkState`]s must agree on every verdict.

mod repo_common;

use bytes::{Bytes, BytesMut};
use hx_ipc::repo::pb::{self, JobKind, ObjectType as T, repo_frame::Frame as F, repo_request::Op};
use hx_ipc::repo::{DataFrame, Endpoint, Incoming, LinkState};
use hx_ipc::secret::SecretFrame;
use proptest::prelude::*;
use repo_common::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Who {
    Privd,
    Other,
}

/// Both ends of one link.
struct Pair {
    privd: LinkState,
    other: LinkState,
    worker_link: bool,
}

impl Pair {
    fn worker() -> Self {
        Self {
            privd: LinkState::new(Endpoint::PrivdWorkerLink),
            other: LinkState::new(Endpoint::Worker),
            worker_link: true,
        }
    }

    fn drive() -> Self {
        Self {
            privd: LinkState::new(Endpoint::PrivdDriveLink),
            other: LinkState::new(Endpoint::DriveHelper),
            worker_link: false,
        }
    }

    /// `who` sends; the other end receives. Both must give the same verdict.
    fn msg(&mut self, who: Who, f: pb::RepoFrame) -> Result<(), String> {
        let (tx, rx) = self.ends(who);
        let a = tx.sent_message(&f);
        let b = rx.received_message(&f);
        agree(a, b)
    }

    fn secret(&mut self, who: Who, slot: u8, len: usize) -> Result<(), String> {
        let (tx, rx) = self.ends(who);
        let a = tx.sent_secret(0, slot, len);
        let mut body = 0u64.to_le_bytes().to_vec();
        body.push(slot);
        body.extend(vec![1u8; len]);
        let frame = SecretFrame::from_body(BytesMut::from(&body[..])).unwrap();
        let b = rx.received_secret(&frame);
        agree(a, b)
    }

    fn data(&mut self, who: Who, stream: u64, end: bool, len: usize) -> Result<(), String> {
        let (tx, rx) = self.ends(who);
        let a = tx.sent_data(stream, end, len);
        let frame = DataFrame {
            stream_id: stream,
            end,
            payload: Bytes::from(vec![3u8; len]),
        };
        let b = rx.received_data(&frame);
        agree(a, b)
    }

    fn ends(&mut self, who: Who) -> (&mut LinkState, &mut LinkState) {
        match who {
            Who::Privd => (&mut self.privd, &mut self.other),
            Who::Other => (&mut self.other, &mut self.privd),
        }
    }

    /// The handshake, and on the worker link the job and its secrets.
    fn open(mut self, kind: JobKind) -> Self {
        self.msg(Who::Privd, hello()).unwrap();
        self.msg(Who::Other, ack()).unwrap();
        if self.worker_link {
            self.msg(Who::Privd, job_frame(kind)).unwrap();
            for s in job(kind).secret_slots {
                self.secret(Who::Privd, s.slot as u8, s.length as usize)
                    .unwrap();
            }
        } else {
            self.msg(Who::Privd, req(1, open_repo())).unwrap();
            self.msg(Who::Other, done(1)).unwrap();
        }
        self
    }

    /// The party that sends requests on this link.
    fn requester(&self) -> Who {
        if self.worker_link {
            Who::Other
        } else {
            Who::Privd
        }
    }

    fn responder(&self) -> Who {
        if self.worker_link {
            Who::Privd
        } else {
            Who::Other
        }
    }
}

fn agree(
    a: Result<(), hx_ipc::repo::LinkError>,
    b: Result<(), hx_ipc::repo::LinkError>,
) -> Result<(), String> {
    match (a, b) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(x), Err(_)) => Err(x.to_string()),
        (a, b) => panic!("the two ends disagree: sender {a:?}, receiver {b:?}"),
    }
}

fn err_has(r: Result<(), String>, needle: &str) {
    match r {
        Err(e) => assert!(e.contains(needle), "wanted {needle:?} in {e:?}"),
        Ok(()) => panic!("expected a violation mentioning {needle:?}"),
    }
}

// ----- handshake -----

#[test]
fn handshake_order_and_version() {
    for mut p in [Pair::worker(), Pair::drive()] {
        // Nothing before Hello.
        err_has(p.msg(Who::Other, ack()), "HelloAck out of order");
    }
    for mut p in [Pair::worker(), Pair::drive()] {
        err_has(
            p.msg(Who::Privd, frame(F::Ping(pb::Ping { nonce: 1 }))),
            "handshake",
        );
    }
    for mut p in [Pair::worker(), Pair::drive()] {
        err_has(p.msg(Who::Other, hello()), "Hello from");
    }
    for mut p in [Pair::worker(), Pair::drive()] {
        let wrong = frame(F::Hello(pb::Hello {
            major: 2,
            minor: 0,
            job_id: job_id(),
        }));
        err_has(p.msg(Who::Privd, wrong), "major");
    }
    for mut p in [Pair::worker(), Pair::drive()] {
        p.msg(Who::Privd, hello()).unwrap();
        err_has(p.msg(Who::Privd, hello()), "Hello out of order");
    }
    for mut p in [Pair::worker(), Pair::drive()] {
        p.msg(Who::Privd, hello()).unwrap();
        err_has(p.msg(Who::Privd, ack()), "HelloAck from privd");
    }
    for mut p in [Pair::worker(), Pair::drive()] {
        p.msg(Who::Privd, hello()).unwrap();
        let wrong = frame(F::HelloAck(pb::HelloAck {
            major: 9,
            minor: 0,
            software: String::new(),
        }));
        err_has(p.msg(Who::Other, wrong), "major");
    }
    for mut p in [Pair::worker(), Pair::drive()] {
        p.msg(Who::Privd, hello()).unwrap();
        // Between Hello and HelloAck only the ack passes.
        err_has(
            p.msg(Who::Privd, frame(F::Ping(pb::Ping { nonce: 1 }))),
            "handshake",
        );
    }
    for mut p in [Pair::worker(), Pair::drive()] {
        p.msg(Who::Privd, hello()).unwrap();
        p.msg(Who::Other, ack()).unwrap();
        err_has(p.msg(Who::Other, ack()), "HelloAck out of order");
    }
}

#[test]
fn nothing_passes_after_bye_and_a_violation_poisons_the_link() {
    let mut p = Pair::drive().open(JobKind::Check);
    p.msg(Who::Privd, frame(F::Bye(pb::Bye {}))).unwrap();
    assert!(p.privd.is_closed() && p.other.is_closed());
    err_has(
        p.msg(Who::Other, frame(F::Ping(pb::Ping { nonce: 1 }))),
        "after Bye",
    );

    let mut p = Pair::worker().open(JobKind::Check);
    err_has(p.msg(Who::Other, req(0, list(T::Pack))), "req_id");
    // Poisoned: even a harmless frame now fails.
    assert!(
        p.privd
            .received_message(&frame(F::Ping(pb::Ping { nonce: 1 })))
            .is_err()
    );
    assert!(
        p.privd
            .sent_message(&frame(F::Ping(pb::Ping { nonce: 1 })))
            .is_err()
    );
}

// ----- job and secrets (worker link) -----

#[test]
fn job_then_exactly_the_declared_secrets() {
    for kind in KINDS {
        let mut p = Pair::worker();
        p.msg(Who::Privd, hello()).unwrap();
        // Job before the ack.
        err_has(p.msg(Who::Privd, job_frame(kind)), "handshake");
    }
    for kind in KINDS {
        let mut p = Pair::worker();
        p.msg(Who::Privd, hello()).unwrap();
        p.msg(Who::Other, ack()).unwrap();
        err_has(p.secret(Who::Privd, 0, 32), "before the Job");
        let mut p = Pair::worker();
        p.msg(Who::Privd, hello()).unwrap();
        p.msg(Who::Other, ack()).unwrap();
        p.msg(Who::Privd, job_frame(kind)).unwrap();
        assert!(!p.privd.job_ready());
        assert_eq!(p.privd.job_kind(), Some(kind));
        // A ping may interleave with the secrets; a request may not.
        p.msg(Who::Privd, frame(F::Ping(pb::Ping { nonce: 1 })))
            .unwrap();
        p.msg(Who::Other, frame(F::Pong(pb::Pong { nonce: 1 })))
            .unwrap();
        err_has(
            p.msg(Who::Other, req(1, list(T::Pack))),
            "before the job is ready",
        );
    }
    // Wrong slot, wrong length, too many, in order.
    let mut p = Pair::worker();
    p.msg(Who::Privd, hello()).unwrap();
    p.msg(Who::Other, ack()).unwrap();
    p.msg(Who::Privd, job_frame(JobKind::Init)).unwrap();
    err_has(p.secret(Who::Privd, 1, 32), "out of order");
    let mut p = Pair::worker();
    p.msg(Who::Privd, hello()).unwrap();
    p.msg(Who::Other, ack()).unwrap();
    p.msg(Who::Privd, job_frame(JobKind::Init)).unwrap();
    err_has(p.secret(Who::Privd, 0, 31), "length");
    let mut p = Pair::worker();
    p.msg(Who::Privd, hello()).unwrap();
    p.msg(Who::Other, ack()).unwrap();
    p.msg(Who::Privd, job_frame(JobKind::Check)).unwrap();
    p.secret(Who::Privd, 0, 32).unwrap();
    assert!(p.privd.job_ready());
    err_has(p.secret(Who::Privd, 0, 32), "more than declared");
    // The worker never sends secrets.
    let mut p = Pair::worker().open(JobKind::Check);
    err_has(p.secret(Who::Other, 0, 32), "from the worker");
    // Job: wrong id, a second one, from the worker.
    let mut p = Pair::worker();
    p.msg(Who::Privd, hello()).unwrap();
    p.msg(Who::Other, ack()).unwrap();
    let mut j = job(JobKind::Check);
    j.job_id = Bytes::from(vec![8u8; 16]);
    err_has(p.msg(Who::Privd, frame(F::Job(j))), "job id");
    let mut p = Pair::worker().open(JobKind::Check);
    err_has(p.msg(Who::Privd, job_frame(JobKind::Check)), "second Job");
    let mut p = Pair::worker();
    p.msg(Who::Privd, hello()).unwrap();
    p.msg(Who::Other, ack()).unwrap();
    err_has(
        p.msg(Who::Other, job_frame(JobKind::Check)),
        "Job from the worker",
    );
    // Secrets never cross the Drive link.
    let mut p = Pair::drive().open(JobKind::Check);
    err_has(p.secret(Who::Privd, 0, 32), "Drive link");
}

#[test]
fn the_drive_link_has_no_job_progress_result_or_cancel() {
    for f in [
        job_frame(JobKind::Check),
        frame(F::Progress(pb::Progress {
            phase: 1,
            ..Default::default()
        })),
        result_frame(result_for(JobKind::Check)),
        frame(F::Cancel(pb::Cancel {})),
    ] {
        let mut p = Pair::drive().open(JobKind::Check);
        for who in [Who::Privd, Who::Other] {
            assert!(p.msg(who, f.clone()).is_err());
            p = Pair::drive().open(JobKind::Check);
        }
    }
    // Event only flows Drive helper -> privd; CancelRequest only privd -> Drive helper.
    let ev = frame(F::Event(pb::Event {
        kind: 1,
        until_ms: 0,
    }));
    let mut p = Pair::drive().open(JobKind::Check);
    p.msg(Who::Other, ev.clone()).unwrap();
    err_has(p.msg(Who::Privd, ev), "Event from privd");
    let cr = frame(F::CancelRequest(pb::CancelRequest { req_id: 1 }));
    let mut p = Pair::drive().open(JobKind::Check);
    p.msg(Who::Privd, cr.clone()).unwrap();
    err_has(p.msg(Who::Other, cr), "CancelRequest from");
    // Neither exists on the worker link.
    let mut p = Pair::worker().open(JobKind::Check);
    assert!(
        p.msg(
            Who::Other,
            frame(F::Event(pb::Event {
                kind: 1,
                until_ms: 0
            }))
        )
        .is_err()
    );
    let mut p = Pair::worker().open(JobKind::Check);
    assert!(
        p.msg(
            Who::Privd,
            frame(F::CancelRequest(pb::CancelRequest { req_id: 1 }))
        )
        .is_err()
    );
    // Cancel: privd to the worker, after the job.
    let mut p = Pair::worker().open(JobKind::Check);
    p.msg(Who::Privd, frame(F::Cancel(pb::Cancel {}))).unwrap();
    err_has(
        p.msg(Who::Other, frame(F::Cancel(pb::Cancel {}))),
        "Cancel from the worker",
    );
}

#[test]
fn open_repo_is_the_first_and_only_first_request_of_the_drive_session() {
    let mut p = Pair::drive();
    p.msg(Who::Privd, hello()).unwrap();
    p.msg(Who::Other, ack()).unwrap();
    err_has(p.msg(Who::Privd, req(1, list(T::Config))), "OpenRepo");
    let mut p = Pair::drive();
    p.msg(Who::Privd, hello()).unwrap();
    p.msg(Who::Other, ack()).unwrap();
    p.msg(Who::Privd, req(1, open_repo())).unwrap();
    err_has(p.msg(Who::Privd, req(2, open_repo())), "second OpenRepo");
    // The helper may not send requests.
    let mut p = Pair::drive().open(JobKind::Check);
    err_has(
        p.msg(Who::Other, req(5, list(T::Pack))),
        "request from the responder",
    );
    // And the worker link has no OpenRepo at all, at the tracker level too.
    let mut p = Pair::worker().open(JobKind::Check);
    err_has(p.msg(Who::Other, req(1, open_repo())), "privd-only");
}

// ----- request ids and outstanding limits -----

#[test]
fn request_ids_are_unique_among_live_requests() {
    for mut p in [
        Pair::worker().open(JobKind::Check),
        Pair::drive().open(JobKind::Check),
    ] {
        let r = p.requester();
        let q = if p.worker_link { 1 } else { 2 };
        p.msg(r, req(q, list(T::Pack))).unwrap();
        err_has(p.msg(r, req(q, list(T::Pack))), "already in use");
    }
    // Once answered, a number is free again (and a sender should not reuse it, but the state
    // machine does not depend on that).
    let mut p = Pair::worker().open(JobKind::Check);
    p.msg(Who::Other, req(7, Op::Create(pb::Create {})))
        .unwrap();
    p.msg(Who::Privd, done(7)).unwrap();
    p.msg(Who::Other, req(7, Op::Create(pb::Create {})))
        .unwrap();
}

#[test]
fn at_most_eight_outstanding_requests_and_four_writes() {
    let mut p = Pair::worker().open(JobKind::Backup);
    for i in 1..=8 {
        p.msg(Who::Other, req(i, list(T::Pack))).unwrap();
    }
    assert_eq!(p.privd.outstanding(), 8);
    err_has(
        p.msg(Who::Other, req(9, list(T::Pack))),
        "too many outstanding",
    );

    // Answering one frees a slot.
    let mut p = Pair::worker().open(JobKind::Backup);
    for i in 1..=8 {
        p.msg(Who::Other, req(i, list(T::Pack))).unwrap();
    }
    p.msg(Who::Privd, resp(3, page(T::Pack, 2, true))).unwrap();
    assert_eq!(p.other.outstanding(), 7);
    p.msg(Who::Other, req(9, list(T::Pack))).unwrap();

    // Four writes and four others; a fifth write is refused even though a slot would be free.
    let mut p = Pair::worker().open(JobKind::Backup);
    for i in 1..=4 {
        p.msg(Who::Other, req(i, write(T::Pack, 1, 10))).unwrap();
    }
    assert_eq!(p.privd.outstanding_writes(), 4);
    err_has(
        p.msg(Who::Other, req(5, write(T::Pack, 1, 10))),
        "too many outstanding writes",
    );
    let mut p = Pair::worker().open(JobKind::Backup);
    for i in 1..=4 {
        p.msg(Who::Other, req(i, write(T::Pack, 1, 10))).unwrap();
    }
    for i in 5..=8 {
        p.msg(Who::Other, req(i, list(T::Pack))).unwrap();
    }
    assert_eq!(p.privd.outstanding(), 8);
    // Finishing a write (data, END, Done) admits another.
    p.data(Who::Other, 1, true, 10).unwrap();
    p.msg(Who::Privd, done(1)).unwrap();
    p.msg(Who::Privd, resp(5, page(T::Pack, 0, true))).unwrap();
    p.msg(Who::Other, req(9, write(T::Pack, 1, 10))).unwrap();
}

// ----- upload streams -----

fn upload(p: &mut Pair, id: u64, size: u32) {
    p.msg(p.requester(), req(id, write(T::Pack, 1, size)))
        .unwrap();
}

#[test]
fn an_upload_is_exactly_size_bytes_then_end_then_done() {
    let mut p = Pair::worker().open(JobKind::Backup);
    upload(&mut p, 1, 100);
    p.data(Who::Other, 1, false, 60).unwrap();
    p.data(Who::Other, 1, true, 40).unwrap();
    p.msg(Who::Privd, done(1)).unwrap();
    assert_eq!(p.privd.outstanding(), 0);
    // The stream is finished: more data for it is a violation.
    err_has(p.data(Who::Other, 1, true, 0), "unknown stream");

    // The last bytes may come in a frame without END, followed by an empty END.
    let mut p = Pair::worker().open(JobKind::Backup);
    upload(&mut p, 1, 100);
    p.data(Who::Other, 1, false, 100).unwrap();
    p.data(Who::Other, 1, true, 0).unwrap();
    p.msg(Who::Privd, done(1)).unwrap();

    // A zero-size object is one empty END frame.
    let mut p = Pair::worker().open(JobKind::Backup);
    upload(&mut p, 1, 0);
    p.data(Who::Other, 1, true, 0).unwrap();
    p.msg(Who::Privd, done(1)).unwrap();
}

#[test]
fn upload_violations() {
    // END before size.
    let mut p = Pair::worker().open(JobKind::Backup);
    upload(&mut p, 1, 100);
    p.data(Who::Other, 1, false, 60).unwrap();
    err_has(p.data(Who::Other, 1, true, 39), "END before");
    // Overrun, in one frame and across frames.
    let mut p = Pair::worker().open(JobKind::Backup);
    upload(&mut p, 1, 100);
    err_has(p.data(Who::Other, 1, false, 101), "exceeds");
    let mut p = Pair::worker().open(JobKind::Backup);
    upload(&mut p, 1, 100);
    p.data(Who::Other, 1, false, 100).unwrap();
    err_has(p.data(Who::Other, 1, false, 1), "exceeds");
    let mut p = Pair::worker().open(JobKind::Backup);
    upload(&mut p, 1, 100);
    p.data(Who::Other, 1, false, 99).unwrap();
    err_has(p.data(Who::Other, 1, true, 2), "exceeds");
    // Unknown stream, and a stream id of zero.
    let mut p = Pair::worker().open(JobKind::Backup);
    err_has(p.data(Who::Other, 5, false, 1), "unknown stream");
    let mut p = Pair::worker().open(JobKind::Backup);
    err_has(p.data(Who::Other, 0, false, 1), "zero");
    // An empty frame that does not end the stream would let a peer spin for free.
    let mut p = Pair::worker().open(JobKind::Backup);
    upload(&mut p, 1, 100);
    err_has(p.data(Who::Other, 1, false, 0), "empty data frame");
    // Done before END, and data from the wrong party.
    let mut p = Pair::worker().open(JobKind::Backup);
    upload(&mut p, 1, 100);
    p.data(Who::Other, 1, false, 100).unwrap();
    err_has(p.msg(Who::Privd, done(1)), "before the END");
    let mut p = Pair::worker().open(JobKind::Backup);
    upload(&mut p, 1, 100);
    err_has(p.data(Who::Privd, 1, false, 10), "from the responder");
    // Data for a request that has no stream (a List, a Remove).
    let mut p = Pair::worker().open(JobKind::Backup);
    p.msg(Who::Other, req(1, list(T::Pack))).unwrap();
    err_has(p.data(Who::Other, 1, true, 0), "finished or unopened");
}

#[test]
fn streams_interleave_but_stay_independent() {
    let mut p = Pair::worker().open(JobKind::Backup);
    upload(&mut p, 1, 30);
    upload(&mut p, 2, 20);
    p.data(Who::Other, 1, false, 10).unwrap();
    p.data(Who::Other, 2, false, 10).unwrap();
    p.data(Who::Other, 1, false, 10).unwrap();
    p.data(Who::Other, 2, true, 10).unwrap();
    p.msg(Who::Privd, done(2)).unwrap();
    p.data(Who::Other, 1, true, 10).unwrap();
    p.msg(Who::Privd, done(1)).unwrap();
    assert_eq!(p.privd.outstanding(), 0);
    // A download and an upload at the same time.
    let mut p = Pair::worker().open(JobKind::Backup);
    upload(&mut p, 1, 5);
    p.msg(Who::Other, req(2, read_full(T::Pack, 1))).unwrap();
    p.msg(Who::Privd, resp(2, read_begin(8))).unwrap();
    p.data(Who::Privd, 2, false, 4).unwrap();
    p.data(Who::Other, 1, true, 5).unwrap();
    p.data(Who::Privd, 2, true, 4).unwrap();
    p.msg(Who::Privd, done(1)).unwrap();
    assert_eq!(p.privd.outstanding(), 0);
}

#[test]
fn an_error_aborts_an_upload_and_in_flight_data_is_discarded_never_beyond_size() {
    let mut p = Pair::worker().open(JobKind::Backup);
    upload(&mut p, 1, 100);
    p.data(Who::Other, 1, false, 40).unwrap();
    p.msg(Who::Privd, error(1, pb::ErrorClass::PolicyDenied))
        .unwrap();
    // Still counted until the sender ends the stream: privd is not misled about its slots.
    assert_eq!(p.privd.outstanding(), 1);
    p.data(Who::Other, 1, false, 30).unwrap();
    // An answer for it is not allowed twice.
    err_has(p.msg(Who::Privd, done(1)), "already answered");

    let mut p = Pair::worker().open(JobKind::Backup);
    upload(&mut p, 1, 100);
    p.msg(Who::Privd, error(1, pb::ErrorClass::Transient))
        .unwrap();
    p.data(Who::Other, 1, false, 60).unwrap();
    err_has(p.data(Who::Other, 1, false, 41), "exceeds");

    // END (even short) ends an aborted stream and frees the slot.
    let mut p = Pair::worker().open(JobKind::Backup);
    upload(&mut p, 1, 100);
    p.msg(Who::Privd, error(1, pb::ErrorClass::Transient))
        .unwrap();
    p.data(Who::Other, 1, true, 10).unwrap();
    assert_eq!(p.privd.outstanding(), 0);

    // An Error after the upload completed simply answers it.
    let mut p = Pair::worker().open(JobKind::Backup);
    upload(&mut p, 1, 10);
    p.data(Who::Other, 1, true, 10).unwrap();
    p.msg(Who::Privd, error(1, pb::ErrorClass::Integrity))
        .unwrap();
    assert_eq!(p.privd.outstanding(), 0);
}

// ----- download streams -----

#[test]
fn a_download_is_read_begin_then_exactly_size_bytes_then_end() {
    let mut p = Pair::worker().open(JobKind::Restore);
    p.msg(Who::Other, req(1, read_full(T::Pack, 1))).unwrap();
    p.msg(Who::Privd, resp(1, read_begin(100))).unwrap();
    p.data(Who::Privd, 1, false, 99).unwrap();
    p.data(Who::Privd, 1, true, 1).unwrap();
    assert_eq!(p.other.outstanding(), 0);

    // Violations: short END, overrun, more after END, data from the requester.
    let start = || {
        let mut p = Pair::worker().open(JobKind::Restore);
        p.msg(Who::Other, req(1, read_full(T::Pack, 1))).unwrap();
        p.msg(Who::Privd, resp(1, read_begin(100))).unwrap();
        p
    };
    err_has(start().data(Who::Privd, 1, true, 99), "END before");
    err_has(start().data(Who::Privd, 1, false, 101), "exceeds");
    let mut p = start();
    p.data(Who::Privd, 1, true, 100).unwrap();
    err_has(p.data(Who::Privd, 1, true, 0), "unknown stream");
    err_has(start().data(Who::Other, 1, false, 1), "from the requester");
    // Data before ReadBegin.
    let mut p = Pair::worker().open(JobKind::Restore);
    p.msg(Who::Other, req(1, read_full(T::Pack, 1))).unwrap();
    err_has(p.data(Who::Privd, 1, false, 1), "finished or unopened");
    // A failure after ReadBegin is a closed session, never a second response.
    err_has(
        start().msg(Who::Privd, error(1, pb::ErrorClass::Transient)),
        "already answered",
    );
    err_has(
        start().msg(Who::Privd, resp(1, read_begin(1))),
        "already answered",
    );
    // ... but an Error instead of ReadBegin is the normal failure.
    let mut p = Pair::worker().open(JobKind::Restore);
    p.msg(Who::Other, req(1, read_full(T::Pack, 1))).unwrap();
    p.msg(Who::Privd, error(1, pb::ErrorClass::NotFound))
        .unwrap();
    assert_eq!(p.other.outstanding(), 0);
    // A zero-size object.
    let mut p = Pair::worker().open(JobKind::Restore);
    p.msg(Who::Other, req(1, read_full(T::Pack, 1))).unwrap();
    p.msg(Who::Privd, resp(1, read_begin(0))).unwrap();
    p.data(Who::Privd, 1, true, 0).unwrap();
    assert_eq!(p.other.outstanding(), 0);
}

#[test]
fn read_begin_respects_the_cap_of_the_type_and_the_requested_length() {
    for (ty, cap) in [
        (T::Config, 64 << 10),
        (T::Key, 64 << 10),
        (T::Snapshot, 4 << 20),
        (T::Index, 96 << 20),
        (T::Pack, 96 << 20),
    ] {
        let mut p = Pair::worker().open(JobKind::Restore);
        p.msg(Who::Other, req(1, read_full(ty, 1))).unwrap();
        p.msg(Who::Privd, resp(1, read_begin(cap))).unwrap();
        let mut p = Pair::worker().open(JobKind::Restore);
        p.msg(Who::Other, req(1, read_full(ty, 1))).unwrap();
        err_has(
            p.msg(Who::Privd, resp(1, read_begin(cap + 1))),
            "over the cap",
        );
    }
    let mut p = Pair::worker().open(JobKind::Restore);
    p.msg(Who::Other, req(1, read_partial(T::Pack, 1, 100, 50)))
        .unwrap();
    p.msg(Who::Privd, resp(1, read_begin(50))).unwrap();
    let mut p = Pair::worker().open(JobKind::Restore);
    p.msg(Who::Other, req(1, read_partial(T::Pack, 1, 100, 50)))
        .unwrap();
    err_has(
        p.msg(Who::Privd, resp(1, read_begin(51))),
        "requested length",
    );
    // A shorter answer is fine (the object ends sooner).
    let mut p = Pair::worker().open(JobKind::Restore);
    p.msg(Who::Other, req(1, read_partial(T::Pack, 1, 100, 50)))
        .unwrap();
    p.msg(Who::Privd, resp(1, read_begin(0))).unwrap();
}

// ----- listing -----

#[test]
fn listing_pages_and_the_total_cap() {
    let mut p = Pair::worker().open(JobKind::Check);
    p.msg(Who::Other, req(1, list(T::Pack))).unwrap();
    p.msg(Who::Privd, resp(1, page(T::Pack, 1024, false)))
        .unwrap();
    err_has(
        p.msg(Who::Privd, resp(1, page(T::Pack, 0, false))),
        "empty page",
    );

    let mut p = Pair::worker().open(JobKind::Check);
    p.msg(Who::Other, req(1, list(T::Pack))).unwrap();
    p.msg(Who::Privd, resp(1, page(T::Pack, 3, false))).unwrap();
    p.msg(Who::Privd, resp(1, page(T::Pack, 0, true))).unwrap();
    assert_eq!(p.other.outstanding(), 0);
    err_has(
        p.msg(Who::Privd, resp(1, page(T::Pack, 1, true))),
        "unknown request",
    );

    // 1 000 000 in all, and not one more.
    for (last_page, ok) in [(576usize, true), (577, false)] {
        let mut p = Pair::worker().open(JobKind::Check);
        p.msg(Who::Other, req(1, list(T::Pack))).unwrap();
        for _ in 0..976 {
            p.msg(Who::Privd, resp(1, page(T::Pack, 1024, false)))
                .unwrap();
        }
        let r = p.msg(Who::Privd, resp(1, page(T::Pack, last_page, true)));
        assert_eq!(r.is_ok(), ok, "page of {last_page} after 999 424");
        if !ok {
            err_has(r, "1 000 000");
        }
    }

    // Ids follow the type: all zero for CONFIG, not for the rest; sizes follow its cap.
    let mut p = Pair::worker().open(JobKind::Check);
    p.msg(Who::Other, req(1, list(T::Config))).unwrap();
    p.msg(Who::Privd, resp(1, page(T::Config, 1, true)))
        .unwrap();
    let mut p = Pair::worker().open(JobKind::Check);
    p.msg(Who::Other, req(1, list(T::Config))).unwrap();
    err_has(
        p.msg(Who::Privd, resp(1, page(T::Pack, 1, true))),
        "id does not fit",
    );
    let mut p = Pair::worker().open(JobKind::Check);
    p.msg(Who::Other, req(1, list(T::Pack))).unwrap();
    err_has(
        p.msg(Who::Privd, resp(1, page(T::Config, 1, true))),
        "id does not fit",
    );
    let sized = |size: u32| {
        pb::repo_response::Result::ListPage(pb::ListPage {
            entries: vec![pb::ListEntry { id: id(1), size }],
            last: true,
        })
    };
    let mut p = Pair::worker().open(JobKind::Check);
    p.msg(Who::Other, req(1, list(T::Snapshot))).unwrap();
    p.msg(Who::Privd, resp(1, sized(4 << 20))).unwrap();
    let mut p = Pair::worker().open(JobKind::Check);
    p.msg(Who::Other, req(1, list(T::Snapshot))).unwrap();
    err_has(
        p.msg(Who::Privd, resp(1, sized((4 << 20) + 1))),
        "over the cap",
    );
}

// ----- responses must match their requests -----

#[test]
fn a_response_must_match_its_request() {
    let w = |op: Op| {
        let mut p = Pair::worker().open(JobKind::Backup);
        p.msg(Who::Other, req(1, op)).unwrap();
        p
    };
    err_has(w(list(T::Pack)).msg(Who::Privd, done(1)), "does not match");
    err_has(
        w(Op::Create(pb::Create {})).msg(Who::Privd, resp(1, page(T::Pack, 1, true))),
        "does not match",
    );
    err_has(
        w(remove(T::Index, 1)).msg(Who::Privd, resp(1, read_begin(1))),
        "does not match",
    );
    err_has(
        w(write(T::Pack, 1, 5)).msg(Who::Privd, resp(1, read_begin(1))),
        "does not match",
    );
    err_has(
        w(read_full(T::Pack, 1)).msg(Who::Privd, done(1)),
        "does not match",
    );
    err_has(w(list(T::Pack)).msg(Who::Privd, done(2)), "unknown request");
    err_has(
        w(list(T::Pack)).msg(Who::Other, done(1)),
        "response from the requester",
    );
    // QuotaResult answers only a Quota, and exists only on the Drive link.
    let mut p = Pair::drive().open(JobKind::Check);
    p.msg(Who::Privd, req(2, Op::Quota(pb::Quota {}))).unwrap();
    let q = pb::repo_response::Result::QuotaResult(pb::QuotaResult {
        limit: 1,
        usage: 1,
        usage_in_trash: 0,
    });
    p.msg(Who::Other, resp(2, q.clone())).unwrap();
    let mut p = Pair::drive().open(JobKind::Check);
    p.msg(Who::Privd, req(2, list(T::Pack))).unwrap();
    err_has(p.msg(Who::Other, resp(2, q)), "does not match");
    // Plain operations on the Drive link.
    let mut p = Pair::drive().open(JobKind::Check);
    p.msg(
        Who::Privd,
        req(2, Op::SetUploadRate(pb::SetUploadRate { bytes_per_s: 5 })),
    )
    .unwrap();
    p.msg(Who::Other, done(2)).unwrap();
    p.msg(Who::Privd, req(3, Op::Quota(pb::Quota {}))).unwrap();
    p.msg(Who::Other, error(3, pb::ErrorClass::AuthRevoked))
        .unwrap();
    assert_eq!(p.privd.outstanding(), 0);
}

// ----- progress, result, bye -----

#[test]
fn one_job_result_matching_the_kind_then_bye() {
    for kind in KINDS {
        let mut p = Pair::worker().open(kind);
        p.msg(
            Who::Other,
            frame(F::Progress(pb::Progress {
                phase: 1,
                ..Default::default()
            })),
        )
        .unwrap();
        p.msg(Who::Other, result_frame(result_for(kind))).unwrap();
        assert!(p.privd.result_seen());
        err_has(
            p.msg(Who::Other, result_frame(result_for(kind))),
            "second JobResult",
        );
        let mut p = Pair::worker().open(kind);
        p.msg(Who::Other, result_frame(result_for(kind))).unwrap();
        err_has(
            p.msg(
                Who::Other,
                frame(F::Progress(pb::Progress {
                    phase: 1,
                    ..Default::default()
                })),
            ),
            "after JobResult",
        );
        let mut p = Pair::worker().open(kind);
        p.msg(Who::Other, result_frame(result_for(kind))).unwrap();
        err_has(p.msg(Who::Other, req(1, list(T::Pack))), "after JobResult");
        let mut p = Pair::worker().open(kind);
        p.msg(Who::Other, result_frame(result_for(kind))).unwrap();
        p.msg(Who::Other, frame(F::Bye(pb::Bye {}))).unwrap();
        assert!(p.privd.is_closed());
    }
    // The shape is checked against the kind the Job declared.
    let mut p = Pair::worker().open(JobKind::Backup);
    err_has(
        p.msg(Who::Other, result_frame(result_for(JobKind::Snapshots))),
        "job kind",
    );
    let mut p = Pair::worker().open(JobKind::Backup);
    err_has(p.msg(Who::Other, result_frame(ok_result())), "job kind");
    let mut p = Pair::worker().open(JobKind::Snapshots);
    err_has(
        p.msg(Who::Other, result_frame(result_for(JobKind::Backup))),
        "job kind",
    );
    // A failed job is fine for every kind.
    for kind in KINDS {
        let mut p = Pair::worker().open(kind);
        let failed = pb::JobResult {
            ok: false,
            error: pb::WorkerError::Cancelled as i32,
            ..Default::default()
        };
        p.msg(Who::Other, result_frame(failed)).unwrap();
    }
    // The worker may not say Bye before its result; privd may say it at any time.
    let mut p = Pair::worker().open(JobKind::Check);
    err_has(
        p.msg(Who::Other, frame(F::Bye(pb::Bye {}))),
        "before JobResult",
    );
    let mut p = Pair::worker().open(JobKind::Check);
    p.msg(Who::Privd, frame(F::Bye(pb::Bye {}))).unwrap();
    // No result or progress before the secrets are in.
    let mut p = Pair::worker();
    p.msg(Who::Privd, hello()).unwrap();
    p.msg(Who::Other, ack()).unwrap();
    p.msg(Who::Privd, job_frame(JobKind::Check)).unwrap();
    err_has(
        p.msg(Who::Other, result_frame(result_for(JobKind::Check))),
        "before the job is ready",
    );
    // Pending requests may outlive the result (privd just stops answering them).
    let mut p = Pair::worker().open(JobKind::Check);
    p.msg(Who::Other, req(1, list(T::Pack))).unwrap();
    p.msg(Who::Other, result_frame(result_for(JobKind::Check)))
        .unwrap();
}

// ----- properties -----

#[derive(Debug, Clone)]
enum Step {
    Request(u64, u8),
    Answer(u64, u8),
    Data(u64, bool, u8),
    Cancel(u64),
    Ping,
}

fn arb_step() -> impl Strategy<Value = Step> {
    prop_oneof![
        (1u64..14, 0u8..6).prop_map(|(i, k)| Step::Request(i, k)),
        (1u64..14, 0u8..4).prop_map(|(i, k)| Step::Answer(i, k)),
        (1u64..14, any::<bool>(), 0u8..40).prop_map(|(i, e, n)| Step::Data(i, e, n)),
        (1u64..14).prop_map(Step::Cancel),
        Just(Step::Ping),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Whatever the sequence, the two ends agree, the limits hold, and an error poisons both.
    #[test]
    fn random_traffic_keeps_the_limits_and_both_ends_in_agreement(steps in proptest::collection::vec(arb_step(), 0..60), drive: bool) {
        let mut p = if drive { Pair::drive() } else { Pair::worker() }.open(JobKind::Backup);
        let mut failed = false;
        for s in steps {
            let r = match s {
                Step::Request(i, k) => {
                    let op = match k {
                        0 => list(T::Pack),
                        1 => write(T::Pack, 1, 20),
                        2 => read_full(T::Pack, 1),
                        3 => remove(T::Index, 1),
                        4 => Op::Create(pb::Create {}),
                        _ => write(T::Index, 2, 0),
                    };
                    let r = p.requester();
                    p.msg(r, req(i + 10, op))
                }
                Step::Answer(i, k) => {
                    let r = p.responder();
                    let res = match k {
                        0 => done(i + 10),
                        1 => error(i + 10, pb::ErrorClass::Transient),
                        2 => resp(i + 10, read_begin(20)),
                        _ => resp(i + 10, page(T::Pack, 1, true)),
                    };
                    p.msg(r, res)
                }
                Step::Data(i, end, n) => {
                    let who = if i % 2 == 0 { p.requester() } else { p.responder() };
                    p.data(who, i + 10, end, usize::from(n))
                }
                Step::Cancel(i) => {
                    if p.worker_link {
                        p.msg(Who::Privd, frame(F::Cancel(pb::Cancel {})))
                    } else {
                        p.msg(Who::Privd, frame(F::CancelRequest(pb::CancelRequest { req_id: i + 10 })))
                    }
                }
                Step::Ping => p.msg(Who::Privd, frame(F::Ping(pb::Ping { nonce: 1 }))),
            };
            if failed {
                prop_assert!(r.is_err(), "a poisoned link accepted a frame");
            }
            failed |= r.is_err();
            prop_assert!(p.privd.outstanding() <= 8);
            prop_assert!(p.privd.outstanding_writes() <= 4);
            prop_assert_eq!(p.privd.outstanding(), p.other.outstanding());
        }
    }

    /// An upload of `size` bytes in any chunking is valid exactly when the chunks add up to
    /// `size` and the last one carries END.
    #[test]
    fn upload_chunking(size in 0u32..500, cuts in proptest::collection::vec(1u32..120, 0..10), end_early: bool) {
        let mut p = Pair::worker().open(JobKind::Backup);
        upload(&mut p, 1, size);
        let mut sent = 0u32;
        let mut ok = true;
        for c in cuts {
            if sent + c > size { break; }
            if p.data(Who::Other, 1, false, c as usize).is_err() { ok = false; break; }
            sent += c;
        }
        prop_assert!(ok);
        let rest = size - sent;
        if end_early && rest > 0 {
            prop_assert!(p.data(Who::Other, 1, true, (rest - 1) as usize).is_err());
        } else {
            p.data(Who::Other, 1, true, rest as usize).unwrap();
            p.msg(Who::Privd, done(1)).unwrap();
            prop_assert_eq!(p.privd.outstanding(), 0);
        }
    }

    /// Arbitrary decoded frames never panic a tracker (and never bypass its poisoning).
    #[test]
    fn arbitrary_valid_frames_never_panic_the_tracker(i in 0usize..32, j in 0usize..32, k in 0usize..4) {
        let frames = every_frame();
        let e = ALL[k];
        let mut s = LinkState::new(e);
        let mut failed = false;
        for idx in [i, j, i, j] {
            let (_, f, to) = &frames[idx];
            if !to.contains(&e) { continue; }
            let r = s.received(&Incoming::Message(f.clone()));
            if failed { prop_assert!(r.is_err()); }
            failed |= r.is_err();
        }
    }
}
