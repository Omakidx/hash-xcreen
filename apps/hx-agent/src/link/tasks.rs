//! The tasks of a running link: three lane readers, two writers and a maintenance task.
//!
//! Each reader owns one lane and nothing else (`docs/ipc.md` section 17, point 4: cursor,
//! `stream_format`, `cancel_frames` and statistics are parsed in a task separate from the media
//! and bulk readers). A task that ends for any reason ends the link: the first failure wins and
//! is classified (violation, fault, closed) for the reconnect policy.
//!
//! The rules of section 19.1 are applied here, in the order the data arrives:
//!
//! 1. lengths are checked before any allocation (the framing decoder, in [`super::lane`]);
//! 2. integers are range-checked (`parse`, `validate`, the checks below);
//! 3. session text is sanitised and only logged, never forwarded to a client;
//! 4. cursor, transfer-header and file-name content gets the client-protocol validation;
//! 5. unknown variants are ignored and counted, undecodable bodies are violations;
//! 6. rates are enforced per message class;
//! 7. nothing secret is ever sent;
//! 8. no descriptors (`recvmsg`, see [`super::lane`]).

use super::annexb;
use super::lane::{LaneFail, LaneReader, WriteFail, write_all_stall};
use super::shared::{BulkOut, InXfer, Pop, Shared, Staged, lock};
use super::types::{
    FailureClass, Frame, LinkEvent, SessionEvent, StreamFormat, TransferChunk, TransferEvent,
};
use hx_ipc::link::frames::{
    LinkFrame, encode_gateway_message, encode_transfer_abort, encode_transfer_data_prefix, parse,
};
use hx_ipc::link::validate::{check_cancel_frames, check_stream_format, sanitize_text};
use hx_ipc::link::{MAX_TRANSFER_CHUNK, pb};
use hx_proto::channel::{RESET_TRANSFER_ERROR, STOP_TRANSFER_REJECTED};
use hx_proto::order::serial_gt;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

type Fail = (FailureClass, String);

fn violation(why: impl Into<String>) -> Fail {
    (FailureClass::Violation, why.into())
}

fn lane_fail(name: &str, f: LaneFail) -> Fail {
    let class = match f {
        LaneFail::Violation(_) => FailureClass::Violation,
        _ => FailureClass::Fault,
    };
    (class, format!("{name} lane: {}", f.text()))
}

/// Runs `body` until it fails or the link ends elsewhere; a failure ends the link.
async fn run<F: std::future::Future<Output = Fail>>(sh: &Arc<Shared>, body: F) {
    tokio::select! {
        () = sh.wait_closed() => {}
        (class, detail) = body => sh.fail(class, detail),
    }
}

// ----- ctl reader -----

pub(crate) async fn ctl_reader(sh: Arc<Shared>, mut lane: LaneReader) {
    let s = sh.clone();
    run(&sh, async move { ctl_loop(&s, &mut lane).await }).await;
}

async fn ctl_loop(sh: &Arc<Shared>, lane: &mut LaneReader) -> Fail {
    loop {
        let raw = match lane.next().await {
            Ok(r) => r,
            Err(f) => return lane_fail("ctl", f),
        };
        let frame = match parse(lane.policy(), raw, u64::MAX) {
            Ok(f) => f,
            Err(e) => return violation(format!("ctl lane: {e}")),
        };
        match frame {
            LinkFrame::UnknownVariant => {
                // A negotiated peer never sends one; a trickle is tolerated, a flood is abuse.
                if !lock(&sh.events_rl).unknown.allow(Instant::now()) {
                    return violation("too many ctl frames of unknown variants");
                }
                sh.count(|c| c.unknown_variants += 1);
            }
            LinkFrame::FromSession(m) => {
                if let Err(f) = on_session_message(sh, m) {
                    return f;
                }
            }
            _ => return violation("unexpected frame on ctl"),
        }
    }
}

fn on_session_message(sh: &Arc<Shared>, m: pb::SessionToGateway) -> Result<(), Fail> {
    use pb::session_to_gateway::Message as M;
    let Some(m) = m.message else { return Ok(()) };
    let now = Instant::now();
    match m {
        M::Info(_) => return Err(violation("a second info on ctl")),
        M::StreamFormat(f) => on_stream_format(sh, &f, now),
        M::Cursor(c) => on_cursor(sh, c, now),
        M::CancelFrames(c) => on_cancel(sh, c.up_to_frame, now),
        M::Stats(s) => {
            if lock(&sh.events_rl).stats.allow(now) {
                sh.inbox.push_event(LinkEvent::Stats(s));
            } else {
                sh.count(|c| c.dropped_stats_events += 1);
            }
        }
        M::Event(e) => {
            if lock(&sh.events_rl).event.allow(now) {
                let kind = pb::EventKind::try_from(e.kind).unwrap_or(pb::EventKind::Unspecified);
                // Session text goes to logs only, sanitised again here: defence in depth.
                let message = sanitize_text(&e.message, hx_ipc::link::validate::MAX_MESSAGE_LEN);
                sh.inbox
                    .push_event(LinkEvent::Event(SessionEvent { kind, message }));
            } else {
                sh.count(|c| c.dropped_stats_events += 1);
            }
        }
        M::Pong(p) => on_pong(sh, p.nonce, now)?,
        M::Goodbye(g) => {
            sh.inbox
                .push_event(LinkEvent::SessionGoodbye { code: g.code });
            return Err((
                FailureClass::SessionGoodbye,
                "the session said goodbye".into(),
            ));
        }
    }
    Ok(())
}

fn on_stream_format(sh: &Arc<Shared>, f: &pb::StreamFormat, now: Instant) {
    if !lock(&sh.events_rl).stream_format.allow(now) {
        sh.count(|c| c.bad_stream_formats += 1);
        return;
    }
    let newest = lock(&sh.video).newest;
    if check_stream_format(f, newest, &sh.negotiated).is_err() {
        sh.count(|c| c.bad_stream_formats += 1);
        return;
    }
    // `check_stream_format` accepted the codec, so the conversion cannot fail.
    let Ok(codec) = hx_proto::VideoCodec::try_from(f.codec) else {
        return;
    };
    let fmt = StreamFormat {
        epoch: f.epoch,
        codec,
        width: f.width,
        height: f.height,
        fps: f.fps,
        first_frame: f.first_frame,
    };
    lock(&sh.formats).push(fmt);
    sh.fmt_notify.notify_waiters();
    if sh.inbox.push_event(LinkEvent::StreamFormat(fmt)) {
        sh.count(|c| c.dropped_events += 1);
    }
}

fn on_cursor(sh: &Arc<Shared>, c: hx_proto::pb::CursorEvent, now: Instant) {
    use hx_proto::pb::cursor_event::Event;
    match c.event {
        Some(Event::Position(p)) => sh.inbox.push_position(p),
        Some(Event::Shape(shape)) => {
            // At most 20 shapes and 4 MiB of shape data per second; the excess is dropped.
            let bytes = shape.rgba.len();
            let mut r = lock(&sh.cursor_rl);
            while r
                .shape_bytes
                .front()
                .is_some_and(|(t, _)| now.duration_since(*t) >= Duration::from_secs(1))
            {
                r.shape_bytes.pop_front();
            }
            let used: usize = r.shape_bytes.iter().map(|(_, b)| *b).sum();
            let within = used + bytes <= hx_ipc::link::budget::CURSOR_SHAPE_BYTES_PER_SEC as usize;
            if within && r.shapes.allow(now) {
                r.shape_bytes.push_back((now, bytes));
                drop(r);
                let dropped = sh.inbox.push_shape(shape);
                if dropped > 0 {
                    sh.count(|c| c.dropped_shapes += dropped as u64);
                }
            } else {
                drop(r);
                sh.count(|c| c.dropped_shapes += 1);
            }
        }
        None => {}
    }
}

fn on_cancel(sh: &Arc<Shared>, up_to: u32, now: Instant) {
    let newest = lock(&sh.video).newest;
    let valid = newest.is_some_and(|n| check_cancel_frames(up_to, n));
    if !valid || !lock(&sh.events_rl).cancel.allow(now) {
        sh.count(|c| c.ignored_cancels += 1);
        return;
    }
    // Frames still queued here are cancelled right away; the decode chain is broken, so
    // everything is discarded until the next `KEY | RESYNC` frame.
    let gone = sh.inbox.cancel_frames_up_to(up_to);
    sh.report_frames(&gone, pb::FrameOutcome::Cancelled);
    lock(&sh.video).gate_armed = true;
    sh.inbox
        .push_event(LinkEvent::CancelFrames { up_to_frame: up_to });
}

fn on_pong(sh: &Arc<Shared>, nonce: u64, now: Instant) -> Result<(), Fail> {
    let mut p = lock(&sh.pings);
    if !p.pong_rl.allow(now) {
        return Err(violation("more than 10 pongs per second"));
    }
    match p.pending.iter().position(|(n, _)| *n == nonce) {
        Some(i) => {
            if let Some((_, sent)) = p.pending.remove(i) {
                p.rtt_us = u32::try_from(now.duration_since(sent).as_micros()).unwrap_or(u32::MAX);
            }
        }
        // A nonce the gateway did not send, or a second pong for the same ping.
        None => sh.count(|c| c.unexpected_pongs += 1),
    }
    Ok(())
}

// ----- media reader -----

pub(crate) async fn media_reader(sh: Arc<Shared>, mut lane: LaneReader) {
    let s = sh.clone();
    run(&sh, async move { media_loop(&s, &mut lane).await }).await;
}

async fn media_loop(sh: &Arc<Shared>, lane: &mut LaneReader) -> Fail {
    loop {
        let raw = match lane.next().await {
            Ok(r) => r,
            Err(f) => return lane_fail("media", f),
        };
        let frame = match parse(lane.policy(), raw, u64::MAX) {
            Ok(f) => f,
            Err(e) => return violation(format!("media lane: {e}")),
        };
        match frame {
            LinkFrame::Video(v) => {
                if let Err(f) = on_video(sh, v).await {
                    return f;
                }
            }
            // Audio is reserved: the AUDIO feature is never negotiated in Phase 1.
            LinkFrame::Audio(_) => return violation("audio frame, but audio was not negotiated"),
            _ => return violation("unexpected frame on media"),
        }
    }
}

/// How long a key frame waits for its `stream_format` (the lanes race).
const FORMAT_WAIT: Duration = Duration::from_secs(2);

/// The format in force for frame `n`. The lanes race, so a key frame can arrive before the
/// `stream_format` that announces its (new) size: a key frame waits, within [`FORMAT_WAIT`],
/// until the format in force for it matches the size its SPS announces. A frame that still
/// does not match then, or any other frame without a format, is a violation.
async fn format_for(
    sh: &Arc<Shared>,
    n: u32,
    key: bool,
    sps: Option<(u32, u32)>,
) -> Result<Arc<StreamFormat>, Fail> {
    let deadline = tokio::time::Instant::now() + FORMAT_WAIT;
    loop {
        let notified = sh.fmt_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let (found, any) = {
            let f = lock(&sh.formats);
            (f.in_force(n), !f.is_empty())
        };
        let mismatch = |f: &StreamFormat, d: (u32, u32)| {
            violation(format!(
                "the SPS announces {}x{} but stream_format says {}x{}",
                d.0, d.1, f.width, f.height
            ))
        };
        match (&found, key, sps) {
            (Some(f), _, Some(d)) if (f.width, f.height) != d => {
                // An SPS in a frame that is not a key frame is never waited for.
                if !key {
                    return Err(mismatch(f, d));
                }
                // Possibly the announcement is still in flight on ctl.
                if timeout(
                    deadline.saturating_duration_since(tokio::time::Instant::now()),
                    notified,
                )
                .await
                .is_err()
                {
                    return Err(mismatch(f, d));
                }
            }
            (Some(f), _, _) => return Ok(f.clone()),
            (None, false, _) => {
                return Err(violation(if any {
                    "a frame older than every announced stream_format"
                } else {
                    "a frame before any stream_format"
                }));
            }
            (None, true, _) => {
                if timeout(
                    deadline.saturating_duration_since(tokio::time::Instant::now()),
                    notified,
                )
                .await
                .is_err()
                {
                    return Err(violation("a key frame without a stream_format"));
                }
            }
        }
    }
}

/// Validates one video frame (`docs/ipc.md` 15.1) and queues it for the consumer.
/// `Err` is a violation; rate overages and stale frames are dropped and counted.
async fn on_video(sh: &Arc<Shared>, v: hx_ipc::link::frames::VideoFrame) -> Result<(), Fail> {
    let h = v.header;
    let (n, key) = (h.frame_number, h.is_key());
    let now = Instant::now();
    if !sh.negotiated.contains(&h.codec) {
        return Err(violation("a frame in a codec that was not negotiated"));
    }
    // The bitstream sanity check: Annex B structure, and on a key frame the SPS size.
    let checked = annexb::check_frame(v.payload(), key)
        .map_err(|e| violation(format!("bitstream check: {e}")))?;
    {
        let mut st = lock(&sh.video);
        // Sustained attempts far beyond the allowed rate are a flood, not a busy desktop.
        if !st.attempts_rl.allow(now) {
            return Err(violation("video frame flood"));
        }
        if st.newest.is_some_and(|newest| !serial_gt(n, newest)) {
            drop(st);
            sh.count(|c| c.stale_frames += 1);
            return Ok(());
        }
        st.newest = Some(n);
        let within = st.frames_rl.allow(now);
        let idr_ok = !key || st.idr_rl.allow(now);
        if !within || !idr_ok {
            drop(st);
            sh.count(|c| c.rate_limited_frames += 1);
            sh.report_frames(&[n], pb::FrameOutcome::Dropped);
            sh.arm_resync();
            return Ok(());
        }
    }
    // The rest needs the stream_format, which may still be in flight on ctl: park the frame
    // for the staging task. This reader never waits (docs/ipc.md 15.2).
    let evicted = sh.inbox.stage_frame(
        Staged {
            frame: v,
            sps: checked.sps,
            received_at: now,
        },
        sh.cfg.video_pool_bytes(),
    );
    if !evicted.is_empty() {
        sh.count(|c| c.evicted_frames += evicted.len() as u64);
        sh.report_frames(&evicted, pb::FrameOutcome::Dropped);
        sh.arm_resync();
    }
    Ok(())
}

/// The staging task: resolves each parked frame's stream format (a key frame waits, within
/// [`FORMAT_WAIT`], for the announcement that may still be in flight), then applies the epoch
/// filter and the resync gate and queues the frame for the consumer. Only this task waits; the
/// media reader keeps draining the lane.
pub(crate) async fn video_stage(sh: Arc<Shared>) {
    let s = sh.clone();
    run(&sh, async move {
        loop {
            let wake = s.inbox.staged_wake.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            match s.inbox.take_staged() {
                Some(st) => {
                    if let Err(f) = process_staged(&s, st).await {
                        return f;
                    }
                }
                None => wake.await,
            }
        }
    })
    .await;
}

async fn process_staged(sh: &Arc<Shared>, st: Staged) -> Result<(), Fail> {
    let Staged {
        frame: v,
        sps,
        received_at: now,
    } = st;
    let h = v.header;
    let (n, key) = (h.frame_number, h.is_key());
    let fmt = format_for(sh, n, key, sps.map(|s| (s.width, s.height))).await?;
    if let Some(sps) = sps
        && (sps.width, sps.height) != (fmt.width, fmt.height)
    {
        return Err(violation(format!(
            "the SPS announces {}x{} but stream_format says {}x{}",
            sps.width, sps.height, fmt.width, fmt.height
        )));
    }
    // Only the current client's frames are forwarded.
    if !sh.epoch_set.load(Relaxed) || fmt.epoch != sh.epoch.load(Relaxed) {
        sh.count(|c| c.discarded_frames += 1);
        sh.report_frames(&[n], pb::FrameOutcome::Dropped);
        return Ok(());
    }
    // After a cancel or drop, only a fresh full image restarts the chain.
    {
        let mut st = lock(&sh.video);
        if st.gate_armed {
            if key && h.is_resync() {
                st.gate_armed = false;
            } else {
                drop(st);
                sh.count(|c| c.discarded_frames += 1);
                sh.report_frames(&[n], pb::FrameOutcome::Dropped);
                return Ok(());
            }
        }
    }
    let frame = Frame {
        header: h,
        format: fmt,
        received_at: now,
        body: v.body,
    };
    let evicted = sh.inbox.push_frame(frame, sh.cfg.video_pool_bytes());
    if !evicted.is_empty() {
        sh.count(|c| c.evicted_frames += evicted.len() as u64);
        sh.report_frames(&evicted, pb::FrameOutcome::Dropped);
        sh.arm_resync();
    }
    Ok(())
}

// ----- bulk reader -----

pub(crate) async fn bulk_reader(sh: Arc<Shared>, mut lane: LaneReader) {
    let s = sh.clone();
    run(&sh, async move { bulk_loop(&s, &mut lane).await }).await;
}

fn abort_frame(sh: &Shared, id: u32, code: u32) {
    if let Ok(f) = encode_transfer_abort(id, code) {
        sh.queue_abort(f);
    }
}

async fn bulk_loop(sh: &Arc<Shared>, lane: &mut LaneReader) -> Fail {
    loop {
        let raw = match lane.next().await {
            Ok(r) => r,
            Err(f) => return lane_fail("bulk", f),
        };
        // The file-size limit is a refusal, not a violation: it is applied below.
        let frame = match parse(lane.policy(), raw, u64::MAX) {
            Ok(f) => f,
            Err(e) => return violation(format!("bulk lane: {e}")),
        };
        if let Err(f) = on_bulk(sh, frame) {
            return f;
        }
    }
}

fn on_bulk(sh: &Arc<Shared>, frame: LinkFrame) -> Result<(), Fail> {
    match frame {
        LinkFrame::TransferOpen(open) => on_open(sh, open),
        LinkFrame::TransferData { id, data } => {
            let mut x = lock(&sh.xfer);
            let Some(t) = x.incoming.get_mut(&id) else {
                return if x.recent.contains(&id) {
                    Ok(())
                } else {
                    Err(violation("data for an unknown transfer"))
                };
            };
            t.got = t.got.saturating_add(data.len() as u64);
            if t.got > t.size {
                x.incoming.remove(&id);
                x.remember(id);
                drop(x);
                abort_transfer_inner(sh, id, RESET_TRANSFER_ERROR);
                return Ok(());
            }
            drop(x);
            let credit = sh.credits.acquire(id, data.len());
            let ev = TransferEvent::Data(TransferChunk {
                id,
                data,
                _credit: credit,
            });
            if !sh.inbox.push_transfer(ev) {
                return Err((
                    FailureClass::Fault,
                    "the consumer stopped reading transfers".into(),
                ));
            }
            Ok(())
        }
        LinkFrame::TransferEnd { id } => {
            let mut x = lock(&sh.xfer);
            let Some(t) = x.incoming.remove(&id) else {
                return if x.recent.contains(&id) {
                    Ok(())
                } else {
                    Err(violation("end of an unknown transfer"))
                };
            };
            if t.got != t.size {
                x.remember(id);
                drop(x);
                abort_transfer_inner(sh, id, RESET_TRANSFER_ERROR);
                return Ok(());
            }
            x.remember(id);
            drop(x);
            sh.credits.forget(id);
            push_transfer(sh, TransferEvent::End { id })
        }
        LinkFrame::TransferAbort { id, code } => {
            let mut x = lock(&sh.xfer);
            if x.incoming.remove(&id).is_some() {
                drop(x);
                sh.credits.forget(id);
                return push_transfer(
                    sh,
                    TransferEvent::Aborted {
                        id,
                        code,
                        outgoing: false,
                    },
                );
            }
            if x.outgoing.contains_key(&id) {
                x.out_aborted.insert(id);
                drop(x);
                return push_transfer(
                    sh,
                    TransferEvent::Aborted {
                        id,
                        code,
                        outgoing: true,
                    },
                );
            }
            // An abort for something already finished: nothing to do.
            Ok(())
        }
        _ => Err(violation("unexpected frame on bulk")),
    }
}

fn push_transfer(sh: &Arc<Shared>, ev: TransferEvent) -> Result<(), Fail> {
    if sh.inbox.push_transfer(ev) {
        Ok(())
    } else {
        Err((
            FailureClass::Fault,
            "the consumer stopped reading transfers".into(),
        ))
    }
}

/// Aborts an incoming transfer the gateway gives up on: tells the session, tells the consumer.
fn abort_transfer_inner(sh: &Arc<Shared>, id: u32, code: u32) {
    abort_frame(sh, id, code);
    sh.credits.forget(id);
    if !sh.inbox.push_transfer(TransferEvent::Aborted {
        id,
        code,
        outgoing: false,
    }) {
        sh.fail(
            FailureClass::Fault,
            "the consumer stopped reading transfers",
        );
    }
}

fn on_open(sh: &Arc<Shared>, open: pb::TransferOpen) -> Result<(), Fail> {
    let header = open.header.clone().unwrap_or_default();
    let channel = pb::TransferChannel::try_from(open.channel)
        .map_err(|_| violation("unknown transfer channel"))?;
    let clipboard = channel == pb::TransferChannel::Clipboard;
    let mut x = lock(&sh.xfer);
    if x.incoming.contains_key(&open.id) {
        return Err(violation("transfer id already in use"));
    }
    x.recent.retain(|r| *r != open.id);
    // Policy and limits refuse the transfer; the lane continues.
    let allowed = if clipboard {
        sh.clipboard_allowed.load(Relaxed)
    } else {
        sh.files_allowed.load(Relaxed) && header.size <= sh.cfg.max_file_bytes
    };
    let refuse = |x: &mut super::shared::XferState| {
        x.remember(open.id);
    };
    if !allowed {
        refuse(&mut x);
        drop(x);
        sh.count(|c| c.refused_transfers += 1);
        abort_frame(sh, open.id, STOP_TRANSFER_REJECTED);
        return Ok(());
    }
    if clipboard {
        // At most 4 clipboard transfers per second from the session.
        if !x
            .clipboard_rl
            .as_mut()
            .is_some_and(|r| r.allow(Instant::now()))
        {
            refuse(&mut x);
            drop(x);
            sh.count(|c| c.refused_transfers += 1);
            abort_frame(sh, open.id, STOP_TRANSFER_REJECTED);
            return Ok(());
        }
        // One clipboard transfer at a time: a new one aborts the previous.
        let old: Vec<u32> = x
            .incoming
            .iter()
            .filter(|(_, t)| t.clipboard)
            .map(|(id, _)| *id)
            .collect();
        for id in old {
            x.incoming.remove(&id);
            x.remember(id);
            drop(x);
            abort_transfer_inner(sh, id, RESET_TRANSFER_ERROR);
            x = lock(&sh.xfer);
        }
    }
    if x.incoming.len() >= 4 {
        refuse(&mut x);
        drop(x);
        sh.count(|c| c.refused_transfers += 1);
        abort_frame(sh, open.id, STOP_TRANSFER_REJECTED);
        return Ok(());
    }
    x.incoming.insert(
        open.id,
        InXfer {
            size: header.size,
            got: 0,
            clipboard,
        },
    );
    drop(x);
    push_transfer(
        sh,
        TransferEvent::Open {
            id: open.id,
            channel,
            header,
        },
    )
}

/// The consumer refuses or abandons an incoming transfer.
pub(crate) fn abort_incoming(sh: &Arc<Shared>, id: u32, code: u32) {
    let mut x = lock(&sh.xfer);
    if x.incoming.remove(&id).is_some() {
        x.remember(id);
        drop(x);
        abort_frame(sh, id, code);
        sh.credits.forget(id);
    }
}

// ----- writers -----

pub(crate) async fn ctl_writer(sh: Arc<Shared>, stream: Arc<UnixStream>) {
    let s = sh.clone();
    run(&sh, async move {
        loop {
            let notified = s.out.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match s.out.pop(Instant::now()) {
                Pop::Frame(f) => {
                    if let Err(e) = write_all_stall(&stream, &f, s.cfg.ctl_write_stall).await {
                        return write_fail("ctl", &e);
                    }
                }
                Pop::Wait(until) => {
                    let d = until.saturating_duration_since(Instant::now());
                    let _ = timeout(d, notified).await;
                }
                Pop::Empty => notified.await,
            }
        }
    })
    .await;
}

fn write_fail(name: &str, e: &WriteFail) -> Fail {
    match e {
        WriteFail::Stall => (
            FailureClass::Fault,
            format!("{name} write stalled: the session is not reading"),
        ),
        WriteFail::Io(e) => (FailureClass::Fault, format!("{name} write failed: {e}")),
    }
}

pub(crate) async fn bulk_writer(
    sh: Arc<Shared>,
    stream: Arc<UnixStream>,
    mut rx: mpsc::Receiver<BulkOut>,
) {
    let s = sh.clone();
    run(&sh, async move {
        loop {
            // Aborts first, whatever the upload is doing.
            let wake = s.abort_wake.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            while let Some(a) = s.pop_abort() {
                if let Err(e) = write_all_stall(&stream, &a, s.cfg.bulk_write_stall).await {
                    return write_fail("bulk", &e);
                }
            }
            let out = tokio::select! {
                biased;
                () = &mut wake => continue,
                out = rx.recv() => match out {
                    Some(o) => o,
                    None => break,
                },
            };
            let r = match out {
                BulkOut::Frame(f) => write_all_stall(&stream, &f, s.cfg.bulk_write_stall).await,
                BulkOut::Data { id, data } => {
                    let mut r = Ok(());
                    for chunk in data.chunks(MAX_TRANSFER_CHUNK) {
                        let Ok(prefix) = encode_transfer_data_prefix(id, chunk.len()) else {
                            return violation("cannot encode a transfer data frame");
                        };
                        r = write_all_stall(&stream, &prefix, s.cfg.bulk_write_stall).await;
                        if r.is_ok() {
                            r = write_all_stall(&stream, chunk, s.cfg.bulk_write_stall).await;
                        }
                        if r.is_err() {
                            break;
                        }
                    }
                    r
                }
            };
            if let Err(e) = r {
                return write_fail("bulk", &e);
            }
        }
        (FailureClass::Closed, "bulk writer closed".into())
    })
    .await;
}

// ----- maintenance -----

/// Pings every 2 s, retries a refused IDR request and nothing else; liveness itself is the idle
/// limit of the `ctl` reader.
pub(crate) async fn maintenance(sh: Arc<Shared>) {
    let s = sh.clone();
    run(&sh, async move {
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let now = Instant::now();
            let ping = {
                let mut p = lock(&s.pings);
                if now.duration_since(p.last_ping) >= s.cfg.ping_interval {
                    p.last_ping = now;
                    let nonce = p.next_nonce;
                    p.next_nonce = p.next_nonce.wrapping_add(1);
                    if p.pending.len() >= 8 {
                        p.pending.pop_front();
                    }
                    p.pending.push_back((nonce, now));
                    Some(nonce)
                } else {
                    None
                }
            };
            if let Some(nonce) = ping {
                s.send_p1(pb::gateway_to_session::Message::Ping(pb::Ping { nonce }));
            }
            let retry = lock(&s.video).idr_retry;
            if retry {
                s.request_idr();
            }
        }
    })
    .await;
}

/// Encodes one gateway message for the queues; shared by the client API.
pub(crate) fn encode(m: pb::gateway_to_session::Message) -> Result<Vec<u8>, String> {
    encode_gateway_message(&pb::GatewayToSession { message: Some(m) }).map_err(|e| e.to_string())
}
