//! Dialling a desktop: three lanes, the preamble on each, `info`, negotiation.
//!
//! The classification of what can go wrong follows the behaviours the proxy spike found
//! (`docs/spikes/1c-proxy-device.md`): a stale host socket gives `ECONNREFUSED`, and a connect
//! that the proxy cannot complete on the container side is reset right after it is accepted
//! (`ECONNRESET`, `EPIPE` or an end of stream on the first read or write). Both are
//! [`FailureClass::Unavailable`], "the session is not available", never a violation.

use super::config::LinkConfig;
use super::lane::{LaneFail, LaneReader, gateway_policy, read_exact, write_all_stall};
use super::shared::{BulkOut, Shared};
use super::tasks;
use super::types::{ConnectError, FailureClass, SessionInfo};
use hx_ipc::link::frames::{LinkFrame, parse};
use hx_ipc::link::preamble::{ClientPreamble, PREAMBLE_LEN, Preamble, PreambleError};
use hx_ipc::link::{Lane, pb};
use hx_ipc::text::sanitize_text;
use hx_proto::VideoCodec;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout, timeout_at};

fn unavailable(detail: impl Into<String>) -> ConnectError {
    ConnectError::new(FailureClass::Unavailable, detail)
}

fn from_lane(name: &str, f: LaneFail) -> ConnectError {
    match f {
        LaneFail::Violation(v) => {
            ConnectError::new(FailureClass::Violation, format!("{name}: {v}"))
        }
        other => unavailable(format!("{name}: {}", other.text())),
    }
}

/// One lane: connect, send the preamble and `link_id`, check the answer. Returns the stream and
/// the negotiated minor.
async fn dial_lane(
    path: &Path,
    lane: Lane,
    link_id: [u8; 16],
    cfg: &LinkConfig,
    deadline: Instant,
) -> Result<(Arc<UnixStream>, u8), ConnectError> {
    let name = match lane {
        Lane::Ctl => "ctl",
        Lane::Media => "media",
        Lane::Bulk => "bulk",
    };
    let connect = timeout(cfg.connect_timeout, UnixStream::connect(path))
        .await
        .map_err(|_| unavailable(format!("{name}: connect timed out")))?
        .map_err(|e| unavailable(format!("{name}: connect failed: {e}")))?;
    let stream = Arc::new(connect);
    let offer = Preamble::ours(lane);
    let wire = ClientPreamble {
        preamble: offer,
        link_id,
    }
    .encode();
    let remaining = deadline.saturating_duration_since(Instant::now());
    write_all_stall(
        &stream,
        &wire,
        remaining.max(std::time::Duration::from_millis(1)),
    )
    .await
    .map_err(|_| {
        unavailable(format!("{name}: the session did not take the preamble")).after_preamble()
    })?;
    let mut answer = [0u8; PREAMBLE_LEN];
    timeout_at(deadline, read_exact(&stream, &mut answer))
        .await
        .map_err(|_| unavailable(format!("{name}: no preamble answer in time")))?
        .map_err(|f| {
            let ended = matches!(f, LaneFail::Eof | LaneFail::Io(_));
            let e = from_lane(name, f);
            // The connection ended right after the preamble was sent (not a timeout).
            if ended { e.after_preamble() } else { e }
        })?;
    let answer = Preamble::decode(&answer)
        .map_err(|e| ConnectError::new(FailureClass::Violation, format!("{name}: {e}")))?;
    match offer.check_answer(&answer) {
        Ok(minor) => Ok((stream, minor)),
        Err(PreambleError::MajorMismatch { .. }) => Err(ConnectError::new(
            FailureClass::Outdated,
            format!("{name}: the session speaks another link major version"),
        )),
        Err(e) => Err(ConnectError::new(
            FailureClass::Violation,
            format!("{name}: {e}"),
        )),
    }
}

fn random_link_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    // A failure leaves zeros, which is still a valid (if guessable) id: nothing secret rides on
    // it, it only tells the session which lanes belong together.
    let _ = rustix::rand::getrandom(&mut id, rustix::rand::GetRandomFlags::empty());
    id
}

/// The codecs of `info` the gateway accepts, in the session's order, without duplicates.
fn intersect(info: &pb::Info, allowed: &[VideoCodec]) -> Vec<VideoCodec> {
    let mut out = Vec::new();
    for c in &info.codecs {
        if let Ok(c) = VideoCodec::try_from(*c)
            && c != VideoCodec::Unspecified
            && allowed.contains(&c)
            && !out.contains(&c)
        {
            out.push(c);
        }
    }
    out
}

pub(crate) struct Connected {
    pub shared: Arc<Shared>,
}

pub(crate) async fn connect(path: &Path, cfg: LinkConfig) -> Result<Connected, ConnectError> {
    cfg.validate()
        .map_err(|e| ConnectError::new(FailureClass::Incompatible, e))?;
    let link_id = random_link_id();
    let started = Instant::now();
    let hs_deadline = started + cfg.handshake_timeout;

    // ctl first, and wait for `info` (section 12.2).
    let (ctl, minor) = dial_lane(path, Lane::Ctl, link_id, &cfg, hs_deadline).await?;
    let policy = gateway_policy(Lane::Ctl, cfg.max_frame_bytes)
        .map_err(|e| ConnectError::new(FailureClass::Incompatible, e.to_string()))?;
    let mut ctl_reader = LaneReader::new(
        ctl.clone(),
        Lane::Ctl,
        policy,
        Some(cfg.handshake_timeout),
        None,
    );
    let raw = timeout_at(hs_deadline, ctl_reader.next())
        .await
        .map_err(|_| unavailable("no info from the session in time"))?
        .map_err(|f| from_lane("ctl", f))?;
    let info_msg = match parse(ctl_reader.policy(), raw, u64::MAX) {
        Ok(LinkFrame::FromSession(pb::SessionToGateway {
            message: Some(pb::session_to_gateway::Message::Info(i)),
        })) => i,
        Ok(_) => {
            return Err(ConnectError::new(
                FailureClass::Violation,
                "the first ctl message was not info",
            ));
        }
        Err(e) => {
            return Err(ConnectError::new(
                FailureClass::Violation,
                format!("info: {e}"),
            ));
        }
    };
    let codecs = intersect(&info_msg, &cfg.codecs);
    if codecs.is_empty() {
        return Err(ConnectError::new(
            FailureClass::Incompatible,
            "the session offers no codec the gateway accepts",
        ));
    }
    let display = info_msg.display.unwrap_or_default();
    let info = SessionInfo {
        software: sanitize_text(&info_msg.software, hx_ipc::link::validate::MAX_SOFTWARE_LEN),
        features: info_msg.features,
        codecs,
        display: (display.width, display.height),
        max_fps: info_msg.max_fps,
    };

    // The extra lanes, within 5 s of info.
    let lanes_deadline = Instant::now() + cfg.extra_lanes_timeout;
    let (media, m_minor) = dial_lane(path, Lane::Media, link_id, &cfg, lanes_deadline).await?;
    let (bulk, b_minor) = dial_lane(path, Lane::Bulk, link_id, &cfg, lanes_deadline).await?;
    let minor = minor.min(m_minor).min(b_minor);

    let (bulk_tx, bulk_rx) = mpsc::channel::<BulkOut>(16);
    let max_frame = cfg.max_frame_bytes;
    let shared = Shared::new(cfg, info, minor, bulk_tx);
    ctl_reader.set_idle_limit(Some(shared.cfg.liveness_timeout));
    let media_reader = LaneReader::new(
        media.clone(),
        Lane::Media,
        gateway_policy(Lane::Media, max_frame)
            .map_err(|e| ConnectError::new(FailureClass::Incompatible, e.to_string()))?,
        None,
        None,
    );
    let bulk_reader = LaneReader::new(
        bulk.clone(),
        Lane::Bulk,
        gateway_policy(Lane::Bulk, max_frame)
            .map_err(|e| ConnectError::new(FailureClass::Incompatible, e.to_string()))?,
        None,
        Some(shared.credits.clone()),
    );
    tokio::spawn(tasks::ctl_reader(shared.clone(), ctl_reader));
    tokio::spawn(tasks::ctl_writer(shared.clone(), ctl));
    tokio::spawn(tasks::media_reader(shared.clone(), media_reader));
    tokio::spawn(tasks::video_stage(shared.clone()));
    tokio::spawn(tasks::bulk_reader(shared.clone(), bulk_reader));
    tokio::spawn(tasks::bulk_writer(shared.clone(), bulk, bulk_rx));
    tokio::spawn(tasks::maintenance(shared.clone()));
    // The media lane is silent in this direction and never written to: dropping our write side
    // is not needed, the stream stays open for the reader.
    Ok(Connected { shared })
}
