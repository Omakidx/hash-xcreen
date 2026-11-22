//! Entry point for the cargo-fuzz target `agent_link_session` (feature `fuzzing`, never part of
//! a product build): the gateway's three lane readers, fed what a hostile `hx-session` could
//! write. It runs the production `ctl_loop`, `media_loop` and `bulk_loop` (framing, per-kind
//! limits, byte budgets and frame-rate windows, protobuf decode, the contract's validation, the
//! Annex B / SPS check, transfer rules and the shared queues) over socket pairs, so nothing
//! touches the network or the disk.

use std::cell::RefCell;
use std::sync::Arc;

use hx_ipc::link::Lane;
use hx_proto::VideoCodec;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use super::config::LinkConfig;
use super::lane::{LaneReader, gateway_policy};
use super::shared::Shared;
use super::tasks::{bulk_loop, ctl_loop, media_loop};
use super::types::SessionInfo;

thread_local! {
    static RT: RefCell<Option<tokio::runtime::Runtime>> = const { RefCell::new(None) };
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    RT.with(|cell| {
        let mut rt = cell.borrow_mut();
        let rt = rt.get_or_insert_with(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime")
        });
        rt.block_on(f)
    })
}

/// Splits `data` into the three lane streams: `u16 ctl_len | u16 media_len | ctl | media | bulk`
/// (little endian; a short input gives empty lanes).
pub fn split(data: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let Some((head, rest)) = data.split_first_chunk::<4>() else {
        return (&[], &[], &[]);
    };
    let ctl = usize::from(u16::from_le_bytes([head[0], head[1]])).min(rest.len());
    let (ctl, rest) = rest.split_at(ctl);
    let media = usize::from(u16::from_le_bytes([head[2], head[3]])).min(rest.len());
    let (media, bulk) = rest.split_at(media);
    (ctl, media, bulk)
}

/// Writes `bytes` to one end of a socket pair, closes it, and returns the other end.
async fn serve(bytes: &[u8]) -> Arc<UnixStream> {
    let (ours, mut theirs) = UnixStream::pair().expect("socketpair");
    let bytes = bytes.to_vec();
    tokio::spawn(async move {
        let _ = theirs.write_all(&bytes).await;
        let _ = theirs.shutdown().await;
    });
    Arc::new(ours)
}

/// Drives the three loops over the lane streams encoded in `data` (see [`split`]).
pub fn session_link(data: &[u8]) {
    let (ctl, media, bulk) = split(data);
    block_on(async {
        let cfg = LinkConfig::default();
        let (bulk_tx, _bulk_rx) = mpsc::channel(16);
        let info = SessionInfo {
            software: String::new(),
            features: u64::MAX,
            codecs: vec![VideoCodec::H264],
            display: (1920, 1080),
            max_fps: 60,
        };
        let sh = Shared::new(cfg.clone(), info, 0, bulk_tx);
        let lane = |stream: Arc<UnixStream>, l: Lane| {
            LaneReader::new(
                stream,
                l,
                gateway_policy(l, cfg.max_frame_bytes).expect("policy"),
                None,
                None,
            )
        };
        let mut r = lane(serve(ctl).await, Lane::Ctl);
        let _ = ctl_loop(&sh, &mut r).await;
        let mut r = lane(serve(media).await, Lane::Media);
        let _ = media_loop(&sh, &mut r).await;
        // `bulk` is not paused by the consumer's credits here: nothing consumes in this harness.
        let mut r = lane(serve(bulk).await, Lane::Bulk);
        let _ = bulk_loop(&sh, &mut r).await;
        // The consumer side of the queues must cope with whatever was queued.
        while sh.inbox.pop().is_some() {}
    });
}
