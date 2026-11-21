//! Transfer limits and policy changes through the relay (real session under Xvfb, see
//! `relay_e2e.rs` for the setup).

mod gateway_common;
mod relay_common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::time::{Duration, Instant};

use hx_transport::TransferKind;
use relay_common::*;

#[tokio::test(flavor = "multi_thread")]
async fn a_session_pushing_file_after_file_gets_only_a_few_through() {
    let Some(rig) = Rig::start(RigOptions::default()).await else {
        return;
    };
    let dev = rig.device("laptop").await;
    let mut c = rig.client(&dev, "laptop").await;
    c.view(|_| {}).await;
    c.next_frame(15).await;
    let src = rig.dir.join("tiny.bin");
    std::fs::write(&src, b"tiny").unwrap();
    let sender = rig.server.as_ref().unwrap().sender();
    // 200 pushes, 50 a second: fast enough to be a flood, slow enough for the link's own limits
    // (a faster one closes the link as a fault, which `link_hostile` covers).
    let started = Instant::now();
    let pusher = {
        let (sender, src) = (sender.clone(), src.clone());
        tokio::task::spawn_blocking(move || {
            for _ in 0..200 {
                let _ = sender.send_file(&src);
                std::thread::sleep(Duration::from_millis(20));
            }
        })
    };
    let mut got = 0u32;
    while c.next_transfer(3).await.is_some() {
        got += 1;
    }
    pusher.await.unwrap();
    let secs = started.elapsed().as_secs_f64();
    // 16 at once, then about 1.6 a second.
    let most = 16.0 + 1.6 * (secs + 1.0);
    assert!(got >= 8, "some got through: {got}");
    assert!(
        f64::from(got) <= most,
        "at most {most} of 200 may open client streams, {got} did"
    );
    // The link itself was not harmed.
    assert!(rig.relay.keeper().is_up());
}

#[tokio::test(flavor = "multi_thread")]
async fn turning_the_clipboard_off_aborts_a_transfer_in_flight() {
    let Some(rig) = Rig::start(RigOptions::default()).await else {
        return;
    };
    let dev = rig.device("laptop").await;
    let mut c = rig.client(&dev, "laptop").await;
    c.view(|_| {}).await;
    c.next_frame(15).await;
    // A 64 MiB clipboard, written slowly.
    let size: u64 = 64 << 20;
    let mut s = c
        .conn
        .open_transfer(
            TransferKind::Clipboard,
            hx_proto::pb::TransferHeader {
                mime: "image/png".into(),
                name: String::new(),
                size,
            },
        )
        .await
        .unwrap();
    let written = Arc::new(AtomicU64::new(0));
    let w2 = written.clone();
    let writer = tokio::spawn(async move {
        let mut png = vec![7u8; 64 * 1024];
        png[..8].copy_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        let mut total = 0u64;
        while total < size {
            if s.write(&png).await.is_err() {
                return Err(total);
            }
            total += png.len() as u64;
            w2.store(total, SeqCst);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        s.finish().await.map_err(|_| total)
    });
    while written.load(SeqCst) < (2 << 20) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    c.view(|v| v.clipboard_enabled = false).await;
    let r = tokio::time::timeout(Duration::from_secs(20), writer)
        .await
        .expect("the writer ends")
        .unwrap();
    assert!(
        matches!(r, Err(total) if total < size),
        "the transfer was aborted part way: {r:?}"
    );
}
