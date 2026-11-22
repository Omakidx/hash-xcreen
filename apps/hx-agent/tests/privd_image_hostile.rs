//! The image fetcher's directory is hostile (docs/ipc.md 6.12, "privd's side"): a compromised
//! fetcher can plant symlinks, hard links and fifos, lie about sizes, rewrite and replay chunks,
//! stall, flood names, and leave a poisoned manifest or probe. Every case here ends the same way:
//! nothing unverified reaches Incus, the unit is stopped, the directory is swept, no named file is
//! left in staging, and `auto` builds on the server while `prebuilt` reports the stage.

mod privd_image_common;

use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use hx_agent::fetcher::ImageJob;
use hx_ipc::privd::pb::{ErrorCode, ErrorDetail, ImageMode, ImageReason, PathTaken, ProgressStage};
use privd_image_common::*;

fn data() -> Vec<u8> {
    image_bytes(200 * 1024 + 123, 7)
}

/// Serves the list and the probe honestly and the image through `image`.
fn serve(
    env: &Env,
    image: impl Fn(&Path, &AtomicBool) -> Result<(), String> + Send + Sync + 'static,
) {
    env.publish_image(&data(), 86_400);
    let (m, sig) = env.script(|s| s.manifest.clone()).unwrap();
    let probe = env.script(|s| s.probe.clone()).unwrap();
    env.script(|s| {
        s.hook = Some(Arc::new(move |job, dir, stop| match job {
            ImageJob::Manifest => {
                write_new(dir, "images.json", &m);
                write_new(dir, "images.json.minisig", sig.as_bytes());
                Ok(())
            }
            ImageJob::Probe { .. } => {
                write_new(dir, "probe.json", probe.as_bytes());
                Ok(())
            }
            ImageJob::Image { .. } => image(dir, stop),
        }));
    });
}

fn clean(env: &Env) {
    assert!(
        env.fetch_dir_names().is_empty(),
        "swept: {:?}",
        env.fetch_dir_names()
    );
    let staging = &env.h.daemon.cfg.image.staging_dir;
    assert_eq!(
        std::fs::read_dir(staging).map(|d| d.count()).unwrap_or(0),
        0,
        "no named file in staging"
    );
    assert!(
        env.h
            .incus
            .with(|s| s.imports.is_empty() && s.images.is_empty()),
        "nothing reached Incus"
    );
    assert!(env.h.incus.with(|s| s.instances.is_empty()), "no instance");
}

/// `prebuilt`: the error, at IMAGE_FETCH. `auto`: a build, `FELL_BACK`, naming IMAGE_FETCH.
async fn refused_both_ways(env: &Env, code: ErrorCode, detail: ErrorDetail) {
    let r = env.create(env.request(ImageMode::Prebuilt)).await;
    let e = err(&r);
    assert_eq!(
        (e.code(), e.detail(), e.stage()),
        (code, detail, ProgressStage::ImageFetch),
        "{}",
        e.message
    );
    assert!(
        env.systemd
            .fetcher
            .stopped()
            .iter()
            .any(|j| j.starts_with("image-")),
        "the unit was stopped: {:?}",
        env.systemd.fetcher.stopped()
    );
    clean(env);
    env.next_hour();
    // AUTO falls back to a build, and says where.
    let c = created(env.create(env.request(ImageMode::Auto)).await);
    assert_eq!(c.path_taken(), PathTaken::Build);
    assert_eq!(c.reason_code(), ImageReason::FellBack);
    assert!(c.reason.contains("failed at IMAGE_FETCH"), "{}", c.reason);
    assert!(env.fetch_dir_names().is_empty());
    assert!(
        env.h
            .incus
            .with(|s| s.imports.is_empty() && s.images.is_empty())
    );
}

fn secret(env: &Env) -> std::path::PathBuf {
    let p = env.h.dir.path().join("secret");
    std::fs::write(&p, b"root only").unwrap();
    p
}

#[tokio::test(flavor = "multi_thread")]
async fn a_symlink_as_a_chunk_is_refused_and_never_followed() {
    let env = Env::new().await;
    let secret = secret(&env);
    let target = secret.clone();
    serve(&env, move |dir, _| {
        symlink(&target, dir.join("c-000000")).map_err(|e| e.to_string())?;
        write_new(dir, "r-000000", b"");
        std::thread::sleep(Duration::from_millis(300));
        Ok(())
    });
    refused_both_ways(&env, ErrorCode::FailedPrecondition, ErrorDetail::Image).await;
    assert_eq!(
        std::fs::read(&secret).unwrap(),
        b"root only",
        "the target is untouched"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hard_link_as_a_chunk_is_refused() {
    let env = Env::new().await;
    let secret = secret(&env);
    let d = data();
    let target = secret.clone();
    serve(&env, move |dir, _| {
        // A hard link to a file of the same size as the first chunk would pass a size test.
        std::fs::write(&target, &d[..CHUNK as usize]).unwrap();
        std::fs::hard_link(&target, dir.join("c-000000")).map_err(|e| e.to_string())?;
        write_new(dir, "r-000000", b"");
        std::thread::sleep(Duration::from_millis(300));
        Ok(())
    });
    refused_both_ways(&env, ErrorCode::FailedPrecondition, ErrorDetail::Image).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fifo_as_a_chunk_cannot_block_privd() {
    let env = Env::new().await;
    serve(&env, |dir, _| {
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.join("c-000000"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .map_err(|e| e.to_string())?;
        write_new(dir, "r-000000", b"");
        std::thread::sleep(Duration::from_millis(300));
        Ok(())
    });
    tokio::time::timeout(
        Duration::from_secs(20),
        refused_both_ways(&env, ErrorCode::FailedPrecondition, ErrorDetail::Image),
    )
    .await
    .expect("privd did not block on the fifo");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_directory_or_a_socket_as_a_chunk_is_refused() {
    let env = Env::new().await;
    serve(&env, |dir, _| {
        std::fs::create_dir(dir.join("c-000000")).map_err(|e| e.to_string())?;
        write_new(dir, "r-000000", b"");
        std::thread::sleep(Duration::from_millis(300));
        Ok(())
    });
    refused_both_ways(&env, ErrorCode::FailedPrecondition, ErrorDetail::Image).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_chunk_of_the_wrong_size_is_refused_oversize_and_short() {
    for delta in [1i64, -1] {
        let env = Env::new().await;
        let d = data();
        serve(&env, move |dir, _| {
            let mut c = d[..CHUNK as usize].to_vec();
            if delta > 0 {
                c.push(0);
            } else {
                c.pop();
            }
            write_new(dir, "c-000000", &c);
            write_new(dir, "r-000000", b"");
            std::thread::sleep(Duration::from_millis(300));
            Ok(())
        });
        refused_both_ways(&env, ErrorCode::FailedPrecondition, ErrorDetail::Image).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_chunk_that_grows_after_it_was_opened_cannot_make_the_image_longer() {
    // The last chunk is announced shorter than a chunk; a fetcher that appends to a middle chunk
    // after the size check is caught by the read bound and the digest.
    let env = Env::new().await;
    let d = data();
    serve(&env, move |dir, stop| {
        let mut evil = d.clone();
        evil[10] ^= 0xff;
        write_chunks(dir, &evil, CHUNK, stop)
    });
    refused_both_ways(&env, ErrorCode::FailedPrecondition, ErrorDetail::Image).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn one_flipped_bit_in_the_image_fails_the_signed_digest() {
    let env = Env::new().await;
    let d = data();
    serve(&env, move |dir, stop| {
        let mut bad = d.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        write_chunks(dir, &bad, CHUNK, stop)
    });
    refused_both_ways(&env, ErrorCode::FailedPrecondition, ErrorDetail::Image).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_chunk_rewritten_after_it_was_taken_is_never_read_again() {
    // The hostile fetcher re-creates chunk 0 with other bytes and a marker after privd took it.
    // privd moved on and never reopens a chunk: the image still verifies, and the planted names
    // are swept.
    let env = Env::new().await;
    let d = data();
    serve(&env, move |dir, stop| {
        let chunk = CHUNK as usize;
        write_new(dir, "c-000000", &d[..chunk]);
        write_new(dir, "r-000000", b"");
        if !wait_gone(dir, "c-000000", stop, Duration::from_secs(10)) {
            return Err("not taken".into());
        }
        write_new(dir, "c-000000", &vec![0xEE; chunk]);
        write_new(dir, "r-000000", b"");
        for (k, piece) in d.chunks(chunk).enumerate().skip(1) {
            let k = k as u32;
            if k >= 3
                && !wait_gone(
                    dir,
                    &format!("c-{:06}", k - 2),
                    stop,
                    Duration::from_secs(10),
                )
            {
                return Err("not taken".into());
            }
            write_new(dir, &format!("c-{k:06}"), piece);
            write_new(dir, &format!("r-{k:06}"), b"");
        }
        write_new(dir, "end", b"");
        Ok(())
    });
    let c = created(env.create(env.request(ImageMode::Prebuilt)).await);
    assert_eq!(c.path_taken(), PathTaken::Prebuilt);
    assert!(
        env.fetch_dir_names().is_empty(),
        "{:?}",
        env.fetch_dir_names()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn extra_names_are_swept_and_ignored() {
    let env = Env::new().await;
    let d = data();
    serve(&env, move |dir, stop| {
        for i in 0..8 {
            write_new(dir, &format!("junk-{i}"), b"x");
        }
        write_new(dir, "c-9999999", b"x");
        write_new(dir, ".hidden", b"x");
        write_new(dir, "\u{e9}t\u{e9}", b"x");
        write_chunks(dir, &d, CHUNK, stop)
    });
    let c = created(env.create(env.request(ImageMode::Prebuilt)).await);
    assert_eq!(c.path_taken(), PathTaken::Prebuilt);
    assert!(
        env.fetch_dir_names().is_empty(),
        "{:?}",
        env.fetch_dir_names()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_download_ends_at_the_idle_limit_and_stops_the_unit() {
    let env = Env::new().await;
    let d = data();
    serve(&env, move |dir, stop| {
        write_new(dir, "c-000000", &d[..CHUNK as usize]);
        write_new(dir, "r-000000", b"");
        // Then nothing, until the unit is stopped.
        let t = std::time::Instant::now();
        while !stop.load(Ordering::SeqCst) && t.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(5));
        }
        Err("stopped".into())
    });
    let daemon = env.daemon_with(|c| c.image.chunk_idle = Duration::from_millis(400));
    let r = env
        .create_on(
            &daemon,
            hx_ipc::privd::pb::Role::Admin,
            env.request(ImageMode::Prebuilt),
        )
        .await;
    let e = err(&r);
    assert_eq!(e.code(), ErrorCode::Unavailable, "{}", e.message);
    assert!(e.retryable);
    assert_eq!(e.stage(), ProgressStage::ImageFetch);
    assert!(
        env.systemd
            .fetcher
            .stopped()
            .iter()
            .any(|j| j.starts_with("image-"))
    );
    clean(&env);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_download_that_never_starts_ends_at_the_fetch_deadline() {
    let env = Env::new().await;
    serve(&env, |_dir, stop| {
        let t = std::time::Instant::now();
        while !stop.load(Ordering::SeqCst) && t.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(5));
        }
        Err("stopped".into())
    });
    let daemon = env.daemon_with(|c| c.image.fetch_wait = Duration::from_millis(400));
    let r = env
        .create_on(
            &daemon,
            hx_ipc::privd::pb::Role::Admin,
            env.request(ImageMode::Prebuilt),
        )
        .await;
    let e = err(&r);
    assert_eq!(e.code(), ErrorCode::Unavailable, "{}", e.message);
    clean(&env);
}

#[tokio::test(flavor = "multi_thread")]
async fn more_chunks_than_announced_or_fewer_are_refused() {
    // More: an extra chunk, marker and end after the announced ones.
    let env = Env::new().await;
    let d = data();
    serve(&env, move |dir, stop| {
        let mut longer = d.clone();
        longer.extend_from_slice(&[1u8; 10]);
        // The honest chunks of the longer file: the last announced chunk is short in the
        // signed size, so a longer last chunk is oversize.
        write_chunks(dir, &longer, CHUNK, stop)
    });
    refused_both_ways(&env, ErrorCode::FailedPrecondition, ErrorDetail::Image).await;
    // An extra whole chunk after the announced ones.
    let env = Env::new().await;
    let d = data();
    serve(&env, move |dir, stop| {
        let n = d.chunks(CHUNK as usize).count() as u32;
        write_chunks_no_end(dir, &d, CHUNK, stop)?;
        write_new(dir, &format!("c-{n:06}"), b"extra");
        write_new(dir, &format!("r-{n:06}"), b"");
        write_new(dir, "end", b"");
        Ok(())
    });
    refused_both_ways(&env, ErrorCode::FailedPrecondition, ErrorDetail::Image).await;
    // Fewer: `end` after the first chunk only.
    let env = Env::new().await;
    let d = data();
    serve(&env, move |dir, _| {
        write_new(dir, "c-000000", &d[..CHUNK as usize]);
        write_new(dir, "r-000000", b"");
        write_new(dir, "end", b"");
        Ok(())
    });
    refused_both_ways(&env, ErrorCode::FailedPrecondition, ErrorDetail::Image).await;
}

fn write_chunks_no_end(
    dir: &Path,
    data: &[u8],
    chunk: u64,
    stop: &AtomicBool,
) -> Result<(), String> {
    for (k, piece) in data.chunks(chunk as usize).enumerate() {
        let k = k as u32;
        if k >= 2
            && !wait_gone(
                dir,
                &format!("c-{:06}", k - 2),
                stop,
                Duration::from_secs(10),
            )
        {
            return Err("not taken".into());
        }
        write_new(dir, &format!("c-{k:06}"), piece);
        write_new(dir, &format!("r-{k:06}"), b"");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_unit_that_fails_after_its_last_chunk_is_a_failed_download() {
    let env = Env::new().await;
    let d = data();
    serve(&env, move |dir, stop| {
        write_chunks(dir, &d, CHUNK, stop)?;
        Err("exit 1".into())
    });
    let r = env.create(env.request(ImageMode::Prebuilt)).await;
    let e = err(&r);
    assert_eq!(e.code(), ErrorCode::Unavailable, "{}", e.message);
    clean(&env);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_poisoned_manifest_file_is_an_unverified_list_not_a_read() {
    let secret_text = b"{\"schema\":1}";
    // A symlink where the manifest should be.
    let env = Env::new().await;
    let secret = secret(&env);
    std::fs::write(&secret, secret_text).unwrap();
    let t = secret.clone();
    env.script(|s| {
        s.hook = Some(Arc::new(move |job, dir, _| {
            if let ImageJob::Manifest = job {
                symlink(&t, dir.join("images.json")).map_err(|e| e.to_string())?;
                write_new(dir, "images.json.minisig", b"junk");
            }
            Ok(())
        }));
    });
    let c = created(env.create(env.request(ImageMode::Auto)).await);
    assert_eq!(c.reason_code(), ImageReason::ListUnverified);
    assert!(
        env.h
            .audit
            .lines()
            .iter()
            .any(|l| l.contains("image list not verified"))
    );
    // A manifest over the 1 MiB limit.
    let env = Env::new().await;
    env.script(|s| {
        s.hook = Some(Arc::new(|job, dir, _| {
            if let ImageJob::Manifest = job {
                write_new(dir, "images.json", &vec![b' '; 1024 * 1024 + 1]);
                write_new(dir, "images.json.minisig", b"junk");
            }
            Ok(())
        }));
    });
    let c = created(env.create(env.request(ImageMode::Auto)).await);
    assert_eq!(c.reason_code(), ImageReason::ListUnverified);
    // The job produced nothing: the list is unavailable.
    let env = Env::new().await;
    env.script(|s| s.hook = Some(Arc::new(|_, _, _| Ok(()))));
    let c = created(env.create(env.request(ImageMode::Auto)).await);
    assert_eq!(c.reason_code(), ImageReason::ListUnavailable);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_poisoned_probe_only_costs_the_prebuilt_image() {
    for poison in ["symlink", "huge", "extra field", "negative"] {
        let env = Env::new().await;
        env.publish_image(&data(), 86_400);
        let (m, sig) = env.script(|s| s.manifest.clone()).unwrap();
        let secret = secret(&env);
        let p = poison.to_string();
        env.script(|s| {
            s.hook = Some(Arc::new(move |job, dir, _| {
                match job {
                    ImageJob::Manifest => {
                        write_new(dir, "images.json", &m);
                        write_new(dir, "images.json.minisig", sig.as_bytes());
                    }
                    ImageJob::Probe { .. } => match p.as_str() {
                        "symlink" => {
                            symlink(&secret, dir.join("probe.json")).map_err(|e| e.to_string())?
                        }
                        "huge" => write_new(dir, "probe.json", &vec![b' '; 5000]),
                        "extra field" => write_new(
                            dir,
                            "probe.json",
                            b"{\"release_bytes\":1,\"release_ms\":1,\"x\":1}",
                        ),
                        _ => write_new(
                            dir,
                            "probe.json",
                            b"{\"release_bytes\":-1,\"release_ms\":1}",
                        ),
                    },
                    ImageJob::Image { .. } => return Err("not reached".into()),
                }
                Ok(())
            }));
        });
        let c = created(env.create(env.request(ImageMode::Auto)).await);
        assert_eq!(c.path_taken(), PathTaken::Build, "{poison}");
        assert_eq!(c.reason_code(), ImageReason::ProbeFailed, "{poison}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_directory_privd_cannot_empty_is_reported_not_papered_over() {
    let env = Env::new().await;
    env.publish_image(&data(), 86_400);
    // A non-empty subdirectory: the real fetcher cannot make one (its system-call filter forbids
    // mkdir), and without CAP_DAC_OVERRIDE privd could not empty one the fetcher chmod-ed. Here
    // it is simply not removable by `unlinkat`.
    let dir = env.fetch_dir();
    std::fs::create_dir_all(dir.join("trap")).unwrap();
    std::fs::write(dir.join("trap/inner"), b"x").unwrap();
    // AUTO treats an unusable fetch directory like an unavailable list and builds.
    let c = created(env.create(env.request(ImageMode::Auto)).await);
    assert_eq!(c.reason_code(), ImageReason::ListUnavailable);
    // PREBUILT says so (retryable: an administrator clears it).
    env.next_hour();
    env.h.incus.with(|s| s.instances.clear());
    let r = env.create(env.request(ImageMode::Prebuilt)).await;
    assert_eq!(err(&r).code(), ErrorCode::Unavailable);
}
