//! The image template of the fetcher against a local HTTPS server (docs/ipc.md 6.12): the three
//! jobs, the chunk protocol with its back-pressure, the quotas and hosts, the binary's refusal of
//! the wrong template, and the whole chain: privd, a fake systemd that runs the **real** fetcher,
//! and the loopback server.

mod privd_image_common;

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use hx_agent::fetcher::images::{END_FILE, chunk_name, marker_name};
use hx_agent::fetcher::{FetchError, ImageJob, run_image};
use hx_ipc::privd::pb::{ImageMode, ImageReason, PathTaken};
use privd_image_common::*;

const BUILD: &str = "20261120.1";

fn data() -> Vec<u8> {
    image_bytes(5 * CHUNK as usize + 4321, 9)
}

fn img_job(parts: usize) -> ImageJob {
    ImageJob::Image {
        recipe: rid(),
        build_id: BUILD.into(),
        nparts: parts,
    }
}

fn publish_parts(srv: &TestServer, d: &[u8], parts: usize) {
    let file = hx_provision::images::file_name(rid(), BUILD);
    let base = format!("/rel/images-{BUILD}");
    if parts == 1 {
        srv.route(&format!("{base}/{file}"), ok_route(d));
    } else {
        let per = d.len().div_ceil(parts);
        for (i, c) in d.chunks(per).enumerate() {
            srv.route(&format!("{base}/{file}.p{i}"), ok_route(c));
        }
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Plays privd's part: takes chunks as their markers appear, concatenates, unlinks.
fn consume(dir: std::path::PathBuf, n: usize) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let t = Instant::now();
        for k in 0..n as u32 {
            while !dir.join(marker_name(k)).exists() {
                assert!(t.elapsed() < Duration::from_secs(20), "no chunk {k}");
                std::thread::sleep(Duration::from_millis(2));
            }
            out.extend(std::fs::read(dir.join(chunk_name(k))).unwrap());
            std::fs::remove_file(dir.join(marker_name(k))).unwrap();
            std::fs::remove_file(dir.join(chunk_name(k))).unwrap();
        }
        out
    })
}

#[test]
fn the_image_job_writes_chunks_markers_and_end_for_one_part_and_for_several() {
    for parts in [1usize, 2, 4] {
        let srv = TestServer::start();
        let out = tempfile::tempdir().unwrap();
        let d = data();
        publish_parts(&srv, &d, parts);
        let n = d.len().div_ceil(CHUNK as usize);
        let taker = consume(out.path().to_path_buf(), n);
        run_image(&img_job(parts), &srv.fetch_config(out.path())).unwrap();
        // Chunks span the part boundaries: the concatenation is the file, in exact chunk sizes.
        assert_eq!(taker.join().unwrap(), d, "{parts} parts");
        assert_eq!(names(out.path()), [END_FILE], "{parts} parts");
        let hits = srv.hits();
        assert_eq!(hits.len(), parts, "{hits:?}");
    }
}

#[test]
fn chunks_are_exactly_the_chunk_size_except_the_last() {
    let srv = TestServer::start();
    let out = tempfile::tempdir().unwrap();
    let d = data();
    publish_parts(&srv, &d, 2);
    let dir = out.path().to_path_buf();
    // Read sizes as they appear.
    let n = d.len().div_ceil(CHUNK as usize);
    let sizes = std::thread::spawn(move || {
        let mut sizes = Vec::new();
        for k in 0..n as u32 {
            let t = Instant::now();
            while !dir.join(marker_name(k)).exists() {
                assert!(t.elapsed() < Duration::from_secs(20));
                std::thread::sleep(Duration::from_millis(2));
            }
            sizes.push(std::fs::metadata(dir.join(chunk_name(k))).unwrap().len());
            std::fs::remove_file(dir.join(marker_name(k))).unwrap();
            std::fs::remove_file(dir.join(chunk_name(k))).unwrap();
        }
        sizes
    });
    run_image(&img_job(2), &srv.fetch_config(out.path())).unwrap();
    let sizes = sizes.join().unwrap();
    assert!(sizes[..sizes.len() - 1].iter().all(|s| *s == CHUNK));
    assert_eq!(*sizes.last().unwrap(), 4321);
}

#[test]
fn back_pressure_stops_the_fetcher_two_chunks_ahead_of_a_consumer_that_takes_none() {
    let srv = TestServer::start();
    let out = tempfile::tempdir().unwrap();
    publish_parts(&srv, &data(), 1);
    let mut cfg = srv.fetch_config(out.path());
    cfg.image.stall = Duration::from_millis(600);
    let e = run_image(&img_job(1), &cfg).unwrap_err();
    assert!(matches!(e, FetchError::Io(_)), "{e}");
    // Chunks 0 and 1 (and their markers) were written; chunk 2 was never started, and `end` is
    // not there.
    let got = names(out.path());
    assert_eq!(
        got,
        ["c-000000", "c-000001", "r-000000", "r-000001"],
        "{got:?}"
    );
}

#[test]
fn quotas_hosts_and_failures_end_the_job_without_end() {
    // A part over the per-part cap; the total over the total cap.
    for (cap_part, cap_total) in [(1000u64, u64::MAX), (u64::MAX, 100_000)] {
        let srv = TestServer::start();
        let out = tempfile::tempdir().unwrap();
        publish_parts(&srv, &data(), 1);
        let mut cfg = srv.fetch_config(out.path());
        cfg.image.max_part = cap_part;
        cfg.image.max_total = cap_total.min(10 * 1024 * 1024);
        let taker = consume(out.path().to_path_buf(), 1);
        assert!(run_image(&img_job(1), &cfg).is_err());
        let _ = taker.join();
        assert!(!out.path().join(END_FILE).exists());
    }
    // Not found.
    let srv = TestServer::start();
    let out = tempfile::tempdir().unwrap();
    let e = run_image(&img_job(1), &srv.fetch_config(out.path())).unwrap_err();
    assert!(matches!(e, FetchError::Response(m) if m.contains("404")));
    assert!(names(out.path()).is_empty());
    // A redirect to a host that is not a release host.
    let srv = TestServer::start();
    let file = hx_provision::images::file_name(rid(), BUILD);
    srv.route(
        &format!("/rel/images-{BUILD}/{file}"),
        Route {
            status: 302,
            headers: vec![("Location".into(), "https://evil.example/x".into())],
            ..Route::default()
        },
    );
    let e = run_image(&img_job(1), &srv.fetch_config(out.path())).unwrap_err();
    assert!(matches!(e, FetchError::Refused(_)), "{e}");
    // A certificate that chains to no trusted root.
    let srv = TestServer::start();
    publish_parts(&srv, &data(), 1);
    let mut cfg = srv.fetch_config(out.path());
    cfg.roots = std::sync::Arc::new(rustls::RootCertStore::empty());
    assert!(matches!(
        run_image(&img_job(1), &cfg).unwrap_err(),
        FetchError::Tls(_)
    ));
    // A truncated body.
    let srv = TestServer::start();
    let d = data();
    let file = hx_provision::images::file_name(rid(), BUILD);
    srv.route(
        &format!("/rel/images-{BUILD}/{file}"),
        Route {
            cut_at: Some(1000),
            ..ok_route(&d)
        },
    );
    let taker = consume(out.path().to_path_buf(), 1);
    assert!(run_image(&img_job(1), &srv.fetch_config(out.path())).is_err());
    drop(taker);
}

#[test]
fn the_manifest_job_downloads_both_files_and_leaves_nothing_on_failure() {
    let srv = TestServer::start();
    let out = tempfile::tempdir().unwrap();
    let m = manifest_json(vec![], NOW);
    let name = hx_provision::images::manifest_file_name(&arch());
    srv.route(&format!("/rel/images/{name}"), ok_route(&m));
    srv.route(&format!("/rel/images/{name}.minisig"), ok_route(b"sig"));
    run_image(&ImageJob::Manifest, &srv.fetch_config(out.path())).unwrap();
    assert_eq!(std::fs::read(out.path().join("images.json")).unwrap(), m);
    assert_eq!(
        std::fs::read(out.path().join("images.json.minisig")).unwrap(),
        b"sig"
    );
    // The signature is missing: the first file is removed again.
    let srv = TestServer::start();
    let out = tempfile::tempdir().unwrap();
    srv.route(&format!("/rel/images/{name}"), ok_route(&m));
    assert!(run_image(&ImageJob::Manifest, &srv.fetch_config(out.path())).is_err());
    assert!(names(out.path()).is_empty());
    // Over 1 MiB.
    let srv = TestServer::start();
    srv.route(
        &format!("/rel/images/{name}"),
        ok_route(&vec![b' '; 1024 * 1024 + 1]),
    );
    srv.route(&format!("/rel/images/{name}.minisig"), ok_route(b"s"));
    assert!(run_image(&ImageJob::Manifest, &srv.fetch_config(out.path())).is_err());
}

#[test]
fn the_probe_job_measures_the_release_host_and_the_mirror_and_discards_the_bodies() {
    let srv = TestServer::start();
    let out = tempfile::tempdir().unwrap();
    let file = hx_provision::images::file_name(rid(), BUILD);
    // An unsplit image only has `<file>`; a split one only `<file>.p0`.
    for split in [false, true] {
        let out = tempfile::tempdir().unwrap();
        let path = if split {
            format!("/rel/images-{BUILD}/{file}.p0")
        } else {
            format!("/rel/images-{BUILD}/{file}")
        };
        let srv = TestServer::start();
        srv.route(&path, ok_route(&vec![7u8; 100_000]));
        srv.route("/mirror/Packages.xz", ok_route(&vec![8u8; 50_000]));
        let job = ImageJob::Probe {
            recipe: rid(),
            build_id: BUILD.into(),
        };
        run_image(&job, &srv.fetch_config(out.path())).unwrap();
        let p: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.path().join("probe.json")).unwrap()).unwrap();
        // The release probe stops at the 8 KiB budget of this configuration; the mirror's 50 KB
        // body is also cut there. Only the numbers are written, never a body.
        assert_eq!(p["release_bytes"], 8 * 1024, "{p}");
        assert_eq!(p["mirror_bytes"], 8 * 1024, "{p}");
        assert!(p["release_ms"].as_u64().unwrap() >= 1);
        assert_eq!(names(out.path()), ["probe.json"]);
        assert!(
            std::fs::metadata(out.path().join("probe.json"))
                .unwrap()
                .len()
                < 4096
        );
    }
    // A release host that fails and a mirror that is not on the allowed list: both fields absent,
    // the job still succeeds.
    let mut cfg = srv.fetch_config(out.path());
    cfg.image.mirror_hosts = vec!["not-localhost.example".into()];
    srv.route("/mirror/Packages.xz", ok_route(b"x"));
    let job = ImageJob::Probe {
        recipe: rid(),
        build_id: BUILD.into(),
    };
    run_image(&job, &cfg).unwrap();
    assert_eq!(std::fs::read(out.path().join("probe.json")).unwrap(), b"{}");
    // The mirror is not asked at all when its host is not allowed.
    assert!(
        !srv.hits().iter().any(|h| h.contains("mirror")),
        "{:?}",
        srv.hits()
    );
}

#[test]
fn the_binary_refuses_the_other_templates_jobs_and_unknown_templates() {
    let bin = env!("CARGO_BIN_EXE_hx-update-fetcher");
    let run = |arg: &str, template: Option<&str>| {
        let mut c = Command::new(bin);
        c.arg(arg).env_remove("HX_FETCH_TEMPLATE");
        if let Some(t) = template {
            c.env("HX_FETCH_TEMPLATE", t);
        }
        c.output().unwrap().status.code()
    };
    // Image jobs under the update template, update jobs under the image template.
    assert_eq!(run("images-manifest", None), Some(2));
    assert_eq!(
        run("probe-ubuntu-24.04-xfce-basic-20261120.1", None),
        Some(2)
    );
    assert_eq!(
        run("image-ubuntu-24.04-xfce-basic-20261120.1-1", None),
        Some(2)
    );
    assert_eq!(run("manifest-stable", Some("image")), Some(2));
    assert_eq!(run("artifact-1.2.3", Some("image")), Some(2));
    // Unknown template values and invalid jobs.
    assert_eq!(run("images-manifest", Some("Image")), Some(2));
    assert_eq!(run("images-manifest", Some("")), Some(2));
    assert_eq!(run("images-manifest", Some("update")), Some(2));
    assert_eq!(
        run("image-ubuntu-24.04-xfce-basic-20261120.1-9", Some("image")),
        Some(2)
    );
    assert_eq!(run("../x", Some("image")), Some(2));
    // No argument, or two.
    assert_eq!(Command::new(bin).output().unwrap().status.code(), Some(2));
    assert_eq!(
        Command::new(bin)
            .args(["a", "b"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
}

/// The whole chain: privd, a systemd that runs the real fetcher, a loopback HTTPS server.
#[tokio::test(flavor = "multi_thread")]
async fn privd_installs_from_an_image_served_over_https_by_the_real_fetcher() {
    let env = Env::new().await;
    let srv = TestServer::start();
    let d = data();
    let e = entry_for(rid(), &d, BUILD, NOW - 86_400, 2);
    let m = manifest_json(vec![e.clone()], NOW);
    let sig = env.signer.sign_manifest(&m, NOW);
    let mname = hx_provision::images::manifest_file_name(&arch());
    srv.route(&format!("/rel/images/{mname}"), ok_route(&m));
    srv.route(
        &format!("/rel/images/{mname}.minisig"),
        ok_route(sig.as_bytes()),
    );
    publish_parts(&srv, &d, 2);
    srv.route("/mirror/Packages.xz", ok_route(&vec![1u8; 100_000]));
    let cfg = srv.fetch_config(&env.fetch_dir());
    env.script(|s| s.hook = Some(https_hook(cfg)));
    // The first part is the same bytes as the unsplit file's start: the probe uses `.p0`.
    let c = created(env.create(env.request(ImageMode::Auto)).await);
    assert_eq!(c.path_taken(), PathTaken::Prebuilt, "{}", c.reason);
    assert_eq!(c.reason_code(), ImageReason::PrebuiltFaster);
    assert_eq!(
        env.h.incus.with(|s| s.imports.clone()),
        [(e.sha256.clone(), d.len() as u64)]
    );
    assert!(
        env.fetch_dir_names().is_empty(),
        "{:?}",
        env.fetch_dir_names()
    );
    // The server saw: the list and its signature, the probes of the release host and the mirror,
    // and both parts.
    let hits = srv.hits();
    assert!(hits.iter().any(|h| h.ends_with(".json")), "{hits:?}");
    assert!(hits.iter().any(|h| h.contains("mirror")), "{hits:?}");
    assert!(
        hits.iter().filter(|h| h.contains(".p")).count() >= 2,
        "{hits:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_serves_a_tampered_image_makes_auto_build() {
    let env = Env::new().await;
    let srv = TestServer::start();
    let d = data();
    let e = entry_for(rid(), &d, BUILD, NOW - 86_400, 1);
    let m = manifest_json(vec![e], NOW);
    let sig = env.signer.sign_manifest(&m, NOW);
    let mname = hx_provision::images::manifest_file_name(&arch());
    srv.route(&format!("/rel/images/{mname}"), ok_route(&m));
    srv.route(
        &format!("/rel/images/{mname}.minisig"),
        ok_route(sig.as_bytes()),
    );
    let mut bad = d.clone();
    bad[4000] ^= 1;
    publish_parts(&srv, &bad, 1);
    srv.route("/mirror/Packages.xz", ok_route(&vec![1u8; 100_000]));
    let cfg = srv.fetch_config(&env.fetch_dir());
    env.script(|s| s.hook = Some(https_hook(cfg)));
    let c = created(env.create(env.request(ImageMode::Auto)).await);
    assert_eq!(c.path_taken(), PathTaken::Build);
    assert_eq!(c.reason_code(), ImageReason::FellBack);
    assert!(env.h.incus.with(|s| s.imports.is_empty()));
}
