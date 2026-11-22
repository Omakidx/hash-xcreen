//! End to end under real network impairment: install-equivalent stack, pair, PIN login, connect,
//! type and scroll, idle, disconnect, reconnect, once per network profile (LAN, broadband, lossy,
//! mobile-ish), and the macro run of the performance suite (the LAN profile repeated).
//!
//! ```text
//! HX_E2E_NETEM=1 cargo nextest run -p hx-agent --run-ignored only --test e2e_netem \
//!     --no-capture -E 'test(netem_e2e_over_all_profiles)'
//! HX_PERF=1 HX_PERF_RUNS=5 cargo nextest run --release -p hx-agent --run-ignored only \
//!     --test e2e_netem --no-capture -E 'test(perf_macro_lan)'
//! ```
//!
//! Unprivileged: the network is made of two network namespaces inside a user namespace
//! (`unshare -rn`) joined by a veth pair with `tc netem` on both ends (see
//! `perf_common/net.rs`), and each profile is *measured* (ping RTT, ping loss, UDP rate) before
//! the flow starts; a netem that does nothing fails the run. Needs `unshare`, `ip`, `tc`,
//! `nsenter`, `ping`, Xvfb, FFmpeg (x264) and permission to create user namespaces (on Ubuntu
//! 24.04 runners: `sysctl kernel.apparmor_restrict_unprivileged_userns=0`).
//!
//! The process layout (the test binary re-executes itself, selected by `HX_NETEM_ROLE`):
//!
//! ```text
//! controller (this test, host namespaces)
//!   `unshare -rn` -> orchestrator (server namespace: Xvfb, desk, hx-session, hx-gatewayd)
//!                      `nsenter -n` -> client (client namespace)
//! ```
//!
//! Thresholds and their rationale are in `docs/testing.md`; they live in
//! `perf_common/result.rs` and are unit-tested there.

mod e2e_common;
mod gateway_common;
mod perf_common;

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use perf_common::net::{self, PROFILES, Profile};
use perf_common::result::{self, RunResult};
use perf_common::stack::{self, Opts};

fn parse_res(default: &str) -> (u32, u32) {
    let v = std::env::var("HX_PERF_RES").unwrap_or_else(|_| default.into());
    let (w, h) = v.split_once('x').expect("HX_PERF_RES is WIDTHxHEIGHT");
    (w.parse().unwrap(), h.parse().unwrap())
}

/// The text after `tag` on a line. libtest prints "test name ... " before a test that prints
/// with `--nocapture`, so a tag is not always at the start of the line.
fn tagged<'a>(line: &'a str, tag: &str) -> Option<&'a str> {
    line.find(tag).map(|i| &line[i + tag.len()..])
}

fn have_netns() -> Result<(), String> {
    let ok = Command::new("unshare")
        .args(["-rn", "true"])
        .stdin(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if ok {
        Ok(())
    } else {
        Err("`unshare -rn` failed: unprivileged user namespaces are not available (on Ubuntu 24.04: sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0)".into())
    }
}

/// Builds `hx-session` next to the gateway binary when it is not there (cargo test builds the
/// gateway binary for this crate's tests, not the other package's).
fn ensure_session_binary() -> PathBuf {
    let bin = stack::session_binary();
    if bin.exists() {
        return bin;
    }
    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.args(["build", "-p", "hx-session", "--bin", "hx-session"]);
    if !cfg!(debug_assertions) {
        cmd.arg("--release");
    }
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"));
    let ok = cmd.status().is_ok_and(|s| s.success());
    assert!(
        ok && bin.exists(),
        "could not build hx-session at {}",
        bin.display()
    );
    bin
}

/// Runs the orchestrator for `p` under `unshare -rn` and returns its result.
fn run_orchestrator(p: &Profile, res: (u32, u32)) -> RunResult {
    have_netns().unwrap();
    let session = ensure_session_binary();
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new("unshare")
        .args(["-rn", "--"])
        .arg(&exe)
        .args([
            "--exact",
            "netem_role_orchestrator",
            "--ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("HX_NETEM_ROLE", "orchestrator")
        .env("HX_NETEM_PROFILE", p.name)
        .env("HX_NETEM_SESSION_BIN", &session)
        .env("HX_PERF_RES", format!("{}x{}", res.0, res.1))
        .env("HX_REQUIRE_XVFB", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the orchestrator");
    let out = child.stdout.take().unwrap();
    // A hung run must not hang the test run.
    let pid = child.id();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let d2 = done.clone();
    let watchdog = std::thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(900);
        while Instant::now() < end {
            if d2.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
    });
    let mut json = None;
    for line in BufReader::new(out).lines().map_while(Result::ok) {
        if let Some(j) = tagged(&line, "HXRESULT ") {
            json = Some(j.to_string());
        }
    }
    let status = child.wait().unwrap();
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = watchdog.join();
    let json = json.unwrap_or_else(|| {
        panic!(
            "the orchestrator for {} produced no result (exit {status:?})",
            p.name
        )
    });
    serde_json::from_str(&json).expect("the orchestrator's result")
}

fn print_result(r: &RunResult) {
    let c = &r.client;
    if std::env::var_os("HX_NETEM_LOGS").is_some() {
        eprintln!("FIRSTFRAMES [{}] {}", r.profile, c.first_frames.join("; "));
        eprintln!("KEYFRAMES [{}] {}", r.profile, c.key_frames.join("; "));
        for l in &c.server_stats {
            eprintln!("SERVERSTATS [{}] {l}", r.profile);
        }
    }
    let lat = |p: &result::Phase| {
        p.latency.as_ref().map_or("n/a".to_string(), |l| {
            format!(
                "p50 {:.1} p95 {:.1} p99 {:.1} max {:.1} ms ({}/{} seen)",
                l.p50, l.p95, l.p99, l.max, l.seen, l.events
            )
        })
    };
    eprintln!(
        "RESULT [{}] rtt {} ms, {} {}, load {:.1} on {} cpus{}",
        r.profile,
        r.rtt_ms,
        r.resolution,
        if r.release_build { "release" } else { "debug" },
        r.loadavg_1m,
        r.cpus,
        if r.noisy { " (NOISY HOST)" } else { "" }
    );
    eprintln!(
        "RESULT [{}] pair {:.0} ms, login {:.0} ms (transport ping {:.1} ms), first frame {:.0} ms, stream {}",
        r.profile, c.pair_ms, c.login_ms, c.transport_rtt_ms, c.first_frame_ms, c.stream
    );
    for ph in [&c.typing, &c.scroll] {
        eprintln!(
            "RESULT [{}] {}: {} frames ({} key) in {:.1}s, {:.0} kbit/s video, {:.0} kbit/s on the wire, max gap {:.0} ms, {} decode failures, {} frame gaps, {:.2} cores (session {:.2} + gateway {:.2}); latency {}",
            r.profile,
            ph.name,
            ph.frames,
            ph.key_frames,
            ph.secs,
            ph.video_kbit_s(),
            ph.net_kbit_s(),
            ph.max_gap_ms,
            ph.decode_failures,
            ph.frame_gaps,
            ph.cores(),
            ph.session_cores,
            ph.gateway_cores,
            lat(ph)
        );
    }
    eprintln!(
        "RESULT [{}] idle: {} frames, {:.0} bytes/s on the wire, {:.3} cores (session {:.3} + gateway {:.3})",
        r.profile,
        c.idle.frames,
        c.idle.net_bytes_s(),
        c.idle.cores(),
        c.idle.session_cores,
        c.idle.gateway_cores
    );
    eprintln!(
        "RESULT [{}] gap recoveries (ms to the repairing key frame): {:?}",
        r.profile,
        c.gap_recovery_ms
            .iter()
            .map(|v| v.round())
            .collect::<Vec<_>>()
    );
    eprintln!(
        "RESULT [{}] picture: {:.3}% pixels wrong, contrast {:.0}, match {}; disconnect clean {}; reconnect {:.0} ms decoded {}; netem dropped {} packets in total",
        r.profile,
        c.mismatch_pct,
        c.contrast,
        c.final_matches,
        c.disconnect_clean,
        c.reconnect_ms,
        c.reconnect_decoded,
        r.control.netem_dropped
    );
}

fn profile_filter() -> Vec<Profile> {
    match std::env::var("HX_NETEM_PROFILES") {
        Ok(list) if !list.is_empty() => list
            .split(',')
            .map(|n| net::profile_named(n.trim()).unwrap_or_else(|| panic!("unknown profile {n}")))
            .collect(),
        _ => PROFILES.to_vec(),
    }
}

// ----- the tests the maintainer runs -----------------------------------------------------------

/// The impairment of every profile is applied for real: ping RTT, ping loss, jitter and UDP
/// rate are measured on the veth, with an unimpaired baseline. Fast (about a minute).
#[test]
#[ignore = "needs unprivileged user namespaces, ip, tc, ping; HX_E2E_NETEM=1"]
fn netem_control_proves_the_impairment_applies() {
    if std::env::var("HX_E2E_NETEM").as_deref() != Ok("1") {
        eprintln!("HX_E2E_NETEM is not 1: skipping");
        return;
    }
    have_netns().unwrap();
    let exe = std::env::current_exe().unwrap();
    for p in profile_filter() {
        let out = Command::new("unshare")
            .args(["-rn", "--"])
            .arg(&exe)
            .args([
                "--exact",
                "netem_role_control",
                "--ignored",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .env("HX_NETEM_ROLE", "control")
            .env("HX_NETEM_PROFILE", p.name)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        let mut failed = false;
        for l in text.lines().filter_map(|l| tagged(l, "HXNOTE ")) {
            eprintln!("NETEM [{}] {l}", p.name);
            failed |= l.starts_with("FAIL");
        }
        for l in text
            .lines()
            .filter(|l| l.contains("qdisc netem") || l.contains("(dropped"))
        {
            eprintln!("    | {l}");
        }
        assert!(
            out.status.success() && !failed && text.contains("HXNOTE "),
            "{} control failed:\n{text}\n{}",
            p.name,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// The whole flow under every profile, with the Gate 1 numbers on LAN and sanity bounds
/// elsewhere. About a minute per profile.
#[test]
#[ignore = "needs unprivileged user namespaces, ip, tc, ping, Xvfb, x264; HX_E2E_NETEM=1"]
fn netem_e2e_over_all_profiles() {
    if std::env::var("HX_E2E_NETEM").as_deref() != Ok("1") {
        eprintln!("HX_E2E_NETEM is not 1: skipping");
        return;
    }
    let res = parse_res("1280x720");
    let strict = std::env::var("HX_PERF_STRICT").as_deref() == Ok("1");
    let mut failures = Vec::new();
    for p in profile_filter() {
        let r = run_orchestrator(&p, res);
        print_result(&r);
        let f = result::evaluate(&r, &p, strict);
        for line in &f {
            eprintln!("FAIL [{}] {line}", p.name);
        }
        if let Ok(dir) = std::env::var("HX_NETEM_OUT") {
            let _ = std::fs::create_dir_all(&dir);
            let _ = std::fs::write(
                PathBuf::from(dir).join(format!("{}.json", p.name)),
                serde_json::to_vec_pretty(&r).unwrap(),
            );
        }
        failures.extend(f.into_iter().map(|l| format!("{}: {l}", p.name)));
    }
    assert!(
        failures.is_empty(),
        "{} bound(s) violated:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The macro run of the performance suite: the LAN profile `HX_PERF_RUNS` times (default 5) at
/// 1080p, aggregated into one JSON file (`HX_PERF_OUT`, default `target/tmp/perf-macro.json`)
/// that `perf/check.py` compares with the baseline. Fails only when a run does not complete or
/// the picture is wrong; the thresholds are `check.py`'s.
#[test]
#[ignore = "the performance macro run; HX_PERF=1; needs the same things as the netem e2e"]
fn perf_macro_lan() {
    if std::env::var("HX_PERF").as_deref() != Ok("1") {
        eprintln!("HX_PERF is not 1: skipping");
        return;
    }
    let runs: u32 = std::env::var("HX_PERF_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let res = parse_res("1920x1080");
    let mut all = Vec::new();
    for i in 0..runs {
        eprintln!("PERF run {}/{runs}", i + 1);
        let r = run_orchestrator(&net::LAN, res);
        print_result(&r);
        all.push(r);
    }
    let m = result::aggregate(all);
    let out = std::env::var("HX_PERF_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("perf-macro.json"));
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    std::fs::write(&out, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    eprintln!("PERF wrote {}", out.display());
    for (k, v) in &m.metrics {
        eprintln!("PERF {k} = {v:.4}");
    }
    let broken: Vec<String> = m
        .per_run
        .iter()
        .enumerate()
        .flat_map(|(i, r)| {
            let mut f: Vec<String> = r
                .control
                .notes
                .iter()
                .filter(|n| n.starts_with("FAIL"))
                .cloned()
                .collect();
            f.extend(r.client.errors.iter().cloned());
            if !r.client.final_matches {
                f.push("the decoded picture does not match".into());
            }
            f.into_iter().map(move |l| format!("run {}: {l}", i + 1))
        })
        .collect();
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}

// ----- the roles: the test binary re-executes itself --------------------------------------------

#[test]
#[ignore = "internal role of the netem tests"]
fn netem_role_control() {
    if std::env::var("HX_NETEM_ROLE").as_deref() != Ok("control") {
        return;
    }
    let p = net::profile_named(&std::env::var("HX_NETEM_PROFILE").unwrap()).unwrap();
    let net = net::Net::create().unwrap();
    let c = net.control(&p).unwrap();
    for n in &c.notes {
        println!("HXNOTE {n}");
    }
    println!("{}", c.tc_after);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "internal role of the netem tests"]
async fn netem_role_orchestrator() {
    if std::env::var("HX_NETEM_ROLE").as_deref() != Ok("orchestrator") {
        return;
    }
    let p = net::profile_named(&std::env::var("HX_NETEM_PROFILE").unwrap()).unwrap();
    let (w, h) = parse_res("1280x720");
    let r = stack::run_profile(&p, &Opts::from_env(w, h)).await;
    println!("HXRESULT {}", serde_json::to_string(&r).unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "internal role of the netem tests"]
async fn netem_role_client() {
    if std::env::var("HX_NETEM_ROLE").as_deref() != Ok("client") {
        return;
    }
    let path = std::env::var("HX_NETEM_PARAMS").unwrap();
    let params: perf_common::client::Params =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let rep = perf_common::client::run(params).await;
    println!("HXCLIENT {}", serde_json::to_string(&rep).unwrap());
}
