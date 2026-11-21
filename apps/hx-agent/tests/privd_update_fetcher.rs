//! The update fetcher against a local HTTPS server (docs/ipc.md 6.12, "update fetcher"): release
//! hosts only, redirects only between them, TLS with a certificate that chains to the roots it was
//! given, size and time quotas, and that a failed job leaves no file behind. There is no real
//! release host; the server here is a thread speaking rustls on a loopback port with a
//! certificate made by `rcgen`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hx_agent::fetcher::{Channel, Config, FetchError, Job, run};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

#[derive(Clone, Default)]
struct Route {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    chunked: bool,
    /// No `Content-Length` and not chunked.
    unframed: bool,
    /// Send only this many body bytes, then close (a truncated response).
    cut_at: Option<usize>,
    /// Stall this long after the head, before the body.
    stall: Duration,
    /// Declare this `Content-Length` instead of the real one.
    declared_len: Option<usize>,
}

fn ok(body: &[u8]) -> Route {
    Route {
        status: 200,
        body: body.to_vec(),
        ..Route::default()
    }
}

fn redirect(to: &str) -> Route {
    Route {
        status: 302,
        headers: vec![("Location".into(), to.into())],
        ..Route::default()
    }
}

struct TestServer {
    port: u16,
    roots: Arc<RootCertStore>,
    routes: Arc<Mutex<HashMap<String, Route>>>,
    hits: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl TestServer {
    fn start() -> Self {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert: CertificateDer<'static> = ck.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = Arc::new(
            ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key.into())
                .unwrap(),
        );
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let routes: Arc<Mutex<HashMap<String, Route>>> = Arc::default();
        let hits: Arc<Mutex<Vec<String>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        {
            let (routes, hits, stop) = (routes.clone(), hits.clone(), stop.clone());
            std::thread::spawn(move || {
                for conn in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(tcp) = conn else { continue };
                    let (cfg, routes, hits) = (cfg.clone(), routes.clone(), hits.clone());
                    std::thread::spawn(move || serve(tcp, cfg, &routes, &hits));
                }
            });
        }
        Self {
            port,
            roots: Arc::new(roots),
            routes,
            hits,
            stop,
        }
    }

    fn route(&self, path: &str, r: Route) {
        self.routes.lock().unwrap().insert(path.to_string(), r);
    }

    fn hits(&self) -> Vec<String> {
        self.hits.lock().unwrap().clone()
    }

    fn config(&self, out: &std::path::Path) -> Config {
        Config {
            hosts: vec!["localhost".into()],
            port: self.port,
            releases_path: "/rel".into(),
            arch: "x86_64".into(),
            roots: self.roots.clone(),
            out_dir: out.to_path_buf(),
            allow_non_global: true,
            connect_timeout: Duration::from_secs(2),
            manifest_timeout: Duration::from_secs(3),
            artifact_timeout: Duration::from_secs(3),
            max_manifest: 1024,
            max_artifact: 4096,
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn serve(
    tcp: TcpStream,
    cfg: Arc<ServerConfig>,
    routes: &Mutex<HashMap<String, Route>>,
    hits: &Mutex<Vec<String>>,
) {
    let Ok(conn) = ServerConnection::new(cfg) else {
        return;
    };
    let mut tls = StreamOwned::new(conn, tcp);
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tls.read(&mut b) {
            Ok(1) => head.push(b[0]),
            _ => return,
        }
        if head.len() > 8192 {
            return;
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let path = text.split(' ').nth(1).unwrap_or("").to_string();
    hits.lock().unwrap().push(path.clone());
    let route = routes.lock().unwrap().get(&path).cloned();
    let Some(r) = route else {
        let _ = tls
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let _ = tls.flush();
        return;
    };
    let mut out = format!("HTTP/1.1 {} X\r\n", r.status);
    for (k, v) in &r.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    if r.chunked {
        out.push_str("Transfer-Encoding: chunked\r\n");
    } else if !r.unframed {
        out.push_str(&format!(
            "Content-Length: {}\r\n",
            r.declared_len.unwrap_or(r.body.len())
        ));
    }
    out.push_str("Connection: close\r\n\r\n");
    let _ = tls.write_all(out.as_bytes());
    let _ = tls.flush();
    std::thread::sleep(r.stall);
    let body = match r.cut_at {
        Some(n) => &r.body[..n.min(r.body.len())],
        None => &r.body[..],
    };
    if r.chunked {
        for part in body.chunks(7) {
            let _ = tls.write_all(format!("{:x}\r\n", part.len()).as_bytes());
            let _ = tls.write_all(part);
            let _ = tls.write_all(b"\r\n");
        }
        if r.cut_at.is_none() {
            let _ = tls.write_all(b"0\r\n\r\n");
        }
    } else {
        let _ = tls.write_all(body);
    }
    let _ = tls.flush();
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

fn files(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

const MANIFEST: &str = "/rel/channel-stable/manifest-x86_64.json";
const SIG: &str = "/rel/channel-stable/manifest-x86_64.json.minisig";
const ARTIFACT: &str = "/rel/v1.4.2/hx-1.4.2-x86_64.tar.gz";

#[test]
fn a_manifest_job_downloads_both_files() {
    let s = TestServer::start();
    s.route(MANIFEST, ok(b"{\"manifest\":true}"));
    s.route(SIG, ok(b"untrusted comment: sig\n"));
    let out = tempfile::tempdir().unwrap();
    run(&Job::Manifest(Channel::Stable), &s.config(out.path())).unwrap();
    assert_eq!(
        files(out.path()),
        ["manifest.json", "manifest.json.minisig"]
    );
    assert_eq!(
        std::fs::read(out.path().join("manifest.json")).unwrap(),
        b"{\"manifest\":true}"
    );
    // Readable by root without CAP_DAC_OVERRIDE: 0644, a regular file.
    let mode = std::fs::metadata(out.path().join("manifest.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o7777, 0o644);
    assert_eq!(s.hits(), [MANIFEST, SIG]);
}

#[test]
fn an_artifact_job_downloads_one_file_framed_either_way() {
    let s = TestServer::start();
    let body: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    s.route(ARTIFACT, ok(&body));
    let out = tempfile::tempdir().unwrap();
    run(&Job::Artifact("1.4.2".into()), &s.config(out.path())).unwrap();
    assert_eq!(
        std::fs::read(out.path().join("artifact.tar.gz")).unwrap(),
        body
    );
    // Chunked.
    std::fs::remove_file(out.path().join("artifact.tar.gz")).unwrap();
    s.route(
        ARTIFACT,
        Route {
            chunked: true,
            ..ok(&body)
        },
    );
    run(&Job::Artifact("1.4.2".into()), &s.config(out.path())).unwrap();
    assert_eq!(
        std::fs::read(out.path().join("artifact.tar.gz")).unwrap(),
        body
    );
}

#[test]
fn redirects_are_followed_between_release_hosts_only() {
    let s = TestServer::start();
    s.route(ARTIFACT, redirect("/rel/cdn/blob"));
    s.route(
        "/rel/cdn/blob",
        redirect(&format!("https://localhost:{}/rel/cdn/final", s.port)),
    );
    s.route("/rel/cdn/final", ok(b"payload"));
    let out = tempfile::tempdir().unwrap();
    run(&Job::Artifact("1.4.2".into()), &s.config(out.path())).unwrap();
    assert_eq!(
        std::fs::read(out.path().join("artifact.tar.gz")).unwrap(),
        b"payload"
    );
    std::fs::remove_file(out.path().join("artifact.tar.gz")).unwrap();

    // To a host that is not a release host: refused before any connection to it.
    for to in [
        "https://evil.example/x",
        "https://127.0.0.1/x",
        "https://localhost.evil.example/x",
        "https://user@localhost/x",
    ] {
        s.route(ARTIFACT, redirect(to));
        let e = run(&Job::Artifact("1.4.2".into()), &s.config(out.path())).unwrap_err();
        assert!(matches!(e, FetchError::Refused(_)), "{to}: {e:?}");
        assert!(
            files(out.path()).is_empty(),
            "no file after a refused redirect"
        );
    }
    // Downgrade to plain HTTP.
    s.route(ARTIFACT, redirect("http://localhost/x"));
    let e = run(&Job::Artifact("1.4.2".into()), &s.config(out.path())).unwrap_err();
    assert!(matches!(e, FetchError::Refused(_)), "{e:?}");
    // A loop.
    s.route(ARTIFACT, redirect(ARTIFACT));
    let e = run(&Job::Artifact("1.4.2".into()), &s.config(out.path())).unwrap_err();
    assert!(
        matches!(e, FetchError::Refused(m) if m.contains("redirects")),
        "loop"
    );
    // A redirect to another port is not followed to that port.
    s.route(ARTIFACT, redirect("https://localhost:1/x"));
    assert!(run(&Job::Artifact("1.4.2".into()), &s.config(out.path())).is_err());
}

#[test]
fn a_host_that_is_not_in_the_list_is_never_contacted() {
    let s = TestServer::start();
    s.route(MANIFEST, ok(b"x"));
    s.route(SIG, ok(b"x"));
    let out = tempfile::tempdir().unwrap();
    let mut cfg = s.config(out.path());
    cfg.hosts = vec!["not-localhost.example".into()];
    let e = run(&Job::Manifest(Channel::Stable), &cfg).unwrap_err();
    assert!(
        matches!(
            e,
            FetchError::Resolve(_) | FetchError::Io(_) | FetchError::Refused(_)
        ),
        "{e:?}"
    );
    assert!(s.hits().is_empty());
}

#[test]
fn size_quotas_are_enforced_and_a_failed_job_leaves_nothing() {
    let s = TestServer::start();
    let out = tempfile::tempdir().unwrap();
    // Content-Length over the limit: refused before the body is read.
    s.route(ARTIFACT, ok(&vec![1u8; 5000]));
    let e = run(&Job::Artifact("1.4.2".into()), &s.config(out.path())).unwrap_err();
    assert!(matches!(e, FetchError::Quota(_)), "{e:?}");
    // Chunked, with no length to check up front.
    s.route(
        ARTIFACT,
        Route {
            chunked: true,
            ..ok(&vec![1u8; 5000])
        },
    );
    let e = run(&Job::Artifact("1.4.2".into()), &s.config(out.path())).unwrap_err();
    assert!(matches!(e, FetchError::Quota(_)), "{e:?}");
    // A manifest over its own limit, after the first file has been written: both are removed.
    s.route(MANIFEST, ok(b"small"));
    s.route(SIG, ok(&vec![b'x'; 2000]));
    let e = run(&Job::Manifest(Channel::Stable), &s.config(out.path())).unwrap_err();
    assert!(matches!(e, FetchError::Quota(_)), "{e:?}");
    assert!(files(out.path()).is_empty(), "{:?}", files(out.path()));
    // Exactly at the limit is fine.
    s.route(ARTIFACT, ok(&vec![1u8; 4096]));
    run(&Job::Artifact("1.4.2".into()), &s.config(out.path())).unwrap();
}

#[test]
fn bad_responses_are_refused() {
    let s = TestServer::start();
    let out = tempfile::tempdir().unwrap();
    let job = Job::Artifact("1.4.2".into());
    // 404 (no route), 500, and a 200 whose body ends early.
    let e = run(&job, &s.config(out.path())).unwrap_err();
    assert!(matches!(e, FetchError::Response(m) if m.contains("404")));
    s.route(
        ARTIFACT,
        Route {
            status: 500,
            ..Route::default()
        },
    );
    assert!(matches!(
        run(&job, &s.config(out.path())).unwrap_err(),
        FetchError::Response(_)
    ));
    s.route(
        ARTIFACT,
        Route {
            cut_at: Some(10),
            declared_len: Some(100),
            ..ok(&[7u8; 100])
        },
    );
    assert!(run(&job, &s.config(out.path())).is_err());
    // A body with no framing (it could be cut anywhere without anyone noticing).
    s.route(
        ARTIFACT,
        Route {
            unframed: true,
            ..ok(b"abc")
        },
    );
    assert!(matches!(
        run(&job, &s.config(out.path())).unwrap_err(),
        FetchError::Response(_)
    ));
    // A redirect with no Location.
    s.route(
        ARTIFACT,
        Route {
            status: 302,
            ..Route::default()
        },
    );
    assert!(matches!(
        run(&job, &s.config(out.path())).unwrap_err(),
        FetchError::Response(_)
    ));
    // Content-Encoding the fetcher did not ask for.
    s.route(
        ARTIFACT,
        Route {
            headers: vec![("Content-Encoding".into(), "gzip".into())],
            ..ok(b"abc")
        },
    );
    assert!(matches!(
        run(&job, &s.config(out.path())).unwrap_err(),
        FetchError::Response(_)
    ));
    assert!(files(out.path()).is_empty());
}

#[test]
fn the_overall_timeout_stops_a_stalled_server() {
    let s = TestServer::start();
    s.route(
        ARTIFACT,
        Route {
            stall: Duration::from_secs(10),
            ..ok(b"late")
        },
    );
    let out = tempfile::tempdir().unwrap();
    let mut cfg = s.config(out.path());
    cfg.artifact_timeout = Duration::from_millis(800);
    let started = Instant::now();
    let e = run(&Job::Artifact("1.4.2".into()), &cfg).unwrap_err();
    assert!(matches!(e, FetchError::Timeout(_)), "{e:?}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert!(files(out.path()).is_empty());
}

#[test]
fn a_connection_that_never_opens_times_out_on_connect() {
    // A listener that never accepts: the handshake never completes, the deadline ends it.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let s = TestServer::start();
    let out = tempfile::tempdir().unwrap();
    let mut cfg = s.config(out.path());
    cfg.port = port;
    cfg.manifest_timeout = Duration::from_millis(600);
    let started = Instant::now();
    let e = run(&Job::Manifest(Channel::Stable), &cfg).unwrap_err();
    assert!(
        matches!(e, FetchError::Timeout(_) | FetchError::Io(_)),
        "{e:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(l);
}

#[test]
fn a_certificate_that_does_not_chain_to_the_roots_is_refused() {
    let s = TestServer::start();
    s.route(ARTIFACT, ok(b"payload"));
    let out = tempfile::tempdir().unwrap();
    let other = TestServer::start();
    let mut cfg = s.config(out.path());
    // The roots of another server: this one's certificate is not trusted.
    cfg.roots = other.roots.clone();
    let e = run(&Job::Artifact("1.4.2".into()), &cfg).unwrap_err();
    assert!(matches!(e, FetchError::Tls(_) | FetchError::Io(_)), "{e:?}");
    assert!(files(out.path()).is_empty());
    assert!(
        s.hits().is_empty(),
        "no request was sent over an untrusted connection"
    );
    // An empty trust store trusts nothing.
    cfg.roots = Arc::new(RootCertStore::empty());
    assert!(run(&Job::Artifact("1.4.2".into()), &cfg).is_err());
}

#[test]
fn a_plain_http_server_is_not_spoken_to() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let mut c = c;
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc");
        }
    });
    let s = TestServer::start();
    let out = tempfile::tempdir().unwrap();
    let mut cfg = s.config(out.path());
    cfg.port = port;
    let e = run(&Job::Artifact("1.4.2".into()), &cfg).unwrap_err();
    assert!(!matches!(e, FetchError::Quota(_)));
    assert!(files(out.path()).is_empty());
}

#[test]
fn non_global_addresses_are_refused_unless_a_test_allows_them() {
    let s = TestServer::start();
    s.route(ARTIFACT, ok(b"payload"));
    let out = tempfile::tempdir().unwrap();
    let mut cfg = s.config(out.path());
    cfg.allow_non_global = false;
    let e = run(&Job::Artifact("1.4.2".into()), &cfg).unwrap_err();
    assert!(
        matches!(e, FetchError::Resolve(_)),
        "localhost resolves to loopback: {e:?}"
    );
    assert!(s.hits().is_empty());
}

#[test]
fn the_output_files_are_created_exclusively_and_never_overwritten_or_followed() {
    let s = TestServer::start();
    s.route(ARTIFACT, ok(b"payload"));
    let out = tempfile::tempdir().unwrap();
    let victim = out.path().join("victim");
    std::fs::write(&victim, b"keep").unwrap();
    std::os::unix::fs::symlink(&victim, out.path().join("artifact.tar.gz")).unwrap();
    let e = run(&Job::Artifact("1.4.2".into()), &s.config(out.path())).unwrap_err();
    assert!(matches!(e, FetchError::Io(_)), "{e:?}");
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
}

#[test]
fn the_binary_accepts_exactly_one_valid_job() {
    let bin = env!("CARGO_BIN_EXE_hx-update-fetcher");
    let run_with = |args: &[&str]| {
        std::process::Command::new(bin)
            .args(args)
            .env_clear()
            .output()
            .unwrap()
    };
    for args in [
        vec![],
        vec!["manifest-stable", "extra"],
        vec!["manifest-nightly"],
        vec!["artifact-1.2"],
        vec!["artifact-../../x"],
        vec!["https://github.com/x"],
        vec![""],
    ] {
        let o = run_with(&args);
        assert_eq!(
            o.status.code(),
            Some(2),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(o.stdout.is_empty());
    }
}
