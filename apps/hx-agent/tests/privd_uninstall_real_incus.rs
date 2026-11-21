//! privd's `Uninstall` against a **real** Incus: `#[ignore]`d and gated on `HX1E_REAL=1`.
//!
//! ```text
//! HX1E_REAL=1 sg incus-admin -c 'cargo nextest run -p hx-agent --run-ignored only \
//!     --test privd_uninstall_real_incus --no-capture'
//! ```
//!
//! It builds the host objects with `hx_provision::ensure_host` under the prefix `hx1e-`
//! (`hx1e-pool`, `hx1e-br0`, `hx1e-isolate`, `hx1e-desktop`, `hx1e-compat-debian13`), an empty
//! (never started) instance `hx1e-main` with a session-link proxy device, and runs privd's
//! `Uninstall` in keep mode and then in destroy mode, in-process on a temporary directory.
//!
//! It touches **only `hx1e-` objects**: it never uses the `default` pool, `incusbr0`, the `default`
//! profile or Docker, never loads an nftables ruleset and never runs `iptables` or `sysctl`
//! (privd's runner is a stand-in that answers "no table" and "no chain"; the ruleset and sysctl
//! files are in the test's temporary directory). Before and after, it lists every storage pool,
//! network and profile and asserts that, apart from the `hx1e-` ones, the lists are identical.
//! Everything it creates is removed again, also before the run and after a failure.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hx_agent::privd::audit::MemoryAudit;
use hx_agent::privd::clock::SystemClock;
use hx_agent::privd::config::PrivdConfig;
use hx_agent::privd::daemon::{Ctx, Daemon, Deps};
use hx_agent::privd::identity::GatewayIdentity;
use hx_agent::privd::runner::RunOutput;
use hx_agent::privd::testing::{FakeProbe, FakeRunner, error_of, request};
use hx_ipc::privd::pb::{self, Role, request::Command, response::Result as R};
use hx_provision::host::{HostSpec, MIN_POOL_GIB, Naming, PoolSource, ensure_host};
use hx_provision::incus::{
    Client, ImageSource, IncusError, InstanceCreate, Request, Response, SessionLink, Transport,
    UnixTransport,
};
use hx_provision::teardown::{destroy_desktop, teardown_host};
use serde_json::Value;

const PREFIX: &str = "hx1e-";
const INSTANCE: &str = "hx1e-main";

macro_rules! evidence {
    ($label:expr, $($arg:tt)*) => {
        eprintln!("EVIDENCE [{}] {}", $label, format!($($arg)*).trim_end().replace('\n', "\n    | "))
    };
}

fn socket() -> String {
    std::env::var("HX_INCUS_SOCKET").unwrap_or_else(|_| UnixTransport::DEFAULT_SOCKET.to_string())
}

fn naming() -> Naming {
    Naming::with_prefix(PREFIX).unwrap()
}

/// Turns the one create request of this test into an empty instance (`source.type = none`), so
/// that no image is downloaded and nothing can start. Every other request passes unchanged.
#[derive(Clone)]
struct EmptyInstance(UnixTransport);

impl Transport for EmptyInstance {
    async fn send(&self, mut req: Request) -> Result<Response, IncusError> {
        if req.method == hyper::Method::POST && req.path == "/1.0/instances" {
            let mut v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            assert!(
                v["name"].as_str().is_some_and(|n| n.starts_with(PREFIX)),
                "this shim creates hx1e- instances only"
            );
            v["source"] = serde_json::json!({"type": "none"});
            req.body = Bytes::from(serde_json::to_vec(&v).unwrap());
        }
        self.0.send(req).await
    }
}

/// Names in a collection (`storage-pools`, `networks`, `profiles`), excluding ours.
async fn others(collection: &str) -> Vec<String> {
    let t = UnixTransport::new(socket());
    let r = t
        .send(Request {
            method: hyper::Method::GET,
            path: format!("/1.0/{collection}"),
            headers: vec![],
            body: Bytes::new(),
            content_type: None,
            max_response: None,
            timeout: Duration::from_secs(30),
        })
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&r.body).unwrap();
    let mut names: Vec<String> = v["metadata"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p.as_str())
        .map(|p| p.rsplit('/').next().unwrap().to_string())
        .filter(|n| !n.starts_with(PREFIX))
        .collect();
    names.sort();
    names
}

async fn world_snapshot() -> [Vec<String>; 3] {
    [
        others("storage-pools").await,
        others("networks").await,
        others("profiles").await,
    ]
}

async fn cleanup(c: &Client<UnixTransport>) {
    if let Err(e) = destroy_desktop(c, INSTANCE).await {
        eprintln!("cleanup: destroy_desktop: {e}");
    }
    match teardown_host(c, &naming()).await {
        Ok(r) => eprintln!("cleanup: {r:?}"),
        Err(e) => eprintln!("cleanup: teardown_host: {e}"),
    }
}

fn expect_uninstall(r: pb::Response) -> pb::UninstallResult {
    match r.result {
        Some(R::Uninstall(u)) => u,
        Some(R::Error(e)) => panic!("{:?} {:?}: {}", e.code(), e.detail(), e.message),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a real Incus (sg incus-admin) and HX1E_REAL=1"]
async fn uninstall_keeps_then_destroys_hx1e_objects_on_a_real_incus() {
    if std::env::var("HX1E_REAL").as_deref() != Ok("1") {
        eprintln!("HX1E_REAL is not 1: skipping");
        return;
    }
    let c = Client::unix(socket());
    cleanup(&c).await;
    let before = world_snapshot().await;
    evidence!("before", "{before:?}");
    let tmp = std::path::PathBuf::from(format!("/tmp/hx1e-{}", std::process::id()));
    let body = tokio::spawn(run_real(c.clone(), tmp.clone()));
    let result = body.await;
    cleanup(&c).await;
    let _ = std::fs::remove_dir_all(&tmp);
    // Nothing of ours remains, and nothing else changed.
    let n = naming();
    assert!(c.get_instance(INSTANCE).await.unwrap().is_none());
    assert!(c.get_storage_pool(&n.pool).await.unwrap().is_none());
    assert!(c.get_network(&n.bridge).await.unwrap().is_none());
    assert!(!c.acl_exists(&n.acl).await.unwrap());
    assert!(!c.profile_exists(&n.desktop_profile).await.unwrap());
    assert!(!c.profile_exists(&n.compat_profile).await.unwrap());
    let after = world_snapshot().await;
    assert_eq!(before, after, "an object that is not ours changed");
    evidence!(
        "after",
        "no hx1e- object remains; the other objects are unchanged"
    );
    if let Err(e) = result {
        std::panic::resume_unwind(e.into_panic());
    }
}

async fn run_real(c: Client<UnixTransport>, tmp: std::path::PathBuf) {
    let n = naming();
    // --- host objects, an empty instance and its link device -------------------------------------
    ensure_host(
        &c,
        &HostSpec {
            naming: n.clone(),
            pool: PoolSource::LoopFile {
                size_gib: MIN_POOL_GIB,
            },
            ipv4: "auto".into(),
            host_addresses: vec![],
            allow_private_networks: false,
        },
    )
    .await
    .unwrap();
    let empty = Client::new(EmptyInstance(UnixTransport::new(socket())));
    empty
        .create_instance(
            &InstanceCreate {
                name: INSTANCE.into(),
                image: ImageSource::LocalAlias("none".into()),
                profiles: vec![n.desktop_profile.clone()],
                config: [("user.hx.state".to_string(), "ready".to_string())]
                    .into_iter()
                    .collect(),
                devices: Default::default(),
            },
            Duration::from_secs(120),
        )
        .await
        .unwrap();
    let link = SessionLink::new("main", (990, 990), (1000, 1000)).unwrap();
    c.add_session_link(INSTANCE, &link).await.unwrap();
    assert!(
        c.get_instance(INSTANCE)
            .await
            .unwrap()
            .unwrap()
            .devices
            .contains_key("hx-link")
    );

    // --- privd, in-process, with a runner that cannot touch the host -----------------------------
    std::fs::create_dir_all(&tmp).unwrap();
    let me = rustix::process::getuid().as_raw();
    let mut cfg = PrivdConfig::for_tests(
        &tmp,
        GatewayIdentity {
            uid: me,
            gid: rustix::process::getgid().as_raw(),
        },
    );
    cfg.naming = n.clone();
    cfg.instance_prefix = PREFIX.into();
    std::fs::write(&cfg.firewall_file, "table inet hx1e {}\n").unwrap();
    std::fs::write(&cfg.sysctl_file, "# hx1e\n").unwrap();
    // "No nft table, no DOCKER-USER chain": nothing is run, nothing is changed.
    let runner = FakeRunner::with(|_| RunOutput {
        code: Some(1),
        ..Default::default()
    });
    let audit = Arc::new(MemoryAudit::default());
    let d = Daemon::new(
        cfg.clone(),
        Client::unix(socket()),
        Deps {
            runner: runner.clone(),
            probe: Arc::new(FakeProbe::default()),
            clock: Arc::new(SystemClock),
            audit,
        },
    )
    .unwrap();
    d.register_desktop("main").unwrap();
    let call = |keep: bool| {
        let d = d.clone();
        async move {
            d.handle(
                request(
                    1,
                    Command::Uninstall(pb::UninstallRequest {
                        keep_desktop: keep,
                        confirm_destroy: !keep,
                    }),
                ),
                Ctx::new(Role::Admin),
            )
            .await
        }
    };

    // --- keep ------------------------------------------------------------------------------------
    let keep = expect_uninstall(call(true).await);
    evidence!("keep", "{keep:?}");
    assert!(keep.keep_desktop);
    assert_eq!(keep.removed, ["session-link:main"]);
    let inst = c
        .get_instance(INSTANCE)
        .await
        .unwrap()
        .expect("the desktop stays");
    assert!(
        !inst.devices.contains_key("hx-link"),
        "the proxy device is gone"
    );
    assert!(c.get_storage_pool(&n.pool).await.unwrap().is_some());
    assert!(c.get_network(&n.bridge).await.unwrap().is_some());
    assert!(c.acl_exists(&n.acl).await.unwrap());
    assert!(c.profile_exists(&n.desktop_profile).await.unwrap());
    // The gate is up.
    let r = d
        .handle(
            request(2, Command::GetHostInfo(Default::default())),
            Ctx::new(Role::Gateway),
        )
        .await;
    assert_eq!(
        error_of(&r).map(|e| e.detail()),
        Some(pb::ErrorDetail::Uninstalling)
    );

    // --- destroy ---------------------------------------------------------------------------------
    let destroy = expect_uninstall(call(false).await);
    evidence!("destroy", "{destroy:?}");
    assert!(!destroy.keep_desktop);
    for what in [
        "session-link:main",
        "desktop:main",
        "profile:hx1e-desktop",
        "profile:hx1e-compat-debian13",
        "network:hx1e-br0",
        "acl:hx1e-isolate",
        "pool:hx1e-pool",
    ] {
        assert!(
            destroy.removed.iter().any(|r| r == what),
            "{what} in {:?}",
            destroy.removed
        );
    }
    assert!(destroy.warnings.is_empty(), "{:?}", destroy.warnings);
    assert!(c.get_instance(INSTANCE).await.unwrap().is_none());
    assert!(c.get_storage_pool(&n.pool).await.unwrap().is_none());
    assert!(c.get_network(&n.bridge).await.unwrap().is_none());
    assert!(!cfg.firewall_file.exists() && !cfg.sysctl_file.exists());
    // The runner was only ever asked the two read-only questions and, since the answers were "no",
    // nothing else; it is a stand-in anyway.
    let calls: Vec<String> = runner
        .calls()
        .iter()
        .map(|p| format!("{:?} {}", p.tool, p.args.join(" ")))
        .collect();
    evidence!("runner", "{calls:?}");
    assert!(
        calls.iter().all(|c| c.contains("list") || c.contains("-L")),
        "{calls:?}"
    );

    // --- again: idempotent -----------------------------------------------------------------------
    let again = expect_uninstall(call(false).await);
    assert_eq!(again.removed, destroy.removed);
}
