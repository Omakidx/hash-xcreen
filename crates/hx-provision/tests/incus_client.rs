//! The Incus REST client against a fake daemon on a real unix socket and recorded JSON fixtures.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::{Fake, OP_ID, fixture};
use hx_provision::incus::{
    AclAction, Client, DOCKER_MIN_INCUS, ExecSpec, ImageSource, IncusError, IncusVersion,
    InstanceCreate, StateAction, Transport, UnixTransport,
};
use serde_json::json;

fn cfg<const N: usize>(p: [(&str, &str); N]) -> BTreeMap<String, String> {
    p.into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[tokio::test]
async fn server_info_and_version_gate() {
    let fake = Fake::start().await;
    fake.with(|s| s.version = "6.0.0".into());
    let info = fake.client().server_info().await.unwrap();
    assert_eq!(info.api_version, "1.0");
    assert_eq!(info.auth, "trusted");
    assert_eq!(info.firewall, "nftables");
    assert_eq!(info.storage_drivers, ["dir", "btrfs"]);
    let v = info.version().unwrap();
    assert_eq!(v, IncusVersion::new(6, 0, 0));
    assert!(v < DOCKER_MIN_INCUS);
    fake.with(|s| s.version = "6.0.5".into());
    assert!(
        fake.client()
            .server_info()
            .await
            .unwrap()
            .version()
            .unwrap()
            >= DOCKER_MIN_INCUS
    );
}

#[test]
fn version_parsing_and_ordering() {
    let p = |s: &str| s.parse::<IncusVersion>();
    assert_eq!(p("6.0.5").unwrap(), IncusVersion::new(6, 0, 5));
    assert_eq!(p("6.0").unwrap(), IncusVersion::new(6, 0, 0));
    assert_eq!(p("7.6-ubuntu26.04").unwrap(), IncusVersion::new(7, 6, 0));
    assert_eq!(p(" 6.0.5 LTS").unwrap(), IncusVersion::new(6, 0, 5));
    assert!(
        p("").is_err()
            && p("abc").is_err()
            && p(".5").is_err()
            && p("99999999999999999999.0").is_err()
    );
    assert!(
        p("6.0.4").unwrap() < DOCKER_MIN_INCUS
            && p("6.1.0").unwrap() > DOCKER_MIN_INCUS
            && p("6.0.5").unwrap() == DOCKER_MIN_INCUS
    );
    assert!(p("10.0.0").unwrap() > p("9.9.9").unwrap());
    assert_eq!(DOCKER_MIN_INCUS.to_string(), "6.0.5");
}

#[tokio::test]
async fn fixtures_parse_and_404_means_absent() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.overrides.insert(
            "GET /1.0/storage-pools/default".into(),
            (200, fixture("storage_pool.json")),
        );
        s.overrides.insert(
            "GET /1.0/networks/incusbr0".into(),
            (200, fixture("network.json")),
        );
        s.overrides.insert(
            "GET /1.0/instances/nonexistent".into(),
            (404, fixture("error_404.json")),
        );
    });
    let c = fake.client();
    let pool = c.get_storage_pool("default").await.unwrap().unwrap();
    assert_eq!(
        (pool.driver.as_str(), pool.status.as_str()),
        ("btrfs", "Created")
    );
    assert_eq!(pool.config["size"], "60GiB");
    let net = c.get_network("incusbr0").await.unwrap().unwrap();
    assert_eq!(net.kind, "bridge");
    assert_eq!(net.config["ipv4.address"], "10.36.142.1/24");
    assert!(c.get_instance("nonexistent").await.unwrap().is_none());
    assert!(c.get_storage_pool("missing").await.unwrap().is_none());
}

#[tokio::test]
async fn api_errors_carry_code_and_message() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.overrides.insert(
            "POST /1.0/storage-pools".into(),
            (400, json!({"type":"error","error_code":400,"error":"Invalid devices: btrfs needs a block device","metadata":null}).to_string()),
        );
        s.overrides.insert("GET /1.0/networks/x".into(), (403, "Forbidden\n".into()));
    });
    let c = fake.client();
    let e = c
        .create_storage_pool("p", "btrfs", &cfg([("size", "1GiB")]))
        .await
        .unwrap_err();
    assert_eq!(
        e,
        IncusError::Api {
            code: 400,
            message: "Invalid devices: btrfs needs a block device".into()
        }
    );
    let e = c.get_network("x").await.unwrap_err();
    assert_eq!(
        e,
        IncusError::Api {
            code: 403,
            message: "Forbidden".into()
        }
    );
    assert!(!e.is_not_found());
}

#[tokio::test]
async fn connect_failure_is_an_error_not_a_panic() {
    let c = Client::unix("/nonexistent/hx-test/unix.socket");
    let e = c.server_info().await.unwrap_err();
    assert!(matches!(e, IncusError::Connect { .. }), "{e}");
    assert!(e.to_string().contains("/nonexistent/hx-test/unix.socket"));
    let t = UnixTransport::new("/x");
    assert_eq!(t.path().to_str(), Some("/x"));
}

#[tokio::test]
async fn pool_network_acl_profile_request_bodies() {
    let fake = Fake::start().await;
    let c = fake.client();
    c.create_storage_pool("hx1d-test-pool", "btrfs", &cfg([("size", "4GiB")]))
        .await
        .unwrap();
    c.create_network(
        "hx1d-test-br0",
        &cfg([("ipv4.address", "10.77.3.1/24"), ("ipv4.nat", "true")]),
    )
    .await
    .unwrap();
    let acl = hx_provision::host::isolation_acl(
        "hx1d-test-isolate",
        Some("10.77.3.1".parse().unwrap()),
        &[
            "203.0.113.7".parse().unwrap(),
            "2001:db8::7".parse().unwrap(),
        ],
    );
    c.create_acl(&acl).await.unwrap();
    c.patch_network_config(
        "hx1d-test-br0",
        &hx_provision::host::acl_attachment("hx1d-test-isolate"),
    )
    .await
    .unwrap();
    c.create_profile(&hx_provision::host::compat_profile(
        &hx_provision::Naming::with_prefix("hx1d-test-").unwrap(),
    ))
    .await
    .unwrap();
    let log = fake.log();
    assert_eq!(
        log[0].json(),
        json!({"name":"hx1d-test-pool","driver":"btrfs","config":{"size":"4GiB"}})
    );
    assert_eq!(log[1].json()["type"], "bridge");
    let acl_body = log[2].json();
    let egress = acl_body["egress"].as_array().unwrap();
    let dests: Vec<_> = egress
        .iter()
        .map(|r| {
            (
                r["action"].as_str().unwrap(),
                r["destination"].as_str().unwrap_or("*"),
            )
        })
        .collect();
    assert_eq!(
        dests,
        [
            ("drop", "169.254.0.0/16"),
            ("drop", "100.100.100.200/32"),
            ("drop", "168.63.129.16/32"),
            ("drop", "fd00:ec2::/32"),
            ("drop", "10.77.3.1/32"),
            ("drop", "203.0.113.7/32"),
            ("drop", "2001:db8::7/128"),
            ("allow", "*"),
        ]
    );
    assert!(egress.iter().all(|r| r["state"] == "enabled"));
    assert_eq!(log[3].method, "PATCH");
    assert_eq!(
        log[3].json()["config"]["security.acls"],
        "hx1d-test-isolate"
    );
    assert_eq!(
        log[3].json()["config"]["security.acls.default.egress.action"],
        "allow"
    );
    assert_eq!(log[4].json()["config"]["raw.apparmor"], "signal,");
    let _ = AclAction::Allow;
}

#[tokio::test]
async fn instance_creation_follows_the_operation_model() {
    let fake = Fake::start().await;
    let spec = InstanceCreate {
        name: "c1".into(),
        image: ImageSource::official("debian/13"),
        profiles: vec!["hx-desktop".into(), "hx-compat-debian13".into()],
        config: cfg([("limits.cpu", "2"), ("security.privileged", "false")]),
        devices: BTreeMap::new(),
    };
    fake.client()
        .create_instance(&spec, Duration::from_secs(30))
        .await
        .unwrap();
    let keys = fake.keys();
    // POST create, then a wait that says Running, then a wait that says Success.
    assert_eq!(keys[0], "POST /1.0/instances");
    assert_eq!(
        keys[1],
        format!("GET /1.0/operations/{OP_ID}/wait?timeout=30")
    );
    assert_eq!(keys[2], keys[1]);
    assert_eq!(keys.len(), 3);
    let body = fake.log()[0].json();
    assert_eq!(body["type"], "container");
    assert_eq!(
        body["source"],
        json!({"type":"image","mode":"pull","protocol":"simplestreams","server":"https://images.linuxcontainers.org","alias":"debian/13"})
    );
    assert_eq!(
        body["profiles"],
        json!(["hx-desktop", "hx-compat-debian13"])
    );
    assert_eq!(body["config"]["security.privileged"], "false");

    // Local images.
    let local = InstanceCreate {
        image: ImageSource::LocalAlias("hx-desktop".into()),
        ..spec.clone()
    };
    fake.client()
        .create_instance(&local, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(
        fake.log()[3].json()["source"],
        json!({"type":"image","alias":"hx-desktop"})
    );
    let fp = InstanceCreate {
        image: ImageSource::LocalFingerprint("ab12".into()),
        ..spec
    };
    assert_eq!(fp.image, ImageSource::LocalFingerprint("ab12".into()));
}

#[tokio::test]
async fn failed_operations_report_the_daemon_message() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.overrides.insert(
            "POST /1.0/instances".into(),
            (200, fixture("operation_async.json")),
        );
        s.overrides.insert(
            format!("GET /1.0/operations/{OP_ID}/wait?timeout=30"),
            (200, fixture("operation_failed.json")),
        );
    });
    let spec = InstanceCreate {
        name: "c1".into(),
        image: ImageSource::official("x/1"),
        profiles: vec![],
        config: BTreeMap::new(),
        devices: BTreeMap::new(),
    };
    let e = fake
        .client()
        .create_instance(&spec, Duration::from_secs(30))
        .await
        .unwrap_err();
    assert_eq!(
        e,
        IncusError::Operation("Failed instance creation: Image not found".into())
    );
}

#[tokio::test]
async fn operations_that_never_finish_time_out_and_are_cancelled() {
    let fake = Fake::start().await;
    fake.with(|s| s.stuck_ops = true);
    let spec = InstanceCreate {
        name: "c1".into(),
        image: ImageSource::official("x/1"),
        profiles: vec![],
        config: BTreeMap::new(),
        devices: BTreeMap::new(),
    };
    let e = fake
        .client()
        .create_instance(&spec, Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(matches!(e, IncusError::Timeout { .. }), "{e}");
    assert!(
        fake.keys()
            .contains(&format!("DELETE /1.0/operations/{OP_ID}")),
        "{:?}",
        fake.keys()
    );
}

#[tokio::test]
async fn state_changes_config_patch_state_and_delete() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("c1".into(), "Stopped".into());
    });
    let c = fake.client();
    c.patch_instance_config("c1", &cfg([("security.nesting", "true")]))
        .await
        .unwrap();
    c.set_state("c1", StateAction::Start, false, Duration::from_secs(30))
        .await
        .unwrap();
    let st = c.instance_state("c1").await.unwrap();
    assert!(st.is_running());
    assert_eq!(st.ipv4["eth0"], ["10.99.1.5"]);
    assert_eq!(
        c.get_instance("c1").await.unwrap().unwrap().status,
        "Running"
    );
    c.set_state("c1", StateAction::Stop, true, Duration::from_secs(30))
        .await
        .unwrap();
    let log = fake.log();
    assert_eq!(log[0].method, "PATCH");
    assert_eq!(log[0].json(), json!({"config":{"security.nesting":"true"}}));
    let start = log
        .iter()
        .find(|r| r.path == "/1.0/instances/c1/state")
        .unwrap();
    assert_eq!(
        start.json(),
        json!({"action":"start","timeout":30,"force":false,"stateful":false})
    );
    let stop = log
        .iter()
        .rev()
        .find(|r| r.path == "/1.0/instances/c1/state" && r.method == "PUT")
        .unwrap();
    assert_eq!(stop.json()["force"], true);
    hx_provision::destroy_instance(&c, "c1").await.unwrap();
    hx_provision::destroy_instance(&c, "c1").await.unwrap(); // already gone: fine
    assert!(fake.with(|s| s.instances.is_empty()));
}

#[tokio::test]
async fn snapshots_create_list_delete() {
    let fake = Fake::start().await;
    let c = fake.client();
    c.create_snapshot("c1", "hx-backup-1").await.unwrap();
    let list = c.list_snapshots("c1").await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(
        (list[0].name.as_str(), list[0].stateful),
        ("hx-backup-1", false)
    );
    assert_eq!(
        fake.log()[0].json(),
        json!({"name":"hx-backup-1","stateful":false})
    );
    c.delete_snapshot("c1", "hx-backup-1").await.unwrap();
    assert!(c.list_snapshots("c1").await.unwrap().is_empty());
}

#[tokio::test]
async fn exec_never_records_output_and_returns_only_the_status() {
    let fake = Fake::start().await;
    fake.rule("echo hi", 3, "out text\n", "err text\n");
    let spec = ExecSpec {
        command: vec!["sh".into(), "-c".into(), "echo hi".into()],
        env: vec![("A".into(), "b".into())],
        cwd: Some("/tmp".into()),
        timeout: Duration::from_secs(30),
    };
    let r = fake.client().exec("c1", &spec).await.unwrap();
    assert_eq!(
        (r.exit_code, r.stdout.as_str(), r.stderr.as_str()),
        (3, "", "")
    );
    let body = fake.log()[0].json();
    assert_eq!(body["command"], json!(["sh", "-c", "echo hi"]));
    assert_eq!(body["environment"], json!({"A":"b"}));
    assert_eq!(body["cwd"], "/tmp");
    // record-output would make the *host* write unbounded output files under /var/log/incus.
    assert_eq!(body["record-output"], false);
    assert_eq!(body["wait-for-websocket"], false);
    assert_eq!(body["interactive"], false);
    assert!(
        fake.keys().iter().all(|k| !k.contains("exec-output")),
        "{:?}",
        fake.keys()
    );
}

#[tokio::test]
async fn read_and_delete_file_are_bounded_and_missing_is_not_an_error() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.files.insert("/run/x".into(), b"hello".to_vec());
        s.overrides.insert(
            "GET /1.0/instances/c1/files?path=/run/big".into(),
            (200, "x".repeat(5000)),
        );
    });
    let c = fake.client();
    assert_eq!(
        c.read_file("c1", "/run/x", 100).await.unwrap().unwrap(),
        b"hello"
    );
    assert!(c.read_file("c1", "/run/none", 100).await.unwrap().is_none());
    assert_eq!(
        c.read_file("c1", "/run/big", 100).await.unwrap_err(),
        IncusError::TooLarge { limit: 100 }
    );
    c.delete_file("c1", "/run/x").await.unwrap();
    c.delete_file("c1", "/run/x").await.unwrap(); // already gone
    assert!(fake.with(|s| s.files.is_empty()));
    assert!(c.read_file("c1", "relative", 1).await.is_err());
}

#[tokio::test]
async fn file_push_sets_mode_at_creation_and_encodes_the_path() {
    let fake = Fake::start().await;
    let c = fake.client();
    c.push_file("c1", "/etc/hx dir/we&ird.conf", b"data", 0o600)
        .await
        .unwrap();
    c.push_dir("c1", "/run/hx", 0o700).await.unwrap();
    let log = fake.log();
    assert_eq!(
        log[0].path,
        "/1.0/instances/c1/files?path=/etc/hx%20dir/we%26ird.conf"
    );
    assert_eq!(log[0].headers["x-incus-mode"], "0600");
    assert_eq!(log[0].headers["x-incus-type"], "file");
    assert_eq!(log[0].headers["x-incus-uid"], "0");
    assert_eq!(log[0].headers["x-incus-write"], "overwrite");
    assert_eq!(log[0].body, b"data");
    assert_eq!(log[1].headers["x-incus-type"], "directory");
    assert_eq!(log[1].headers["x-incus-mode"], "0700");
    assert!(c.push_file("c1", "relative", b"", 0o600).await.is_err());
}

#[tokio::test]
async fn names_that_could_escape_the_path_are_rejected_before_any_request() {
    let fake = Fake::start().await;
    let c = fake.client();
    for bad in [
        "../x",
        "a/b",
        "",
        "a b",
        "-x",
        "x?y=1",
        "a\nb",
        &"x".repeat(64),
    ] {
        assert!(
            matches!(
                c.get_instance(bad).await,
                Err(IncusError::InvalidName { .. })
            ),
            "{bad:?}"
        );
        assert!(c.delete_network(bad).await.is_err());
        assert!(c.create_snapshot("c1", bad).await.is_err());
    }
    assert!(fake.log().is_empty());
}

/// Garbage from the daemon must produce errors, never panics.
#[tokio::test]
async fn malformed_responses_never_panic() {
    let bodies: Vec<(u16, String)> = vec![
        (200, String::new()),
        (200, "not json".into()),
        (200, "{".into()),
        (200, "null".into()),
        (200, "[]".into()),
        (200, "\"str\"".into()),
        (200, "{}".into()),
        (200, json!({"type":"weird"}).to_string()),
        (200, json!({"type":"sync"}).to_string()),
        (200, json!({"type":"sync","metadata":"text"}).to_string()),
        (200, json!({"type":"sync","metadata":[1,2,3]}).to_string()),
        (
            200,
            json!({"type":"sync","metadata":{"environment":"x"}}).to_string(),
        ),
        (
            200,
            json!({"type":"sync","metadata":{"environment":{"server_version":7}}}).to_string(),
        ),
        (200, json!({"type":"async"}).to_string()),
        (
            200,
            json!({"type":"async","operation":"/etc/passwd"}).to_string(),
        ),
        (
            200,
            json!({"type":"async","operation":"/1.0/operations/../../x"}).to_string(),
        ),
        (
            200,
            json!({"type":"async","operation":"/1.0/operations/","metadata":{"id":5}}).to_string(),
        ),
        (
            200,
            json!({"type":"async","metadata":{"id":"a b"}}).to_string(),
        ),
        (500, String::new()),
        (500, "<html>boom</html>".into()),
        (
            404,
            json!({"type":"error","error_code":"x","error":5}).to_string(),
        ),
        (
            200,
            json!({"type":"error","error_code":0,"error":""}).to_string(),
        ),
        (200, "\u{0}\u{1}\u{2}".into()),
    ];
    for (status, body) in bodies {
        let fake = Fake::start().await;
        fake.with(|s| {
            for k in [
                "GET /1.0",
                "GET /1.0/storage-pools/p",
                "POST /1.0/storage-pools",
                "GET /1.0/networks/n",
                "POST /1.0/networks",
                "PATCH /1.0/networks/n",
                "GET /1.0/network-acls/a",
                "POST /1.0/network-acls",
                "PUT /1.0/network-acls/a",
                "GET /1.0/profiles/p",
                "POST /1.0/profiles",
                "GET /1.0/instances/c1",
                "POST /1.0/instances",
                "DELETE /1.0/instances/c1",
                "PUT /1.0/instances/c1/state",
                "GET /1.0/instances/c1/state",
                "POST /1.0/instances/c1/exec",
                "GET /1.0/instances/c1/snapshots?recursion=1",
                "POST /1.0/instances/c1/snapshots",
                "POST /1.0/instances/c1/files?path=/x",
                "PATCH /1.0/instances/c1",
            ] {
                s.overrides.insert(k.to_string(), (status, body.clone()));
            }
            s.overrides.insert(
                format!("GET /1.0/operations/{OP_ID}/wait?timeout=30"),
                (status, body.clone()),
            );
        });
        let c = fake.client();
        let spec = InstanceCreate {
            name: "c1".into(),
            image: ImageSource::official("x/1"),
            profiles: vec![],
            config: BTreeMap::new(),
            devices: BTreeMap::new(),
        };
        let exec = ExecSpec {
            command: vec!["true".into()],
            env: vec![],
            cwd: None,
            timeout: Duration::from_secs(5),
        };
        // Every call returns *something* (Ok or Err) without panicking.
        let _ = c.server_info().await;
        let _ = c.get_storage_pool("p").await;
        let _ = c.create_storage_pool("p", "btrfs", &BTreeMap::new()).await;
        let _ = c.get_network("n").await;
        let _ = c.create_network("n", &BTreeMap::new()).await;
        let _ = c.patch_network_config("n", &BTreeMap::new()).await;
        let _ = c.acl_exists("a").await;
        let _ = c.profile_exists("p").await;
        let _ = c.get_instance("c1").await;
        let _ = c.create_instance(&spec, Duration::from_secs(2)).await;
        let _ = c.delete_instance("c1").await;
        let _ = c
            .set_state("c1", StateAction::Start, false, Duration::from_secs(2))
            .await;
        let _ = c.instance_state("c1").await;
        let _ = c.exec("c1", &exec).await;
        let _ = c.list_snapshots("c1").await;
        let _ = c.create_snapshot("c1", "s").await;
        let _ = c.push_file("c1", "/x", b"", 0o600).await;
        let _ = c.patch_instance_config("c1", &BTreeMap::new()).await;
        let _ = hx_provision::wait_system_running(
            &c,
            "c1",
            hx_provision::orchestrate::ReadyOptions {
                timeout: Duration::from_millis(50),
                allow_degraded: false,
            },
        )
        .await;
    }
}

#[tokio::test]
async fn exec_result_fixture_parses() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.overrides.insert(
            "POST /1.0/instances/c1/exec".into(),
            (200, fixture("operation_async.json")),
        );
        s.overrides.insert(
            format!("GET /1.0/operations/{OP_ID}/wait?timeout=30"),
            (200, fixture("exec_done.json")),
        );
    });
    let spec = ExecSpec {
        command: vec!["true".into()],
        env: vec![],
        cwd: None,
        timeout: Duration::from_secs(30),
    };
    let r = fake.client().exec("c1", &spec).await.unwrap();
    assert_eq!(r.exit_code, 0);
}

// A transport that records nothing and always fails: the client surfaces the error untouched.
struct Failing;
impl Transport for Failing {
    async fn send(
        &self,
        _r: hx_provision::incus::Request,
    ) -> Result<hx_provision::incus::Response, IncusError> {
        Err(IncusError::Http("boom".into()))
    }
}

#[tokio::test]
async fn transport_errors_propagate() {
    let c = Client::new(Failing);
    assert_eq!(
        c.server_info().await.unwrap_err(),
        IncusError::Http("boom".into())
    );
    assert_eq!(
        c.get_instance("c1").await.unwrap_err(),
        IncusError::Http("boom".into())
    );
}

#[test]
fn request_debug_never_prints_the_body() {
    use hx_provision::incus::Request;
    let r = Request {
        method: hyper::Method::POST,
        path: "/1.0/instances/c1/files?path=/run/hx-provision/stdin-1".into(),
        headers: vec![("X-Incus-mode", "0600".into())],
        body: bytes::Bytes::from_static(b"desk:SuperSecretPassword\n"),
        content_type: Some("application/octet-stream"),
        timeout: Duration::from_secs(1),
        max_response: None,
    };
    let dbg = format!("{r:?} {:#?}", r.clone());
    assert!(
        !dbg.contains("SuperSecret") && !dbg.contains("desk:"),
        "{dbg}"
    );
    assert!(dbg.contains("<25 bytes>"), "{dbg}");
}

#[tokio::test]
async fn read_file_refuses_anything_but_a_regular_file() {
    let fake = Fake::start().await;
    fake.with(|s| {
        for p in ["/run/dir", "/run/link", "/run/fifo", "/run/file"] {
            s.files.insert(p.into(), b"data".to_vec());
        }
        s.file_types.insert("/run/dir".into(), "directory".into());
        s.file_types.insert("/run/link".into(), "symlink".into());
        s.file_types.insert("/run/fifo".into(), "".into());
    });
    let c = fake.client();
    assert_eq!(
        c.read_file("c1", "/run/file", 100).await.unwrap().unwrap(),
        b"data"
    );
    for p in ["/run/dir", "/run/link", "/run/fifo"] {
        let e = c.read_file("c1", p, 100).await.unwrap_err();
        assert!(
            matches!(e, IncusError::Protocol(ref m) if m.contains("not a regular file")),
            "{p}: {e}"
        );
    }
}
