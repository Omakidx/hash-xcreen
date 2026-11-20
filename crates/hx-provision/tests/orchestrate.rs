//! Host setup, executor, desktop creation, readiness and Docker opt-in against the fake daemon.

mod common;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use common::Fake;
use hx_provision::docker::{
    DockerFallback, DockerOptions, DockerOutcome, SelfTestHint, classify_selftest, enable_docker,
    incus_supports_docker, selftest_passed,
};
use hx_provision::host::{
    Ensured, HostSpec, Naming, PoolSource, default_loop_size_gib, ensure_host, isolation_rules,
    needs_compat_profile,
};
use hx_provision::incus::{ImageSource, IncusVersion};
use hx_provision::orchestrate::{
    DesktopSpec, IncusExecutor, Limits, ProvisionError, ReadyError, ReadyOptions, build_on_server,
    finish_prebuilt, wait_system_running,
};
use hx_provision::{
    Action, Addon, ApplyError, Catalog, Desktop, Distro, ExecError, ExecRequest, Executor,
    MemSource, Preset, RecipeId, Secrets, Stage, StepFailure, apply_stage,
};
use serde_json::{Value, json};

const GIB: u64 = 1024 * 1024 * 1024;
const PASSWORD: &str = "Tr0ub4dor&3-horse-staple";

fn id(distro: Distro) -> RecipeId {
    RecipeId {
        distro,
        desktop: Desktop::Xfce,
        preset: Preset::Basic,
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

// ---------------------------------------------------------------------------------------------
// Pure host functions
// ---------------------------------------------------------------------------------------------

#[test]
fn loop_pool_is_sixty_percent_of_free_disk_within_bounds() {
    assert_eq!(default_loop_size_gib(0), 12);
    assert_eq!(default_loop_size_gib(10 * GIB), 12);
    assert_eq!(default_loop_size_gib(25 * GIB), 15);
    assert_eq!(default_loop_size_gib(100 * GIB), 60);
    assert_eq!(default_loop_size_gib(1000 * GIB), 200);
    assert_eq!(default_loop_size_gib(u64::MAX), 200);
}

#[test]
fn naming_prefix_is_validated_and_names_are_distinct_from_production() {
    let t = Naming::with_prefix("hx1d-test-").unwrap();
    assert_eq!(
        (
            t.pool.as_str(),
            t.bridge.as_str(),
            t.acl.as_str(),
            t.desktop_profile.as_str()
        ),
        (
            "hx1d-test-pool",
            "hx1d-test-br0",
            "hx1d-test-isolate",
            "hx1d-test-desktop"
        )
    );
    assert!(t.bridge.len() <= 15);
    let p = Naming::production();
    assert_eq!(p.bridge, "hxbr0");
    assert!(
        [
            &t.pool,
            &t.bridge,
            &t.acl,
            &t.desktop_profile,
            &t.compat_profile
        ]
        .iter()
        .all(|n| !n.starts_with("hx-") && **n != p.bridge)
    );
    for bad in ["", "UPPER", "has space", "waytoolongprefix", "a/b"] {
        assert!(Naming::with_prefix(bad).is_err(), "{bad}");
    }
}

#[test]
fn host_spec_validation() {
    let ok = HostSpec {
        naming: Naming::production(),
        pool: PoolSource::LoopFile { size_gib: 12 },
        ipv4: "10.77.3.1/24".into(),
        host_addresses: vec![],
        allow_private_networks: false,
    };
    assert!(ok.validate().is_ok());
    assert!(
        HostSpec {
            ipv4: "auto".into(),
            ..ok.clone()
        }
        .validate()
        .is_ok()
    );
    for bad in [
        "10.77.3.1",
        "8.8.8.8/24",
        "10.0.0.1/31",
        "10.0.0.1/xx",
        "nonsense/24",
        "10.0.0.1/7",
    ] {
        assert!(
            HostSpec {
                ipv4: bad.into(),
                ..ok.clone()
            }
            .validate()
            .is_err(),
            "{bad}"
        );
    }
    assert!(
        HostSpec {
            pool: PoolSource::LoopFile { size_gib: 0 },
            ..ok.clone()
        }
        .validate()
        .is_err()
    );
    assert!(
        HostSpec {
            pool: PoolSource::Device("/dev/sdb".into()),
            ..ok.clone()
        }
        .validate()
        .is_ok()
    );
    for bad in ["sdb", "/etc/passwd", "/dev/../etc/x", "/dev/sd b"] {
        assert!(
            HostSpec {
                pool: PoolSource::Device(bad.into()),
                ..ok.clone()
            }
            .validate()
            .is_err(),
            "{bad}"
        );
    }
    let mut long = ok;
    long.naming.bridge = "a-very-long-bridge-name".into();
    assert!(long.validate().is_err());
}

#[test]
fn isolation_rules_cover_metadata_gateway_and_hosts_without_duplicates() {
    let rules = isolation_rules(
        Some(ip("10.77.3.1")),
        &[
            ip("203.0.113.7"),
            ip("10.77.3.1"),
            ip("127.0.0.1"),
            ip("::"),
            ip("2001:db8::7"),
            ip("203.0.113.7"),
        ],
    );
    let d: Vec<String> = rules
        .iter()
        .map(|r| r.destination.clone().unwrap_or_else(|| "*".into()))
        .collect();
    assert_eq!(
        d,
        [
            "169.254.0.0/16",
            "100.100.100.200/32",
            "168.63.129.16/32",
            "fd00:ec2::/32",
            "10.77.3.1/32",
            "203.0.113.7/32",
            "2001:db8::7/128",
            "*"
        ]
    );
    // Only the last rule allows; everything before it drops.
    assert!(
        rules[..rules.len() - 1]
            .iter()
            .all(|r| format!("{:?}", r.action) == "Drop")
    );
    assert_eq!(format!("{:?}", rules.last().unwrap().action), "Allow");
    // Without a gateway or hosts the metadata rules are still there.
    assert_eq!(isolation_rules(None, &[]).len(), 5);
}

#[test]
fn compat_profile_is_for_debian_13_only() {
    let c = Catalog::embedded();
    for d in Distro::ALL {
        let plan = c.resolve(id(d), &[]).unwrap();
        assert_eq!(needs_compat_profile(&plan), d == Distro::Debian13, "{d}");
    }
}

// ---------------------------------------------------------------------------------------------
// ensure_host
// ---------------------------------------------------------------------------------------------

fn host_spec() -> HostSpec {
    HostSpec {
        naming: Naming::with_prefix("hx1d-test-").unwrap(),
        pool: PoolSource::LoopFile { size_gib: 4 },
        ipv4: "auto".into(),
        host_addresses: vec![ip("203.0.113.7")],
        allow_private_networks: false,
    }
}

#[tokio::test]
async fn ensure_host_creates_everything_once_and_is_idempotent() {
    let fake = Fake::start().await;
    let c = fake.client();
    let r = ensure_host(&c, &host_spec()).await.unwrap();
    assert_eq!(
        (
            r.pool,
            r.network,
            r.acl,
            r.desktop_profile,
            r.compat_profile
        ),
        (
            Ensured::Created,
            Ensured::Created,
            Ensured::Created,
            Ensured::Created,
            Ensured::Created
        )
    );
    assert_eq!(
        r.gateway,
        Some(ip("10.99.1.1")),
        "gateway is read back from the created network (ipv4 = auto)"
    );
    let keys = fake.keys();
    let creates: Vec<&String> = keys.iter().filter(|k| k.starts_with("POST")).collect();
    assert_eq!(
        creates,
        [
            "POST /1.0/storage-pools",
            "POST /1.0/networks",
            "POST /1.0/network-acls",
            "POST /1.0/profiles",
            "POST /1.0/profiles"
        ]
    );
    // The ACL got the real gateway; the network is attached to it afterwards.
    let acl = fake.with(|s| s.acls["hx1d-test-isolate"].clone());
    let dests: Vec<&str> = acl["egress"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["destination"].as_str())
        .collect();
    assert_eq!(
        dests,
        [
            "169.254.0.0/16",
            "100.100.100.200/32",
            "168.63.129.16/32",
            "fd00:ec2::/32",
            "10.99.1.1/32",
            "203.0.113.7/32"
        ]
    );
    let net = fake.with(|s| s.networks["hx1d-test-br0"].clone());
    assert_eq!(net["security.acls"], "hx1d-test-isolate");
    assert_eq!(net["ipv6.address"], "none");
    assert_eq!(net["ipv4.nat"], "true");
    let pool = fake.with(|s| s.pools["hx1d-test-pool"].clone());
    assert_eq!(
        (pool["driver"].as_str(), pool["config"]["size"].as_str()),
        (Some("btrfs"), Some("4GiB"))
    );
    let profile = fake.with(|s| s.profiles["hx1d-test-desktop"].clone());
    assert_eq!(profile["devices"]["root"]["pool"], "hx1d-test-pool");
    assert_eq!(profile["devices"]["eth0"]["network"], "hx1d-test-br0");

    // Second run: nothing is created, the ACL is refreshed with the (changed) host addresses.
    let before = fake.log().len();
    let mut spec = host_spec();
    spec.host_addresses = vec![ip("198.51.100.9")];
    let r2 = ensure_host(&c, &spec).await.unwrap();
    assert_eq!(
        (
            r2.pool,
            r2.network,
            r2.acl,
            r2.desktop_profile,
            r2.compat_profile
        ),
        (
            Ensured::Existed,
            Ensured::Existed,
            Ensured::Updated,
            Ensured::Existed,
            Ensured::Existed
        )
    );
    let after: Vec<String> = fake.keys()[before..].to_vec();
    assert!(
        after
            .iter()
            .all(|k| k.starts_with("GET") || k == "PUT /1.0/network-acls/hx1d-test-isolate"),
        "{after:?}"
    );
    let acl = fake.with(|s| s.acls["hx1d-test-isolate"].clone());
    assert!(
        acl["egress"].to_string().contains("198.51.100.9/32")
            && !acl["egress"].to_string().contains("203.0.113.7")
    );
}

#[tokio::test]
async fn ensure_host_rejects_a_bad_spec_before_calling_incus() {
    let fake = Fake::start().await;
    let mut spec = host_spec();
    spec.ipv4 = "8.8.8.8/24".into();
    assert!(ensure_host(&fake.client(), &spec).await.is_err());
    assert!(fake.log().is_empty());
}

// ---------------------------------------------------------------------------------------------
// DesktopSpec
// ---------------------------------------------------------------------------------------------

#[test]
fn desktop_spec_builds_an_unprivileged_container_with_limits() {
    let c = Catalog::embedded();
    let plan = c.resolve(id(Distro::Debian13), &[Addon::Docker]).unwrap();
    let naming = Naming::with_prefix("hx1d-test-").unwrap();
    let limits = Limits {
        cpu: Some(2),
        memory_mib: Some(4096),
        disk_gib: Some(40),
        processes: Some(4096),
    };
    let spec = DesktopSpec::for_plan("hx1d-test-c1", naming.clone(), &plan, limits);
    let body = spec.to_create().unwrap();
    assert_eq!(
        body.profiles,
        ["hx1d-test-desktop", "hx1d-test-compat-debian13"]
    );
    assert_eq!(body.image, ImageSource::official("debian/13"));
    assert_eq!(body.config["security.privileged"], "false");
    assert_eq!(body.config["boot.autostart"], "true");
    assert_eq!(body.config["limits.cpu"], "2");
    assert_eq!(body.config["limits.memory"], "4096MiB");
    assert_eq!(body.config["security.nesting"], "true");
    assert_eq!(body.config["security.syscalls.intercept.mknod"], "true");
    let root = &body.devices["root"];
    assert_eq!(
        (
            root["size"].as_str(),
            root["pool"].as_str(),
            root["type"].as_str()
        ),
        ("40GiB", "hx1d-test-pool", "disk")
    );

    // No limits: nothing set, no root override; Ubuntu gets no compat profile.
    let ub = c.resolve(id(Distro::Ubuntu2404), &[]).unwrap();
    let b = DesktopSpec::for_plan("c", naming.clone(), &ub, Limits::default())
        .to_create()
        .unwrap();
    assert_eq!(b.profiles, ["hx1d-test-desktop"]);
    assert!(b.devices.is_empty() && !b.config.contains_key("limits.cpu"));

    // A recipe can never turn privileged on.
    let mut sneaky = DesktopSpec::for_plan("c", naming, &ub, Limits::default());
    sneaky
        .extra_config
        .insert("security.privileged".into(), "true".into());
    assert!(sneaky.to_create().is_err());
}

// ---------------------------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn password_goes_to_the_container_through_a_0600_file_never_argv() {
    let fake = Fake::start().await;
    let c = fake.client();
    let plan = Catalog::embedded()
        .resolve(id(Distro::Debian13), &[])
        .unwrap();
    let secrets = Secrets::none().with_user_password(PASSWORD).unwrap();
    let exec = IncusExecutor::new(&c, "c1");
    apply_stage(&exec, &plan, Stage::Post, &secrets, &mut |_| {})
        .await
        .unwrap();

    let log = fake.log();
    // The password appears in exactly one request body: the file push, mode 0600, in a 0700 directory.
    let carrying: Vec<_> = log
        .iter()
        .filter(|r| String::from_utf8_lossy(&r.body).contains(PASSWORD))
        .collect();
    assert_eq!(
        carrying.len(),
        1,
        "{:?}",
        carrying.iter().map(|r| r.key()).collect::<Vec<_>>()
    );
    let push = carrying[0];
    assert_eq!(push.method, "POST");
    assert!(
        push.path
            .starts_with("/1.0/instances/c1/files?path=/run/hx-provision/stdin-"),
        "{}",
        push.path
    );
    assert_eq!(push.headers["x-incus-mode"], "0600");
    assert_eq!(push.headers["x-incus-type"], "file");
    assert_eq!(push.body, format!("desk:{PASSWORD}\n").into_bytes());
    let dir = log
        .iter()
        .find(|r| r.headers.get("x-incus-type").map(String::as_str) == Some("directory"))
        .unwrap();
    assert_eq!(dir.headers["x-incus-mode"], "0700");
    assert!(dir.path.ends_with("path=/run/hx-provision"));
    // Never in a URL, header, or exec command line; no exec records output.
    for r in &log {
        assert!(!r.path.contains(PASSWORD) && !r.path.contains("horse"));
        assert!(r.headers.values().all(|v| !v.contains(PASSWORD)));
        if r.path.ends_with("/exec") {
            assert_eq!(r.json()["record-output"], false, "{}", r.key());
        }
    }
    // The chpasswd exec goes through the capture wrapper, with the stdin file as its second
    // argument, and the file is gone from the container afterwards.
    let exec_calls: Vec<Value> = log
        .iter()
        .filter(|r| r.path.ends_with("/exec"))
        .map(|r| r.json())
        .collect();
    let chpasswd = exec_calls
        .iter()
        .find(|b| b["command"].to_string().contains("chpasswd"))
        .unwrap();
    let argv: Vec<&str> = chpasswd["command"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    assert_eq!(&argv[..2], ["sh", "-c"]);
    assert!(argv[2].contains("\"$@\" <\"$f\""), "{}", argv[2]);
    assert!(argv[4].starts_with("/run/hx-provision/o-"));
    assert!(argv[5].starts_with("/run/hx-provision/stdin-"));
    assert_eq!(&argv[6..], ["timeout", "--kill-after=15", "60", "chpasswd"]);
    assert!(!chpasswd.to_string().contains(PASSWORD));
    assert!(
        chpasswd["environment"]
            .to_string()
            .find("PASSWORD")
            .is_none()
    );
    assert!(
        fake.with(|s| s
            .files
            .keys()
            .all(|k| !k.contains("/stdin-") && !k.contains("/o-"))),
        "stdin and output files are removed"
    );
}

#[tokio::test]
async fn failed_stdin_command_still_removes_the_secret_file() {
    let fake = Fake::start().await;
    fake.rule("chpasswd", 1, "", "chpasswd: boom");
    let c = fake.client();
    let plan = Catalog::embedded()
        .resolve(id(Distro::Debian13), &[])
        .unwrap();
    let secrets = Secrets::none().with_user_password(PASSWORD).unwrap();
    let exec = IncusExecutor::new(&c, "c1");
    let e = apply_stage(&exec, &plan, Stage::Post, &secrets, &mut |_| {})
        .await
        .unwrap_err();
    assert!(matches!(
        e,
        ApplyError::Step {
            failure: StepFailure::ExitCode { code: 1, .. },
            ..
        }
    ));
    assert!(e.to_string().contains("chpasswd: boom") && !e.to_string().contains(PASSWORD));
    assert!(
        fake.with(|s| s.files.is_empty()),
        "no secret or output file left"
    );
}

fn stdin_request(secrets: &Secrets) -> ExecRequest {
    ExecRequest {
        label: "t".into(),
        argv: vec!["cat".into()],
        env: vec![],
        cwd: None,
        stdin: hx_provision::lower::lower(
            &hx_provision::Step::SetPassword { user: "u".into() },
            secrets,
        )
        .unwrap()
        .into_iter()
        .find_map(|a| match a {
            Action::Exec(r) => r.stdin,
            _ => None,
        }),
        timeout: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn push_error_after_the_daemon_stored_the_secret_removes_it() {
    let fake = Fake::start().await;
    fake.with(|s| s.fail_stdin_push_after_store = true);
    let c = fake.client();
    let secrets = Secrets::none().with_user_password(PASSWORD).unwrap();
    let exec = IncusExecutor::new(&c, "c1");
    let e = exec.exec(&stdin_request(&secrets)).await.unwrap_err();
    assert!(matches!(e, ExecError::Backend(_)), "{e:?}");
    assert!(!e.to_string().contains(PASSWORD));
    // The fake stored the file before answering 500; the executor deleted it.
    assert!(fake.with(|s| s.files.keys().all(|k| !k.contains("/stdin-"))));
    assert!(
        fake.keys()
            .iter()
            .any(|k| k.starts_with("DELETE /1.0/instances/c1/files?path=/run/hx-provision/stdin-"))
    );
    assert!(
        fake.keys().iter().all(|k| !k.ends_with("/exec")),
        "the command never ran"
    );
}

#[tokio::test]
async fn api_failure_of_the_exec_itself_removes_the_secret_file_too() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.overrides.insert(
            "POST /1.0/instances/c1/exec".into(),
            (
                500,
                "{\"type\":\"error\",\"error_code\":500,\"error\":\"nope\"}".into(),
            ),
        );
    });
    let c = fake.client();
    let secrets = Secrets::none().with_user_password(PASSWORD).unwrap();
    let exec = IncusExecutor::new(&c, "c1");
    assert!(exec.exec(&stdin_request(&secrets)).await.is_err());
    assert!(fake.with(|s| s.files.keys().all(|k| !k.contains("/stdin-"))));
}

#[tokio::test]
async fn post_stage_sweeps_the_work_directory_before_and_after() {
    let fake = Fake::start().await;
    let c = fake.client();
    let plan = Catalog::embedded()
        .resolve(id(Distro::Debian13), &[])
        .unwrap();
    let secrets = Secrets::none().with_user_password(PASSWORD).unwrap();
    hx_provision::orchestrate::run_post_stage(&c, "c1", &plan, &secrets, &mut |_| {})
        .await
        .unwrap();
    let execs: Vec<Vec<String>> = fake
        .log()
        .iter()
        .filter(|r| r.path.ends_with("/exec"))
        .map(|r| {
            r.json()["command"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect()
        })
        .collect();
    let sweep = ["find", "/run/hx-provision", "-mindepth", "1", "-delete"];
    assert_eq!(execs.first().unwrap(), &sweep);
    assert_eq!(execs.last().unwrap(), &sweep);
}

#[tokio::test]
async fn captured_output_is_bounded_sanitized_and_files_are_deleted() {
    use hx_provision::orchestrate::exec_captured;
    let fake = Fake::start().await;
    fake.rule(
        "noisy",
        0,
        "ok \u{1b}[31mred\u{1b}[0m\u{7}\r\nline2\u{1b}]0;title\u{7}\n",
        "e\u{0}rr\n",
    );
    let c = fake.client();
    let r = exec_captured(
        &c,
        "c1",
        &["noisy".into()],
        &[],
        None,
        None,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(r.stdout, "ok red\nline2");
    assert_eq!(r.stderr, "err");
    // Oversized output file: refused by the size cap instead of buffered.
    fake.with(|s| {
        s.exec_rules.clear();
    });
    fake.rule("huge", 0, &"A".repeat(300_000), "");
    let r = exec_captured(
        &c,
        "c1",
        &["huge".into()],
        &[],
        None,
        None,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(r.stdout, "(output too large, discarded)");
    assert!(
        fake.with(|s| s.files.keys().all(|k| !k.contains("/o-"))),
        "output files deleted"
    );
    // A failing exec call still cleans up.
    fake.with(|s| {
        s.overrides.insert(
            "POST /1.0/instances/c1/exec".into(),
            (
                500,
                "{\"type\":\"error\",\"error_code\":500,\"error\":\"x\"}".into(),
            ),
        );
    });
    assert!(
        exec_captured(
            &c,
            "c1",
            &["true".into()],
            &[],
            None,
            None,
            Duration::from_secs(5)
        )
        .await
        .is_err()
    );
    assert!(fake.with(|s| s.files.keys().all(|k| !k.contains("/o-"))));
    let deletes = fake
        .keys()
        .iter()
        .filter(|k| k.starts_with("DELETE /1.0/instances/c1/files"))
        .count();
    assert!(deletes >= 12, "{deletes}");
}

#[tokio::test]
async fn readiness_and_docker_execs_never_record_output() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("c1".into(), "Running".into());
    });
    fake.rule("docker --version", 0, "Docker version 27\n", "");
    fake.rule("docker run --rm hello-world", 0, "Hello from Docker!\n", "");
    let c = fake.client();
    wait_system_running(&c, "c1", ReadyOptions::default())
        .await
        .unwrap();
    enable_docker(
        &c,
        "c1",
        &docker_plan(),
        DockerOptions::default(),
        &mut |_| {},
    )
    .await
    .unwrap();
    let execs: Vec<_> = fake
        .log()
        .into_iter()
        .filter(|r| r.path.ends_with("/exec"))
        .collect();
    assert!(execs.len() > 5);
    assert!(execs.iter().all(|r| r.json()["record-output"] == false));
    assert!(fake.keys().iter().all(|k| !k.contains("logs/exec-output")));
}

#[tokio::test]
async fn in_container_timeout_maps_to_exec_error_timeout() {
    let fake = Fake::start().await;
    fake.rule("sleep 999", 124, "", "");
    let c = fake.client();
    let exec = IncusExecutor::new(&c, "c1");
    let req = ExecRequest {
        label: "slow".into(),
        argv: vec!["sleep".into(), "999".into()],
        env: vec![],
        cwd: None,
        stdin: None,
        timeout: Duration::from_secs(7),
    };
    assert_eq!(
        exec.exec(&req).await.unwrap_err(),
        ExecError::Timeout(Duration::from_secs(7))
    );
    let body = fake
        .log()
        .into_iter()
        .find(|r| r.path.ends_with("/exec"))
        .unwrap()
        .json();
    let cmd = body["command"].as_array().unwrap();
    assert_eq!(
        &cmd[6..],
        &[
            json!("timeout"),
            json!("--kill-after=15"),
            json!("7"),
            json!("sleep"),
            json!("999")
        ]
    );
}

// ---------------------------------------------------------------------------------------------
// Readiness
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn readiness_waits_through_starting_until_running() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.running_states = ["initializing", "starting", "running"]
            .map(String::from)
            .into()
    });
    wait_system_running(
        &fake.client(),
        "c1",
        ReadyOptions {
            timeout: Duration::from_secs(30),
            allow_degraded: false,
        },
    )
    .await
    .unwrap();
    let polls = fake
        .log()
        .iter()
        .filter(|r| r.path.ends_with("/exec"))
        .count();
    assert_eq!(polls, 3);
}

#[tokio::test]
async fn degraded_is_final_and_lists_failed_units() {
    let fake = Fake::start().await;
    fake.with(|s| s.running_states = ["starting", "degraded"].map(String::from).into());
    fake.rule(
        "systemctl --failed",
        0,
        "foo.service loaded failed failed Foo\nbar.mount loaded failed failed Bar\n",
        "",
    );
    let opts = ReadyOptions {
        timeout: Duration::from_secs(30),
        allow_degraded: false,
    };
    let e = wait_system_running(&fake.client(), "c1", opts)
        .await
        .unwrap_err();
    assert_eq!(
        e,
        ReadyError::Degraded {
            failed: "foo.service loaded failed failed Foo; bar.mount loaded failed failed Bar"
                .into()
        }
    );
    // ...unless the caller accepts degraded.
    fake.with(|s| s.running_states = ["degraded".to_string()].into());
    wait_system_running(
        &fake.client(),
        "c1",
        ReadyOptions {
            allow_degraded: true,
            ..opts
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn readiness_times_out_with_the_last_state() {
    let fake = Fake::start().await;
    fake.with(|s| s.running_states = ["starting".to_string()].into());
    let e = wait_system_running(
        &fake.client(),
        "c1",
        ReadyOptions {
            timeout: Duration::from_secs(2),
            allow_degraded: false,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        e,
        ReadyError::Timeout {
            last: "starting".into(),
            after: Duration::from_secs(2)
        }
    );
}

// ---------------------------------------------------------------------------------------------
// build_on_server / finish_prebuilt
// ---------------------------------------------------------------------------------------------

fn tiny_plan() -> hx_provision::Plan {
    let src = MemSource::new().with(
        "r.toml",
        "[recipe]\nname=\"tiny\"\nbase_image=\"images:debian/13\"\n[vars]\ndistro=\"debian\"\ndistro_version=\"13\"\n[user]\nname=\"desk\"\nuid=1000\n[apt]\npackages=[\"curl\"]\n",
    );
    hx_provision::recipe::resolve(&src, "r.toml", &[]).unwrap()
}

#[tokio::test]
async fn build_on_server_runs_create_start_ready_build_post_in_order() {
    let fake = Fake::start().await;
    let c = fake.client();
    let plan = tiny_plan();
    let naming = Naming::with_prefix("hx1d-test-").unwrap();
    let spec = DesktopSpec::for_plan(
        "hx1d-test-c1",
        naming,
        &plan,
        Limits {
            cpu: Some(1),
            memory_mib: Some(1024),
            disk_gib: None,
            processes: None,
        },
    );
    let mut steps = Vec::new();
    let secrets = Secrets::none().with_user_password(PASSWORD).unwrap();
    let report = build_on_server(&c, &plan, &spec, &secrets, &mut |p| {
        steps.push(format!("{p:?}"))
    })
    .await
    .unwrap();
    assert!(report.build.is_some() && report.post.is_some());
    let keys = fake.keys();
    let first = keys
        .iter()
        .position(|k| k == "POST /1.0/instances")
        .unwrap();
    let start = keys
        .iter()
        .position(|k| k == "PUT /1.0/instances/hx1d-test-c1/state")
        .unwrap();
    let ready = keys.iter().position(|k| k.ends_with("/exec")).unwrap();
    assert!(first < start && start < ready);
    // Debian 13: compat profile attached.
    assert!(
        fake.log()[first].json()["profiles"]
            .to_string()
            .contains("compat-debian13")
    );
    assert!(steps.iter().all(|s| !s.contains(PASSWORD)));
    assert_eq!(
        fake.with(|s| s.instances["hx1d-test-c1"].clone()),
        "Running"
    );
}

#[tokio::test]
async fn build_failure_leaves_the_container_and_reports_the_step() {
    let fake = Fake::start().await;
    fake.rule("apt-install", 0, "", "");
    fake.rule(
        "install install -y -qq --no-install-recommends 'curl'",
        100,
        "",
        "E: Unable to locate package curl",
    );
    let plan = tiny_plan();
    let spec = DesktopSpec::for_plan(
        "hx1d-test-c1",
        Naming::with_prefix("hx1d-test-").unwrap(),
        &plan,
        Limits::default(),
    );
    let e = build_on_server(&fake.client(), &plan, &spec, &Secrets::none(), &mut |_| {})
        .await
        .unwrap_err();
    let ProvisionError::Apply(ApplyError::Step {
        stage: Stage::Build,
        step,
        failure: StepFailure::ExitCode { code: 100, tail },
        ..
    }) = &e
    else {
        panic!("{e:?}")
    };
    assert!(
        step.starts_with("apt-install") && tail.contains("Unable to locate"),
        "{e}"
    );
    assert!(fake.with(|s| s.instances.contains_key("hx1d-test-c1")));
}

#[tokio::test]
async fn finish_prebuilt_needs_a_local_image_and_runs_only_the_post_stage() {
    let fake = Fake::start().await;
    let plan = tiny_plan();
    let naming = Naming::with_prefix("hx1d-test-").unwrap();
    let remote = DesktopSpec::for_plan("c", naming.clone(), &plan, Limits::default());
    let secrets = Secrets::none().with_user_password(PASSWORD).unwrap();
    let e = finish_prebuilt(&fake.client(), &plan, &remote, &secrets, &mut |_| {})
        .await
        .unwrap_err();
    assert!(matches!(e, ProvisionError::Invalid(_)));
    assert!(fake.log().is_empty());

    let local = remote.with_image(ImageSource::LocalAlias("hx-desktop-debian-13".into()));
    let r = finish_prebuilt(&fake.client(), &plan, &local, &secrets, &mut |_| {})
        .await
        .unwrap();
    assert!(r.build.is_none() && r.post.is_some());
    let create = fake
        .log()
        .into_iter()
        .find(|r| r.key() == "POST /1.0/instances")
        .unwrap()
        .json();
    assert_eq!(create["source"]["alias"], "hx-desktop-debian-13");
    assert!(create["source"].get("server").is_none());
    // No apt-install ran: only post-stage commands.
    let bodies: String = fake
        .log()
        .iter()
        .filter(|r| r.path.ends_with("/exec"))
        .map(|r| r.json().to_string())
        .collect();
    assert!(
        !bodies.contains("apt-bootstrap") && !bodies.contains("--no-install-recommends 'curl'")
    );
    assert!(bodies.contains("chpasswd") && bodies.contains("apt_run 3600 upgrade"));
}

// ---------------------------------------------------------------------------------------------
// Docker
// ---------------------------------------------------------------------------------------------

#[test]
fn selftest_classification_and_version_gate() {
    assert!(selftest_passed(0, "Hello from Docker!\nThis message shows"));
    assert!(!selftest_passed(1, "Hello from Docker!") && !selftest_passed(0, "pulled"));
    assert_eq!(
        classify_selftest(
            "docker: Error response from daemon: failed to create task: runc create failed: open sysctl net.ipv4.ip_unprivileged_port_start file: reopen fd 8: permission denied"
        ),
        SelfTestHint::RuncSysctlDenied
    );
    assert_eq!(
        classify_selftest(
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?"
        ),
        SelfTestHint::DaemonNotRunning
    );
    assert_eq!(
        classify_selftest("Error: dial tcp: lookup registry-1.docker.io: no such host"),
        SelfTestHint::RegistryUnreachable
    );
    assert_eq!(classify_selftest("something else"), SelfTestHint::Unknown);
    assert!(
        !incus_supports_docker(IncusVersion::new(6, 0, 4))
            && incus_supports_docker(IncusVersion::new(6, 0, 5))
            && incus_supports_docker(IncusVersion::new(7, 0, 0))
    );
}

fn docker_plan() -> hx_provision::Plan {
    Catalog::embedded()
        .resolve_addon(id(Distro::Debian13), Addon::Docker)
        .unwrap()
}

#[tokio::test]
async fn docker_on_old_incus_changes_nothing_and_offers_fallbacks() {
    let fake = Fake::start().await;
    fake.with(|s| s.version = "6.0.0".into());
    let out = enable_docker(
        &fake.client(),
        "c1",
        &docker_plan(),
        DockerOptions::default(),
        &mut |_| {},
    )
    .await
    .unwrap();
    assert_eq!(
        out,
        DockerOutcome::UnsupportedIncus {
            found: IncusVersion::new(6, 0, 0),
            required: IncusVersion::new(6, 0, 5),
            fallbacks: vec![
                DockerFallback::UpgradeIncusFromZabbly,
                DockerFallback::HostNetworkOnly,
                DockerFallback::IncusVm
            ],
        }
    );
    assert_eq!(fake.keys(), ["GET /1.0"], "no instance was touched");
}

#[tokio::test]
async fn docker_enable_success_path() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("c1".into(), "Running".into());
    });
    fake.rule(
        "docker --version",
        0,
        "Docker version 27.3.1, build ce12230\n",
        "",
    );
    fake.rule("docker run --rm hello-world", 0, "Hello from Docker!\nThis message shows that your installation appears to be working correctly.\n", "");
    let mut progress = Vec::new();
    let out = enable_docker(
        &fake.client(),
        "c1",
        &docker_plan(),
        DockerOptions::default(),
        &mut |p| progress.push(format!("{p:?}")),
    )
    .await
    .unwrap();
    assert_eq!(
        out,
        DockerOutcome::Enabled {
            docker_version: "Docker version 27.3.1, build ce12230".into()
        }
    );
    let log = fake.log();
    let patch = log
        .iter()
        .find(|r| r.method == "PATCH" && r.path == "/1.0/instances/c1")
        .unwrap()
        .json();
    assert_eq!(
        patch["config"],
        serde_json::json!({"security.nesting":"true","security.syscalls.intercept.mknod":"true","security.syscalls.intercept.setxattr":"true"})
    );
    let restarts = log
        .iter()
        .filter(|r| r.path == "/1.0/instances/c1/state" && r.json()["action"] == "restart")
        .count();
    assert_eq!(
        restarts, 2,
        "restart after the config change and after the install"
    );
    let all_exec: String = log
        .iter()
        .filter(|r| r.path.ends_with("/exec"))
        .map(|r| r.json()["command"].to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        all_exec.contains("docker-ce")
            && all_exec.contains("9DC858229FC7DD38854AE2D88D81803C0EBFCD88")
    );
    assert!(all_exec.contains("usermod -aG") && all_exec.contains("docker.service"));
    // Order: config patch, then install, then the self-test last.
    let pos = |needle: &str| {
        log.iter()
            .position(|r| r.json().to_string().contains(needle))
            .unwrap()
    };
    assert!(pos("security.nesting") < pos("docker-ce") && pos("docker-ce") < pos("hello-world"));
    assert!(progress.iter().any(|p| p.contains("apt-install")));
}

#[tokio::test]
async fn docker_selftest_failure_is_a_structured_result_not_an_error() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.version = "6.0.0".into();
        s.instances.insert("c1".into(), "Running".into());
    });
    fake.rule("docker --version", 0, "Docker version 27.3.1\n", "");
    fake.rule(
        "docker run --rm hello-world",
        125,
        "",
        "docker: Error response from daemon: failed to create task for container: runc create failed: open sysctl net.ipv4.ip_unprivileged_port_start file: permission denied.\n",
    );
    let opts = DockerOptions {
        allow_old_incus: true,
        ..DockerOptions::default()
    };
    let out = enable_docker(&fake.client(), "c1", &docker_plan(), opts, &mut |_| {})
        .await
        .unwrap();
    let DockerOutcome::SelfTestFailed {
        hint,
        output_tail,
        fallbacks,
        isolation_restored,
    } = out
    else {
        panic!("{out:?}")
    };
    assert!(
        isolation_restored,
        "nesting and the intercepts were switched back off"
    );
    assert_eq!(hint, SelfTestHint::RuncSysctlDenied);
    assert!(output_tail.contains("ip_unprivileged_port_start"));
    assert_eq!(
        fallbacks,
        [
            DockerFallback::UpgradeIncusFromZabbly,
            DockerFallback::HostNetworkOnly,
            DockerFallback::IncusVm
        ]
    );
}

#[tokio::test]
async fn docker_install_failure_is_an_error_naming_the_step() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("c1".into(), "Running".into());
    });
    fake.rule(
        "'docker-ce'",
        100,
        "",
        "E: Unable to locate package docker-ce",
    );
    let e = enable_docker(
        &fake.client(),
        "c1",
        &docker_plan(),
        DockerOptions::default(),
        &mut |_| {},
    )
    .await
    .unwrap_err();
    assert!(
        matches!(e, ProvisionError::Apply(ApplyError::Step { .. })),
        "{e:?}"
    );
}

#[tokio::test]
async fn docker_refuses_a_plan_that_is_not_the_addon() {
    let fake = Fake::start().await;
    let plan = Catalog::embedded()
        .resolve(id(Distro::Debian13), &[])
        .unwrap();
    let e = enable_docker(
        &fake.client(),
        "c1",
        &plan,
        DockerOptions::default(),
        &mut |_| {},
    )
    .await
    .unwrap_err();
    assert!(matches!(e, ProvisionError::Invalid(_)));
    assert!(fake.log().is_empty());
    let _: BTreeMap<String, String> = BTreeMap::new();
}

// ---------------------------------------------------------------------------------------------
// Review fixes: metadata ranges, ingress, nftables, existing-bridge reconciliation
// ---------------------------------------------------------------------------------------------

#[test]
fn metadata_block_covers_all_link_local_and_other_clouds() {
    let rules = isolation_rules(None, &[]);
    let dests: Vec<&str> = rules
        .iter()
        .filter_map(|r| r.destination.as_deref())
        .collect();
    for want in [
        "169.254.0.0/16",
        "100.100.100.200/32",
        "168.63.129.16/32",
        "fd00:ec2::/32",
    ] {
        assert!(dests.contains(&want), "{want} missing from {dests:?}");
    }
    // The /16 contains every well-known link-local metadata address.
    for a in [
        "169.254.169.254",
        "169.254.0.23",
        "169.254.170.2",
        "169.254.169.123",
    ] {
        let ip: std::net::Ipv4Addr = a.parse().unwrap();
        assert_eq!(&ip.octets()[..2], &[169, 254]);
    }
}

#[test]
fn ingress_admits_only_the_gateway_and_defaults_to_drop() {
    let acl = hx_provision::host::isolation_acl("a", Some(ip("10.5.0.1")), &[]);
    assert_eq!(acl.ingress.len(), 1);
    assert_eq!(acl.ingress[0].source.as_deref(), Some("10.5.0.1/32"));
    assert_eq!(format!("{:?}", acl.ingress[0].action), "Allow");
    assert!(
        hx_provision::host::isolation_acl("a", None, &[])
            .ingress
            .is_empty()
    );
    let att = hx_provision::host::acl_attachment("a");
    assert_eq!(att["security.acls.default.ingress.action"], "drop");
    assert_eq!(att["security.acls.default.egress.action"], "allow");
}

fn fw(
    bridge: &str,
    gateway: Option<&str>,
    subnet: Option<&str>,
    allow: bool,
) -> hx_provision::host::HostFirewall {
    hx_provision::host::HostFirewall {
        bridge: bridge.into(),
        gateway: gateway.map(|g| g.parse().unwrap()),
        subnet: subnet.map(str::to_string),
        allow_private_networks: allow,
    }
}

#[test]
fn nft_ruleset_text() {
    use hx_provision::host::nft_host_protection;
    let t =
        nft_host_protection(&fw("hxbr0", Some("10.77.3.1"), Some("10.77.3.0/24"), false)).unwrap();
    let want = [
        "# hash-xcreen: desktops may not talk to host services (generated by hx-provision)",
        "table inet hx",
        "delete table inet hx",
        "table inet hx {",
        "  chain input {",
        "    type filter hook input priority -10; policy accept;",
        "    iifname != \"hxbr0\" return",
        "    ct state established,related accept",
        "    ip protocol udp udp dport { 67, 68 } accept",
        "    ip daddr 10.77.3.1 udp dport 53 accept",
        "    ip daddr 10.77.3.1 tcp dport 53 accept",
        "    counter drop",
        "  }",
        "  chain forward {",
        "    type filter hook forward priority -10; policy accept;",
        "    iifname != \"hxbr0\" return",
        "    ct state established,related accept",
        "    ct status dnat drop",
        "    ip daddr 10.77.3.0/24 accept",
        "    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } counter drop",
        "    ip6 daddr { fc00::/7, fe80::/10 } counter drop",
        "  }",
        "}",
        "",
    ]
    .join("\n");
    assert_eq!(t, want);
    // Opting in to private networks removes only the private-range drops; DNAT'd ports stay dropped.
    let open =
        nft_host_protection(&fw("hxbr0", Some("10.77.3.1"), Some("10.77.3.0/24"), true)).unwrap();
    assert!(!open.contains("10.0.0.0/8") && !open.contains("fc00::/7"));
    assert!(
        open.contains("ct status dnat drop") && open.contains("counter drop\n  }\n  chain forward")
    );
    // Without a gateway there is no DNS accept; without a subnet no subnet accept.
    let t = nft_host_protection(&fw("hxbr0", None, None, false)).unwrap();
    assert!(!t.contains("dport 53") && t.contains("counter drop") && !t.contains("ip daddr 10.77"));
    for bad in [
        "",
        "a b",
        "x\"; flush ruleset; \"",
        "waytoolongbridgename0",
        "a\nb",
        "a;b",
    ] {
        assert!(
            nft_host_protection(&fw(bad, None, None, false)).is_err(),
            "{bad:?}"
        );
    }
    for bad in [
        "10.77.3.1/24",
        "10.77.3.0/33",
        "evil; drop",
        "10.77.3.0",
        "10.77.3.0/24 accept\n",
    ] {
        assert!(
            nft_host_protection(&fw("hxbr0", None, Some(bad), false)).is_err(),
            "{bad:?}"
        );
    }
}

#[test]
fn network_of_masks_the_host_bits() {
    use hx_provision::host::network_of;
    assert_eq!(network_of("10.77.3.1/24").as_deref(), Some("10.77.3.0/24"));
    assert_eq!(
        network_of("172.20.5.9/12").as_deref(),
        Some("172.16.0.0/12")
    );
    assert_eq!(network_of("10.0.0.1/0").as_deref(), Some("0.0.0.0/0"));
    assert!(
        network_of("10.0.0.1").is_none()
            && network_of("x/24").is_none()
            && network_of("10.0.0.1/40").is_none()
    );
}

/// Parse the generated rulesets with `nft -c -f` (check mode: nothing is loaded) inside a throwaway
/// user+network namespace (`unshare -rn`), so no host firewall state is read or changed.
#[test]
fn generated_rulesets_parse_with_nft_check_mode() {
    use hx_provision::host::nft_host_protection;
    use std::io::Write;
    use std::process::{Command, Stdio};
    let have = |bin: &str| {
        Command::new(bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    if !have("nft") || !have("unshare") {
        eprintln!("SKIPPED: nft or unshare not installed");
        return;
    }
    // Is an unprivileged user namespace available here at all?
    let probe = Command::new("unshare")
        .args(["-rn", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !probe {
        eprintln!("SKIPPED: unprivileged user namespaces are not available");
        return;
    }
    for (gw, sub, allow) in [
        (Some("10.77.3.1"), Some("10.77.3.0/24"), false),
        (Some("10.77.3.1"), Some("10.77.3.0/24"), true),
        (None, None, false),
    ] {
        let text = nft_host_protection(&fw("hxbr0", gw, sub, allow)).unwrap();
        let mut child = Command::new("unshare")
            .args(["-rn", "nft", "-c", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "nft -c rejected the ruleset:\n{text}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[tokio::test]
async fn ensure_host_returns_the_host_firewall_for_the_caller_to_install() {
    let fake = Fake::start().await;
    let r = ensure_host(&fake.client(), &host_spec()).await.unwrap();
    assert!(
        r.host_firewall
            .contains("iifname != \"hx1d-test-br0\" return")
    );
    assert!(
        r.host_firewall
            .contains("ip daddr 10.99.1.1 udp dport 53 accept")
    );
}

#[tokio::test]
async fn existing_bridge_with_ipv6_or_no_nat_is_reconciled_and_without_ipv4_rejected() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.networks.insert(
            "hx1d-test-br0".into(),
            [
                ("ipv4.address", "10.1.0.1/24"),
                ("ipv6.address", "fd42:1::1/64"),
                ("ipv4.nat", "false"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        );
    });
    let r = ensure_host(&fake.client(), &host_spec()).await.unwrap();
    assert_eq!(r.network, Ensured::Updated);
    let net = fake.with(|s| s.networks["hx1d-test-br0"].clone());
    assert_eq!(
        (net["ipv6.address"].as_str(), net["ipv4.nat"].as_str()),
        ("none", "true")
    );
    assert_eq!(
        net["ipv4.address"], "10.1.0.1/24",
        "the address is not touched"
    );
    assert_eq!(r.gateway, Some(ip("10.1.0.1")));

    let fake = Fake::start().await;
    fake.with(|s| {
        s.networks.insert(
            "hx1d-test-br0".into(),
            [("ipv4.address", "none")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        );
    });
    let e = ensure_host(&fake.client(), &host_spec()).await.unwrap_err();
    assert!(e.to_string().contains("no IPv4 address"), "{e}");
}

// ---------------------------------------------------------------------------------------------
// Review fixes: exact config allowlist, hardening keys, rollback, password cap
// ---------------------------------------------------------------------------------------------

const FORBIDDEN_KEYS: [&str; 7] = [
    "raw.lxc",
    "raw.idmap",
    "linux.kernel_modules",
    "security.syscalls.intercept.bpf.devices",
    "security.syscalls.intercept.bpf",
    "security.syscalls.intercept.sched_setscheduler",
    "security.privileged",
];

#[test]
fn instance_config_allowlist_is_exact_at_the_recipe_sink() {
    use hx_provision::RecipeError;
    for k in FORBIDDEN_KEYS {
        let text = format!(
            "[recipe]\nname=\"t\"\nbase_image=\"images:debian/13\"\n[incus_config]\n\"{k}\" = \"true\"\n"
        );
        let e =
            hx_provision::recipe::resolve(&MemSource::new().with("m.toml", &text), "m.toml", &[])
                .unwrap_err();
        assert!(
            matches!(e, RecipeError::Invalid { ref field, .. } if field == &format!("incus_config.{k}")),
            "{k}: {e}"
        );
    }
    for k in [
        "security.nesting",
        "security.syscalls.intercept.mknod",
        "security.syscalls.intercept.setxattr",
    ] {
        let text = format!(
            "[recipe]\nname=\"t\"\nbase_image=\"images:debian/13\"\n[incus_config]\n\"{k}\" = \"true\"\n"
        );
        assert!(
            hx_provision::recipe::resolve(&MemSource::new().with("m.toml", &text), "m.toml", &[])
                .is_ok(),
            "{k}"
        );
    }
}

#[test]
fn instance_config_allowlist_is_exact_at_the_create_sink() {
    let ub = Catalog::embedded()
        .resolve(id(Distro::Ubuntu2404), &[])
        .unwrap();
    let naming = Naming::with_prefix("hx1d-test-").unwrap();
    for k in FORBIDDEN_KEYS {
        let mut spec = DesktopSpec::for_plan("c", naming.clone(), &ub, Limits::default());
        spec.extra_config.insert(k.to_string(), "true".into());
        let e = spec.to_create().unwrap_err();
        assert!(e.to_string().contains(k), "{k}: {e}");
    }
    let mut spec = DesktopSpec::for_plan("c", naming, &ub, Limits::default());
    spec.extra_config
        .insert("security.nesting".into(), "yes".into());
    assert!(spec.to_create().is_err(), "values must be true/false");
}

#[tokio::test]
async fn instance_config_allowlist_is_exact_at_the_docker_sink() {
    for k in FORBIDDEN_KEYS {
        let fake = Fake::start().await;
        let mut plan = docker_plan();
        plan.incus_config.insert(k.to_string(), "true".into());
        let e = enable_docker(
            &fake.client(),
            "c1",
            &plan,
            DockerOptions::default(),
            &mut |_| {},
        )
        .await
        .unwrap_err();
        assert!(
            matches!(e, ProvisionError::Invalid(ref m) if m.contains(k)),
            "{k}: {e:?}"
        );
        assert!(fake.log().is_empty(), "nothing is sent for {k}");
    }
}

#[test]
fn desktops_get_hardening_keys_and_a_process_limit() {
    let ub = Catalog::embedded()
        .resolve(id(Distro::Ubuntu2404), &[])
        .unwrap();
    let naming = Naming::with_prefix("hx1d-test-").unwrap();
    let c = DesktopSpec::for_plan("c", naming.clone(), &ub, Limits::default())
        .to_create()
        .unwrap()
        .config;
    assert_eq!(c["security.guestapi"], "false");
    assert_eq!(c["security.idmap.isolated"], "true");
    assert_eq!(c["security.privileged"], "false");
    assert_eq!(
        c["limits.processes"],
        hx_provision::orchestrate::DEFAULT_PROCESSES.to_string()
    );
    let lim = Limits {
        processes: Some(1000),
        ..Limits::default()
    };
    assert_eq!(
        DesktopSpec::for_plan("c", naming.clone(), &ub, lim)
            .to_create()
            .unwrap()
            .config["limits.processes"],
        "1000"
    );
    for zero in [
        Limits {
            cpu: Some(0),
            ..Limits::default()
        },
        Limits {
            memory_mib: Some(0),
            ..Limits::default()
        },
        Limits {
            disk_gib: Some(0),
            ..Limits::default()
        },
        Limits {
            processes: Some(0),
            ..Limits::default()
        },
    ] {
        assert!(
            DesktopSpec::for_plan("c", naming.clone(), &ub, zero)
                .to_create()
                .is_err()
        );
    }
}

#[tokio::test]
async fn docker_install_failure_rolls_the_isolation_back() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("c1".into(), "Running".into());
    });
    fake.rule(
        "'docker-ce'",
        100,
        "",
        "E: Unable to locate package docker-ce",
    );
    let e = enable_docker(
        &fake.client(),
        "c1",
        &docker_plan(),
        DockerOptions::default(),
        &mut |_| {},
    )
    .await
    .unwrap_err();
    assert!(matches!(e, ProvisionError::Apply(_)));
    let patches: Vec<Value> = fake
        .log()
        .iter()
        .filter(|r| r.method == "PATCH" && r.path == "/1.0/instances/c1")
        .map(|r| r.json())
        .collect();
    assert_eq!(patches.len(), 2, "enable, then roll back");
    assert_eq!(
        patches[1]["config"],
        json!({"security.nesting":"false","security.syscalls.intercept.mknod":"false","security.syscalls.intercept.setxattr":"false"})
    );
}

#[tokio::test]
async fn docker_selftest_failure_rolls_back_and_reports_it() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("c1".into(), "Running".into());
    });
    fake.rule("docker --version", 0, "Docker version 27\n", "");
    fake.rule(
        "docker run --rm hello-world",
        125,
        "",
        "runc: ip_unprivileged_port_start\n",
    );
    let out = enable_docker(
        &fake.client(),
        "c1",
        &docker_plan(),
        DockerOptions::default(),
        &mut |_| {},
    )
    .await
    .unwrap();
    let DockerOutcome::SelfTestFailed {
        isolation_restored, ..
    } = out
    else {
        panic!("{out:?}")
    };
    assert!(isolation_restored);
    let log = fake.log();
    let last_patch = log.iter().rposition(|r| r.method == "PATCH").unwrap();
    assert_eq!(
        log[last_patch].json()["config"]["security.nesting"],
        "false"
    );
    let restart_after = log[last_patch..]
        .iter()
        .any(|r| r.path.ends_with("/state") && r.json()["action"] == "restart");
    assert!(
        restart_after,
        "the desktop is restarted so the config takes effect"
    );

    // A rollback that cannot be done is reported, not hidden.
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("c1".into(), "Running".into());
    });
    fake.rule("docker run --rm hello-world", 125, "", "boom\n");
    // The second PATCH (the rollback) fails.
    let log_len = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let _ = log_len;
    fake.with(|s| {
        s.fail_second_instance_patch = true;
    });
    let out = enable_docker(
        &fake.client(),
        "c1",
        &docker_plan(),
        DockerOptions::default(),
        &mut |_| {},
    )
    .await
    .unwrap();
    let DockerOutcome::SelfTestFailed {
        isolation_restored, ..
    } = out
    else {
        panic!("{out:?}")
    };
    assert!(!isolation_restored);
}

#[test]
fn password_length_is_capped() {
    use hx_provision::SecretError;
    assert!(
        Secrets::none()
            .with_user_password(&"a".repeat(1024))
            .is_ok()
    );
    assert_eq!(
        Secrets::none()
            .with_user_password(&"a".repeat(1025))
            .unwrap_err(),
        SecretError::TooLong
    );
}

#[test]
fn container_text_is_sanitized_and_truncated() {
    use hx_provision::exec::sanitize;
    assert_eq!(
        sanitize("a\u{1b}[1;31mred\u{1b}[0m b\u{7}\r\u{0}c\td\n", 100),
        "ared bc\td"
    );
    assert_eq!(
        sanitize("x\u{1b}]8;;http://evil\u{7}link\u{1b}]8;;\u{1b}\\", 100),
        "xlink"
    );
    assert_eq!(sanitize("\u{1b}", 10), "");
    let long = "é".repeat(5000);
    let t = sanitize(&long, 100);
    assert!(t.starts_with("...") && t.len() <= 103 + 2);
    assert!(t.chars().all(|c| c == '.' || c == 'é'));
}

#[tokio::test]
async fn step_failures_and_readiness_errors_are_sanitized() {
    let fake = Fake::start().await;
    fake.rule(
        "chpasswd",
        1,
        "",
        "\u{1b}[31mchpasswd: \u{1b}]0;pwned\u{7}failed\u{0}\n",
    );
    let c = fake.client();
    let plan = Catalog::embedded()
        .resolve(id(Distro::Debian13), &[])
        .unwrap();
    let secrets = Secrets::none().with_user_password(PASSWORD).unwrap();
    let e = apply_stage(
        &IncusExecutor::new(&c, "c1"),
        &plan,
        Stage::Post,
        &secrets,
        &mut |_| {},
    )
    .await
    .unwrap_err();
    let msg = e.to_string();
    assert!(
        msg.contains("chpasswd: failed") && !msg.contains('\u{1b}') && !msg.contains("pwned"),
        "{msg:?}"
    );

    fake.with(|s| s.running_states = ["\u{1b}[2Jweird\u{0}state".to_string()].into());
    let e = wait_system_running(
        &c,
        "c1",
        ReadyOptions {
            timeout: Duration::from_millis(1500),
            allow_degraded: false,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        e,
        ReadyError::Timeout {
            last: "weirdstate".into(),
            after: Duration::from_millis(1500)
        }
    );
}

#[tokio::test]
async fn captured_output_that_is_not_a_regular_file_is_discarded() {
    use hx_provision::orchestrate::exec_captured;
    let fake = Fake::start().await;
    fake.rule("planted", 0, "real output", "");
    let c = fake.client();
    // Everything under /run/hx-provision/o-* that the container swapped for a directory, symlink
    // or FIFO is reported as unavailable instead of being read.
    fake.with(|s| s.file_types.insert("*".into(), "x".into()));
    let r = exec_captured(
        &c,
        "c1",
        &["planted".into()],
        &[],
        None,
        None,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(r.stdout, "real output", "regular files are read");
    fake.with(|s| s.default_file_type = Some("symlink".into()));
    let r = exec_captured(
        &c,
        "c1",
        &["planted".into()],
        &[],
        None,
        None,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert!(
        r.stdout.starts_with("(output unavailable:") && r.stdout.contains("not a regular file"),
        "{r:?}"
    );
    assert!(
        fake.with(|s| s.files.keys().all(|k| !k.contains("/o-"))),
        "still cleaned up"
    );
}
