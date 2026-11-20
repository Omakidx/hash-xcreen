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
use serde_json::Value;

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
            "169.254.169.254/32",
            "fd00:ec2::254/128",
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
    assert_eq!(isolation_rules(None, &[]).len(), 3);
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
            "169.254.169.254/32",
            "fd00:ec2::254/128",
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
    };
    let spec = DesktopSpec::for_plan("hx1d-test-c1", naming.clone(), &plan, limits);
    let body = spec.to_create();
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
    let b = DesktopSpec::for_plan("c", naming.clone(), &ub, Limits::default()).to_create();
    assert_eq!(b.profiles, ["hx1d-test-desktop"]);
    assert!(b.devices.is_empty() && !b.config.contains_key("limits.cpu"));

    // A recipe can never turn privileged on.
    let mut sneaky = DesktopSpec::for_plan("c", naming, &ub, Limits::default());
    sneaky
        .extra_config
        .insert("security.privileged".into(), "true".into());
    assert_eq!(sneaky.to_create().config["security.privileged"], "false");
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
    // Never in a URL, header, or exec command line.
    for r in &log {
        assert!(!r.path.contains(PASSWORD) && !r.path.contains("horse"));
        assert!(r.headers.values().all(|v| !v.contains(PASSWORD)));
    }
    // The chpasswd exec reads the file through a redirect and removes it.
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
    assert_eq!(
        &argv[..3],
        [
            "sh",
            "-c",
            r#"f=$1; shift; "$@" < "$f"; rc=$?; rm -f -- "$f"; exit $rc"#
        ]
    );
    assert!(argv[4].starts_with("/run/hx-provision/stdin-"));
    assert_eq!(&argv[5..], ["timeout", "--kill-after=15", "60", "chpasswd"]);
    assert!(!chpasswd.to_string().contains(PASSWORD));
    assert!(
        chpasswd["environment"]
            .to_string()
            .find("PASSWORD")
            .is_none()
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
    assert!(!e.to_string().contains(PASSWORD));
    // Make the exec itself fail at the API level: the executor removes the file in a follow-up.
    fake.with(|s| {
        s.overrides.insert(
            "POST /1.0/instances/c1/exec".into(),
            (
                500,
                "{\"type\":\"error\",\"error_code\":500,\"error\":\"nope\"}".into(),
            ),
        );
    });
    let req = ExecRequest {
        label: "t".into(),
        argv: vec!["cat".into()],
        env: vec![],
        cwd: None,
        stdin: hx_provision::lower::lower(
            &hx_provision::Step::SetPassword { user: "u".into() },
            &secrets,
        )
        .unwrap()
        .into_iter()
        .find_map(|a| match a {
            Action::Exec(r) => r.stdin,
            _ => None,
        }),
        timeout: Duration::from_secs(5),
    };
    let before = fake.log().len();
    assert!(exec.exec(&req).await.is_err());
    let after = &fake.log()[before..];
    // push dir, push file, failed exec, then a cleanup exec attempt (also failing here, best effort).
    assert!(
        after.iter().filter(|r| r.path.ends_with("/exec")).count() >= 2,
        "{:?}",
        after.iter().map(|r| r.key()).collect::<Vec<_>>()
    );
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
    let body = fake.log()[0].json();
    assert_eq!(
        body["command"],
        serde_json::json!(["timeout", "--kill-after=15", "7", "sleep", "999"])
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
    } = out
    else {
        panic!("{out:?}")
    };
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
