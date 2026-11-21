//! A purged operation (404 on `/wait`) is never read as success: every mutating call re-reads the
//! state it changed, and the Docker rollback only says `isolation_restored` when the keys really
//! are off (ipc.md 1.2, 6.9). Also: device replacement and the conditional `PUT`.

mod common;

use std::collections::BTreeMap;

use common::Fake;
use hx_provision::incus::{IncusError, LimitsUpdate, LinkOutcome, SessionLink};
use hx_provision::{
    Addon, Catalog, Desktop, Distro, DockerOptions, DockerOutcome, Preset, ProvisionError,
    RecipeId, disable_docker, enable_docker,
};

fn docker_plan() -> hx_provision::Plan {
    Catalog::embedded()
        .resolve_addon(
            RecipeId {
                distro: Distro::Debian13,
                desktop: Desktop::Xfce,
                preset: Preset::Basic,
            },
            Addon::Docker,
        )
        .unwrap()
}

fn on(fake: &Fake, keys: &[&str]) {
    fake.with(|s| {
        s.instances.insert("c1".into(), "Running".into());
        s.config.insert(
            "c1".into(),
            keys.iter()
                .map(|k| (k.to_string(), "true".to_string()))
                .collect::<BTreeMap<_, _>>(),
        );
    });
}

const KEYS: [&str; 3] = [
    "security.nesting",
    "security.syscalls.intercept.mknod",
    "security.syscalls.intercept.setxattr",
];

#[tokio::test]
async fn a_purged_rollback_that_did_not_apply_is_not_isolation_restored() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("c1".into(), "Running".into());
        // The enabling PATCH applies; the rollback PATCH is accepted, purged and NOT applied.
        s.purge_patch_ops = true;
        s.drop_patches_after = Some(1);
    });
    fake.rule("docker --version", 0, "Docker version 27\n", "");
    fake.rule(
        "docker run --rm hello-world",
        125,
        "",
        "docker: Error response from daemon: runc create failed\n",
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
        panic!("{out:?}");
    };
    assert!(
        !isolation_restored,
        "security.nesting is still true, so isolation was not restored"
    );
    assert_eq!(
        fake.with(|s| s.config["c1"]["security.nesting"].clone()),
        "true"
    );
}

#[tokio::test]
async fn a_purged_rollback_that_did_apply_is_restored() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("c1".into(), "Running".into());
        s.purge_patch_ops = true; // every PATCH is purged, all of them applied
    });
    fake.rule("docker --version", 0, "Docker version 27\n", "");
    fake.rule("docker run --rm hello-world", 125, "", "boom\n");
    let out = enable_docker(
        &fake.client(),
        "c1",
        &docker_plan(),
        DockerOptions::default(),
        &mut |_| {},
    )
    .await
    .unwrap();
    assert!(matches!(
        out,
        DockerOutcome::SelfTestFailed {
            isolation_restored: true,
            ..
        }
    ));
    assert_eq!(
        fake.with(|s| s.config["c1"]["security.nesting"].clone()),
        "false"
    );
}

#[tokio::test]
async fn disable_docker_errors_when_the_purged_patch_did_not_apply() {
    let fake = Fake::start().await;
    on(&fake, &KEYS);
    fake.with(|s| {
        s.purge_patch_ops = true;
        s.drop_patches_after = Some(0);
    });
    let err = disable_docker(&fake.client(), "c1").await.unwrap_err();
    assert!(
        matches!(err, ProvisionError::Incus(IncusError::Purged(_))),
        "{err:?}"
    );
    assert_eq!(
        fake.with(|s| s.config["c1"]["security.nesting"].clone()),
        "true"
    );
}

#[tokio::test]
async fn disable_docker_accepts_a_purged_patch_that_applied() {
    let fake = Fake::start().await;
    on(&fake, &KEYS);
    fake.with(|s| s.purge_patch_ops = true);
    assert!(
        disable_docker(&fake.client(), "c1")
            .await
            .unwrap()
            .restarted
    );
}

#[tokio::test]
async fn set_limits_and_add_session_link_check_the_result_too() {
    let link = SessionLink::new("main", (990, 990), (1000, 1000)).unwrap();
    let fake = Fake::start().await;
    on(&fake, &[]);
    fake.with(|s| {
        s.purge_patch_ops = true;
        s.drop_patches_after = Some(0);
        s.expanded_devices.insert(
            "root".into(),
            [("type", "disk"), ("path", "/"), ("pool", "p")]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        );
    });
    let c = fake.client();
    let lim = LimitsUpdate {
        cpu: Some(2),
        disk_gib: Some(10),
        ..Default::default()
    };
    assert!(matches!(
        c.set_limits("c1", &lim).await.unwrap_err(),
        IncusError::Purged(_)
    ));
    assert!(matches!(
        c.add_session_link("c1", &link).await.unwrap_err(),
        IncusError::Purged(_)
    ));
    // Applied but purged: fine.
    fake.with(|s| s.drop_patches_after = None);
    c.set_limits("c1", &lim).await.unwrap();
    assert_eq!(
        c.add_session_link("c1", &link).await.unwrap(),
        LinkOutcome::Added
    );
}

#[tokio::test]
async fn replacing_the_device_drops_stale_keys() {
    let fake = Fake::start().await;
    on(&fake, &[]);
    let link = SessionLink::new("main", (990, 990), (1000, 1000)).unwrap();
    let mut stale = link.device();
    stale.insert("uid".into(), "5".into());
    stale.insert("proxy_protocol".into(), "true".into());
    fake.with(|s| {
        s.devices
            .insert("c1".into(), [("hx-link".to_string(), stale)].into());
    });
    assert_eq!(
        fake.client().add_session_link("c1", &link).await.unwrap(),
        LinkOutcome::Replaced
    );
    let now = fake.with(|s| s.devices["c1"]["hx-link"].clone());
    assert_eq!(now, link.device(), "no stale key survives");
    assert!(!now.contains_key("proxy_protocol"));
}

#[tokio::test]
async fn removing_the_device_is_conditional_and_retries_on_a_concurrent_change() {
    let fake = Fake::start().await;
    on(&fake, &[]);
    let link = SessionLink::new("main", (990, 990), (1000, 1000)).unwrap();
    let c = fake.client();
    c.add_session_link("c1", &link).await.unwrap();
    // Someone else changes the instance between our read and our write.
    fake.with(|s| s.conflict_once = true);
    assert!(c.remove_session_link("c1").await.unwrap());
    let puts: Vec<_> = fake
        .log()
        .into_iter()
        .filter(|r| r.method == "PUT" && r.path == "/1.0/instances/c1")
        .collect();
    assert_eq!(puts.len(), 2, "one 412, one retry");
    for p in &puts {
        assert!(
            p.headers
                .get("if-match")
                .is_some_and(|v| v.starts_with('"')),
            "PUT carries If-Match: {:?}",
            p.headers
        );
    }
    assert!(fake.with(|s| !s.devices["c1"].contains_key("hx-link")));
    // The description and the rest of the definition travel with the PUT.
    let body = fake.with(|s| s.put_bodies[0].clone());
    assert!(body.get("description").is_some());
    assert_eq!(body["profiles"], serde_json::json!(["p"]));
}

#[tokio::test]
async fn a_conflict_that_never_ends_is_an_error_not_a_blind_overwrite() {
    let fake = Fake::start().await;
    on(&fake, &[]);
    let link = SessionLink::new("main", (990, 990), (1000, 1000)).unwrap();
    let c = fake.client();
    c.add_session_link("c1", &link).await.unwrap();
    // A 412 on every attempt.
    fake.with(|s| {
        s.overrides.insert(
            "PUT /1.0/instances/c1".into(),
            (
                412,
                r#"{"type":"error","error_code":412,"error":"ETag doesn't match"}"#.into(),
            ),
        );
    });
    let err = c.remove_session_link("c1").await.unwrap_err();
    assert!(matches!(err, IncusError::Operation(_)), "{err:?}");
    assert!(fake.with(|s| s.devices["c1"].contains_key("hx-link")));
}
