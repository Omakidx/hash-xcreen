//! The Docker disable path and the named-but-unimplemented host-network-only mode (ipc.md 6.9).

mod common;

use std::collections::BTreeMap;

use common::Fake;
use hx_provision::incus::IncusError;
use hx_provision::plan::ALLOWED_INSTANCE_CONFIG;
use hx_provision::{
    Addon, Catalog, Desktop, Distro, DockerMode, DockerOptions, Preset, ProvisionError, RecipeId,
    disable_docker, enable_docker,
};
use serde_json::json;

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

fn running(fake: &Fake, config: &[(&str, &str)]) {
    fake.with(|s| {
        s.instances.insert("c1".into(), "Running".into());
        s.config.insert(
            "c1".into(),
            config
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
        );
    });
}

#[tokio::test]
async fn disable_sets_exactly_the_three_keys_off_and_restarts() {
    let fake = Fake::start().await;
    running(
        &fake,
        &[
            ("security.nesting", "true"),
            ("security.syscalls.intercept.mknod", "true"),
            ("security.syscalls.intercept.setxattr", "true"),
            ("limits.cpu", "4"),
        ],
    );
    let out = disable_docker(&fake.client(), "c1").await.unwrap();
    assert!(out.restarted);
    let patch = fake
        .log()
        .into_iter()
        .find(|r| r.method == "PATCH")
        .unwrap();
    assert_eq!(
        patch.json(),
        json!({"config": {
            "security.nesting": "false",
            "security.syscalls.intercept.mknod": "false",
            "security.syscalls.intercept.setxattr": "false",
        }})
    );
    // The body names the same keys as the recipe allowlist, and nothing else.
    assert_eq!(
        patch.json()["config"].as_object().unwrap().len(),
        ALLOWED_INSTANCE_CONFIG.len()
    );
    let keys = fake.keys();
    let p = keys.iter().position(|k| k.starts_with("PATCH")).unwrap();
    assert!(
        keys[p..].iter().any(|k| k == "PUT /1.0/instances/c1/state"),
        "restarted after the patch: {keys:?}"
    );
    // Unrelated config is untouched, and nothing but readiness probes ran inside (Docker data stays).
    assert_eq!(fake.with(|s| s.config["c1"]["limits.cpu"].clone()), "4");
    assert!(fake.log().iter().all(|r| {
        !r.path.ends_with("/exec") || r.json()["command"].to_string().contains("systemctl")
    }));
}

#[tokio::test]
async fn disable_converges_when_already_off() {
    let fake = Fake::start().await;
    running(
        &fake,
        &[
            ("security.nesting", "false"),
            ("security.syscalls.intercept.mknod", "false"),
        ],
    );
    let out = disable_docker(&fake.client(), "c1").await.unwrap();
    assert!(!out.restarted);
    assert!(fake.log().iter().all(|r| r.method == "GET"));
    // Also when the keys were never set.
    running(&fake, &[]);
    assert!(
        !disable_docker(&fake.client(), "c1")
            .await
            .unwrap()
            .restarted
    );
}

#[tokio::test]
async fn disable_of_an_unknown_instance_is_not_found() {
    let fake = Fake::start().await;
    let err = disable_docker(&fake.client(), "nope").await.unwrap_err();
    assert!(
        matches!(&err, ProvisionError::Incus(e) if e.is_not_found()),
        "{err}"
    );
    let err = disable_docker(&fake.client(), "../x").await.unwrap_err();
    assert!(matches!(
        err,
        ProvisionError::Incus(IncusError::InvalidName { .. })
    ));
}

#[tokio::test]
async fn host_network_only_is_named_and_unimplemented_and_changes_nothing() {
    let fake = Fake::start().await;
    running(&fake, &[]);
    let opts = DockerOptions {
        mode: DockerMode::HostNetworkOnly,
        ..DockerOptions::default()
    };
    let err = enable_docker(&fake.client(), "c1", &docker_plan(), opts, &mut |_| {})
        .await
        .unwrap_err();
    assert!(matches!(err, ProvisionError::Unimplemented(_)), "{err:?}");
    assert!(fake.log().is_empty(), "no request of any kind");
    assert_eq!(DockerOptions::default().mode, DockerMode::Standard);
}
