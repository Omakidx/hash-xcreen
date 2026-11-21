//! Setting limits on a live instance, including the root disk size (ipc.md 6.8).

mod common;

use std::collections::BTreeMap;

use common::Fake;
use hx_provision::incus::{IncusError, LimitsUpdate, MAX_CPU, MAX_DISK_GIB, MAX_MEMORY_MIB};
use serde_json::json;

fn dev<const N: usize>(p: [(&str, &str); N]) -> BTreeMap<String, String> {
    p.into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn with_instance(fake: &Fake) {
    fake.with(|s| {
        s.instances.insert("hx-main".into(), "Running".into());
        s.expanded_devices.insert(
            "root".into(),
            dev([("type", "disk"), ("path", "/"), ("pool", "hx-pool")]),
        );
    });
}

#[tokio::test]
async fn cpu_memory_and_disk_are_applied_in_one_patch() {
    let fake = Fake::start().await;
    with_instance(&fake);
    let applied = fake
        .client()
        .set_limits(
            "hx-main",
            &LimitsUpdate {
                cpu: Some(4),
                memory_mib: Some(8192),
                disk_gib: Some(60),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        applied.changed,
        ["limits.cpu", "limits.memory", "devices.root.size"]
    );
    // A CPU count change on a running instance needs a restart (Incus 6.0.0 behaviour).
    assert!(applied.restart_required);
    let patch = fake
        .log()
        .into_iter()
        .rfind(|r| r.method == "PATCH")
        .unwrap();
    // The root device keeps pool and path and gets only the size; nothing else is in the body
    // (in particular not limits.processes).
    assert_eq!(
        patch.json(),
        json!({
            "config": {"limits.cpu": "4", "limits.memory": "8192MiB"},
            "devices": {"root": {"type":"disk","path":"/","pool":"hx-pool","size":"60GiB"}},
        })
    );
}

#[tokio::test]
async fn restart_is_needed_only_for_a_cpu_change_on_a_running_instance() {
    let fake = Fake::start().await;
    with_instance(&fake);
    let c = fake.client();
    let mem_disk = LimitsUpdate {
        memory_mib: Some(2048),
        disk_gib: Some(20),
        ..Default::default()
    };
    assert!(
        !c.set_limits("hx-main", &mem_disk)
            .await
            .unwrap()
            .restart_required
    );
    let cpu = LimitsUpdate {
        cpu: Some(2),
        ..Default::default()
    };
    assert!(
        c.set_limits("hx-main", &cpu)
            .await
            .unwrap()
            .restart_required
    );
    fake.with(|s| {
        s.instances.insert("hx-main".into(), "Stopped".into());
    });
    assert!(
        !c.set_limits("hx-main", &cpu)
            .await
            .unwrap()
            .restart_required
    );
}

#[tokio::test]
async fn unset_fields_are_left_alone() {
    let fake = Fake::start().await;
    with_instance(&fake);
    fake.client()
        .set_limits(
            "hx-main",
            &LimitsUpdate {
                cpu: Some(2),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let patch = fake
        .log()
        .into_iter()
        .rfind(|r| r.method == "PATCH")
        .unwrap();
    assert_eq!(patch.json(), json!({"config": {"limits.cpu": "2"}}));
    // No instance lookup is needed when the disk is not touched.
    assert!(
        fake.keys()
            .iter()
            .all(|k| k != "GET /1.0/instances/hx-main")
    );
}

#[tokio::test]
async fn an_existing_local_root_device_is_preferred_and_converges() {
    let fake = Fake::start().await;
    with_instance(&fake);
    fake.with(|s| {
        s.devices.insert(
            "hx-main".into(),
            [(
                "root".to_string(),
                dev([
                    ("type", "disk"),
                    ("path", "/"),
                    ("pool", "hx-pool"),
                    ("size", "20GiB"),
                ]),
            )]
            .into(),
        );
    });
    let u = LimitsUpdate {
        disk_gib: Some(40),
        ..Default::default()
    };
    fake.client().set_limits("hx-main", &u).await.unwrap();
    fake.client().set_limits("hx-main", &u).await.unwrap();
    assert_eq!(
        fake.with(|s| s.devices["hx-main"]["root"]["size"].clone()),
        "40GiB"
    );
}

#[tokio::test]
async fn invalid_updates_never_reach_incus() {
    let fake = Fake::start().await;
    with_instance(&fake);
    let c = fake.client();
    let bad = [
        LimitsUpdate::default(),
        LimitsUpdate {
            cpu: Some(0),
            ..Default::default()
        },
        LimitsUpdate {
            memory_mib: Some(0),
            ..Default::default()
        },
        LimitsUpdate {
            disk_gib: Some(0),
            ..Default::default()
        },
        LimitsUpdate {
            cpu: Some(MAX_CPU + 1),
            ..Default::default()
        },
        LimitsUpdate {
            memory_mib: Some(MAX_MEMORY_MIB + 1),
            ..Default::default()
        },
        LimitsUpdate {
            disk_gib: Some(MAX_DISK_GIB + 1),
            ..Default::default()
        },
        LimitsUpdate {
            cpu: Some(2),
            memory_mib: Some(0),
            disk_gib: Some(10),
        },
    ];
    for u in bad {
        let err = c.set_limits("hx-main", &u).await.unwrap_err();
        assert!(
            matches!(err, IncusError::InvalidArgument(_)),
            "{u:?}: {err}"
        );
    }
    let err = c
        .set_limits(
            "../x",
            &LimitsUpdate {
                cpu: Some(1),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, IncusError::InvalidName { .. }));
    assert!(fake.log().iter().all(|r| r.method != "PATCH"));
}

#[tokio::test]
async fn no_root_disk_or_unknown_instance_is_an_error() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("hx-main".into(), "Running".into());
    });
    let u = LimitsUpdate {
        disk_gib: Some(10),
        ..Default::default()
    };
    let err = fake.client().set_limits("hx-main", &u).await.unwrap_err();
    assert!(matches!(err, IncusError::InvalidArgument(_)), "{err}");
    let err = fake.client().set_limits("hx-gone", &u).await.unwrap_err();
    assert!(err.is_not_found(), "{err}");
    // A `root` device that is not the root disk is refused too.
    fake.with(|s| {
        s.expanded_devices
            .insert("root".into(), dev([("type", "disk"), ("path", "/mnt")]));
    });
    assert!(fake.client().set_limits("hx-main", &u).await.is_err());
    assert!(fake.log().iter().all(|r| r.method != "PATCH"));
}
