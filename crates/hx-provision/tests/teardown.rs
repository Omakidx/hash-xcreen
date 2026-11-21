//! Teardown helpers delete only objects that carry the hash-xcreen marker (ipc.md 6.13, 7).

mod common;

use std::net::IpAddr;

use common::Fake;
use hx_provision::incus::{INSTANCE_STATE_KEY, SessionLink};
use hx_provision::teardown::{Teardown, destroy_desktop, teardown_host};
use hx_provision::{
    Catalog, Desktop, DesktopSpec, Distro, HostSpec, Limits, Naming, PoolSource, Preset,
    ProvisionError, RecipeId, ensure_host,
};
use serde_json::json;

fn naming() -> Naming {
    Naming::with_prefix("hx3b-").unwrap()
}

fn host_spec() -> HostSpec {
    HostSpec {
        naming: naming(),
        pool: PoolSource::LoopFile { size_gib: 12 },
        ipv4: "auto".into(),
        host_addresses: vec!["203.0.113.7".parse::<IpAddr>().unwrap()],
        allow_private_networks: false,
    }
}

fn deleted(fake: &Fake) -> Vec<String> {
    fake.keys()
        .into_iter()
        .filter(|k| k.starts_with("DELETE"))
        .collect()
}

#[tokio::test]
async fn everything_ensure_host_creates_is_marked_and_torn_down_in_order() {
    let fake = Fake::start().await;
    let c = fake.client();
    ensure_host(&c, &host_spec()).await.unwrap();
    let r = teardown_host(&c, &naming()).await.unwrap();
    for t in [
        r.desktop_profile,
        r.compat_profile,
        r.network,
        r.acl,
        r.pool,
    ] {
        assert_eq!(t, Teardown::Removed);
    }
    assert_eq!(
        deleted(&fake),
        [
            "DELETE /1.0/profiles/hx3b-desktop",
            "DELETE /1.0/profiles/hx3b-compat-debian13",
            "DELETE /1.0/networks/hx3b-br0",
            "DELETE /1.0/network-acls/hx3b-isolate",
            "DELETE /1.0/storage-pools/hx3b-pool",
        ]
    );
    // Idempotent: a second call finds nothing and deletes nothing more.
    let again = teardown_host(&c, &naming()).await.unwrap();
    assert_eq!(again.pool, Teardown::Absent);
    assert_eq!(again.desktop_profile, Teardown::Absent);
    assert_eq!(deleted(&fake).len(), 5);
}

#[tokio::test]
async fn objects_with_our_name_but_no_marker_are_never_deleted() {
    let fake = Fake::start().await;
    // Someone else's objects that happen to have our names: no hash-xcreen description.
    fake.with(|s| {
        s.pools.insert(
            "hx3b-pool".into(),
            json!({"name":"hx3b-pool","driver":"dir","config":{},"status":"Created","description":"my backup pool"}),
        );
        s.networks
            .insert("hx3b-br0".into(), Default::default());
        s.descriptions.insert("hx3b-br0".into(), "".into());
        s.acls.insert(
            "hx3b-isolate".into(),
            json!({"name":"hx3b-isolate","description":"not ours"}),
        );
        s.profiles.insert(
            "hx3b-desktop".into(),
            json!({"name":"hx3b-desktop","description":"someone's profile"}),
        );
        // No description field at all.
        s.profiles
            .insert("hx3b-compat-debian13".into(), json!({"name":"hx3b-compat-debian13"}));
    });
    let r = teardown_host(&fake.client(), &naming()).await.unwrap();
    for t in [
        r.desktop_profile,
        r.compat_profile,
        r.network,
        r.acl,
        r.pool,
    ] {
        assert_eq!(t, Teardown::SkippedUnmarked);
    }
    assert!(deleted(&fake).is_empty(), "{:?}", deleted(&fake));
    // A description that merely contains the word, not at the start, is not the marker.
    fake.with(|s| {
        s.profiles.insert(
            "hx3b-desktop".into(),
            json!({"name":"hx3b-desktop","description":"copy of hash-xcreen desktop"}),
        );
    });
    let r = teardown_host(&fake.client(), &naming()).await.unwrap();
    assert_eq!(r.desktop_profile, Teardown::SkippedUnmarked);
}

#[tokio::test]
async fn a_failure_midway_passes_through_and_the_rest_is_not_attempted() {
    let fake = Fake::start().await;
    let c = fake.client();
    ensure_host(&c, &host_spec()).await.unwrap();
    fake.with(|s| {
        s.overrides.insert(
            "DELETE /1.0/networks/hx3b-br0".into(),
            (
                400,
                json!({"type":"error","error_code":400,"error":"The network is currently in use"})
                    .to_string(),
            ),
        );
    });
    let err = teardown_host(&c, &naming()).await.unwrap_err();
    assert!(
        matches!(&err, ProvisionError::Incus(e) if e.to_string().contains("in use")),
        "{err}"
    );
    let d = deleted(&fake);
    assert!(d.iter().any(|k| k.contains("profiles/hx3b-desktop")));
    assert!(!d.iter().any(|k| k.contains("storage-pools")), "{d:?}");
}

fn spec_for_instance() -> DesktopSpec {
    let plan = Catalog::embedded()
        .resolve(
            RecipeId {
                distro: Distro::Ubuntu2404,
                desktop: Desktop::Xfce,
                preset: Preset::Basic,
            },
            &[],
        )
        .unwrap();
    DesktopSpec::for_plan("hx3b-main", naming(), &plan, Limits::default())
}

#[test]
fn a_created_instance_is_marked_from_the_start() {
    let body = spec_for_instance().to_create().unwrap();
    assert_eq!(body.config[INSTANCE_STATE_KEY], "creating");
}

#[tokio::test]
async fn destroy_deletes_hx_snapshots_the_link_and_the_instance() {
    let fake = Fake::start().await;
    let c = fake.client();
    fake.with(|s| {
        s.instances.insert("hx-main".into(), "Running".into());
        s.config.insert(
            "hx-main".into(),
            [("user.hx.state".to_string(), "ready".to_string())].into(),
        );
        s.snapshots = vec!["hx-daily-1".into(), "hx-daily-2".into(), "mine".into()];
    });
    c.add_session_link(
        "hx-main",
        &SessionLink::new("main", (990, 990), (1000, 1000)).unwrap(),
    )
    .await
    .unwrap();
    let r = destroy_desktop(&c, "hx-main").await.unwrap();
    assert!(r.instance_removed && r.link_removed);
    assert_eq!(r.snapshots_removed, 2);
    let d = deleted(&fake);
    assert!(d.contains(&"DELETE /1.0/instances/hx-main/snapshots/hx-daily-1".to_string()));
    assert!(
        !d.iter().any(|k| k.contains("snapshots/mine")),
        "snapshots that are not ours are not listed for deletion"
    );
    assert!(d.contains(&"DELETE /1.0/instances/hx-main".to_string()));
    assert!(!fake.with(|s| s.instances.contains_key("hx-main")));
    // Idempotent.
    let again = destroy_desktop(&c, "hx-main").await.unwrap();
    assert!(!again.instance_removed);
}

#[tokio::test]
async fn destroy_refuses_an_instance_without_the_marker() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("hx-main".into(), "Running".into());
        // Same name, but only unrelated config keys.
        s.config.insert(
            "hx-main".into(),
            [("limits.cpu".to_string(), "2".to_string())].into(),
        );
    });
    let err = destroy_desktop(&fake.client(), "hx-main")
        .await
        .unwrap_err();
    assert!(matches!(err, ProvisionError::NotOurs(_)), "{err}");
    assert!(deleted(&fake).is_empty());
    assert!(fake.with(|s| s.instances.contains_key("hx-main")));
    assert!(fake.log().iter().all(|r| r.method == "GET"));
}

#[tokio::test]
async fn destroy_validates_the_name() {
    let fake = Fake::start().await;
    assert!(destroy_desktop(&fake.client(), "../x").await.is_err());
    assert!(fake.log().is_empty());
}
