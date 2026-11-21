//! The session-link proxy device (ipc.md 6.11 and 11): exact properties, validation, converge.

mod common;

use std::collections::BTreeMap;

use common::Fake;
use hx_provision::incus::{
    IncusError, LinkOutcome, SESSION_LINK_CONNECT, SESSION_LINK_DEVICE, SessionLink,
};
use serde_json::json;

fn link() -> SessionLink {
    SessionLink::new("main", (990, 989), (1000, 1000)).unwrap()
}

fn expected() -> BTreeMap<String, String> {
    [
        ("type", "proxy"),
        ("bind", "host"),
        ("listen", "unix:/run/hx/link/main.sock"),
        ("connect", "unix:/run/hx-session/link.sock"),
        ("uid", "990"),
        ("gid", "989"),
        ("mode", "0600"),
        ("security.uid", "1000"),
        ("security.gid", "1000"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

#[test]
fn the_device_has_exactly_the_documented_properties() {
    assert_eq!(link().device(), expected());
    assert_eq!(link().socket_path(), "/run/hx/link/main.sock");
    assert_eq!(SESSION_LINK_DEVICE, "hx-link");
    assert_eq!(SESSION_LINK_CONNECT, "/run/hx-session/link.sock");
    // The two properties that make the connect side run as the desktop user are always there.
    let d = link().device();
    assert!(d.contains_key("security.uid") && d.contains_key("security.gid"));
}

#[test]
fn inputs_are_validated() {
    let bad_ids = [
        "",
        "Main",
        "1main",
        "main-1",
        "main/x",
        "../x",
        "a.b",
        "toolongdesktopid",
        "ma in",
        "mäin",
        "main\n",
    ];
    for id in bad_ids {
        assert!(
            matches!(
                SessionLink::new(id, (990, 990), (1000, 1000)),
                Err(IncusError::InvalidArgument(_))
            ),
            "{id:?} must be refused"
        );
    }
    // Root and -1 are refused on every id, so the connect side can never run as container root
    // and the host-side socket can never be handed to root.
    for (gw, dk) in [
        ((0, 990), (1000, 1000)),
        ((990, 0), (1000, 1000)),
        ((990, 990), (0, 1000)),
        ((990, 990), (1000, 0)),
        ((u32::MAX, 990), (1000, 1000)),
        ((990, 990), (1000, u32::MAX)),
    ] {
        assert!(SessionLink::new("main", gw, dk).is_err(), "{gw:?} {dk:?}");
    }
    assert!(SessionLink::new("a", (1, 1), (1, 1)).is_ok());
    assert!(SessionLink::new("abcdefghij12", (1, 1), (1, 1)).is_ok());
}

#[tokio::test]
async fn add_patches_only_the_one_device_and_converges() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("hx-main".into(), "Running".into());
    });
    let c = fake.client();

    assert_eq!(
        c.add_session_link("hx-main", &link()).await.unwrap(),
        LinkOutcome::Added
    );
    let patches: Vec<_> = fake
        .log()
        .into_iter()
        .filter(|r| r.method == "PATCH")
        .collect();
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0].path, "/1.0/instances/hx-main");
    // The body is the device and nothing else: no config, no other device.
    assert_eq!(
        patches[0].json(),
        json!({"devices": {"hx-link": expected()}})
    );

    // Same device again: no second PATCH.
    assert_eq!(
        c.add_session_link("hx-main", &link()).await.unwrap(),
        LinkOutcome::Unchanged
    );
    assert_eq!(fake.log().iter().filter(|r| r.method == "PATCH").count(), 1);

    // Other owners: replaced.
    let other = SessionLink::new("main", (991, 991), (1000, 1000)).unwrap();
    assert_eq!(
        c.add_session_link("hx-main", &other).await.unwrap(),
        LinkOutcome::Replaced
    );
    assert_eq!(
        fake.with(|s| s.devices["hx-main"]["hx-link"]["uid"].clone()),
        "991"
    );
}

#[tokio::test]
async fn a_device_of_that_name_that_is_not_a_proxy_is_not_overwritten() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("hx-main".into(), "Stopped".into());
        s.devices.insert(
            "hx-main".into(),
            [(
                "hx-link".to_string(),
                [("type", "disk"), ("source", "/etc"), ("path", "/x")]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )]
            .into(),
        );
    });
    let err = fake
        .client()
        .add_session_link("hx-main", &link())
        .await
        .unwrap_err();
    assert!(matches!(err, IncusError::InvalidArgument(_)), "{err}");
    assert!(fake.log().iter().all(|r| r.method != "PATCH"));
}

#[tokio::test]
async fn unknown_instance_is_not_found_and_bad_names_never_reach_incus() {
    let fake = Fake::start().await;
    let c = fake.client();
    let err = c.add_session_link("hx-nope", &link()).await.unwrap_err();
    assert!(err.is_not_found(), "{err}");
    let err = c.add_session_link("../x", &link()).await.unwrap_err();
    assert!(matches!(err, IncusError::InvalidName { .. }));
    assert!(fake.log().iter().all(|r| !r.path.contains("..")));
}

#[tokio::test]
async fn remove_keeps_other_devices_and_is_idempotent() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("hx-main".into(), "Running".into());
    });
    let c = fake.client();
    assert!(!c.remove_session_link("hx-main").await.unwrap());
    c.add_session_link("hx-main", &link()).await.unwrap();
    fake.with(|s| {
        s.devices.get_mut("hx-main").unwrap().insert(
            "other".into(),
            [("type".to_string(), "none".to_string())].into(),
        );
    });
    assert!(c.remove_session_link("hx-main").await.unwrap());
    let devs = fake.with(|s| s.devices["hx-main"].clone());
    assert!(!devs.contains_key("hx-link") && devs.contains_key("other"));
    assert!(!c.remove_session_link("hx-main").await.unwrap());
    assert!(!c.remove_session_link("hx-gone").await.unwrap());
}
