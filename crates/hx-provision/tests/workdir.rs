//! A secret is written only into a real directory that is root-owned and 0700 (a container that
//! ran user code could have pre-created /run/hx-provision with other owner or mode).

mod common;

use common::Fake;
use hx_provision::password::{PasswordChange, change_user_password};
use hx_provision::session::PASSWORD_CHECK_HELPER;
use hx_provision::{Secrets, Username};

async fn running() -> Fake {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("c1".into(), "Running".into());
    });
    fake.rule(PASSWORD_CHECK_HELPER, 0, "", "");
    fake
}

fn secrets() -> Secrets {
    Secrets::none()
        .with_user_password("new-pw-1234")
        .unwrap()
        .with_current_password("old-pw-1234")
        .unwrap()
}

async fn try_change(fake: &Fake) -> Result<PasswordChange, hx_provision::ProvisionError> {
    change_user_password(
        &fake.client(),
        "c1",
        &Username::new("alice").unwrap(),
        secrets(),
        true,
    )
    .await
}

fn wrote_a_secret(fake: &Fake) -> bool {
    fake.log()
        .iter()
        .any(|r| r.method == "POST" && r.path.contains("/stdin-"))
}

#[tokio::test]
async fn a_private_root_directory_is_accepted() {
    let fake = running().await;
    assert_eq!(try_change(&fake).await.unwrap(), PasswordChange::Changed);
    assert_eq!(
        fake.with(|s| s.dirs["/run/hx-provision"]),
        (0, 0, 0o700),
        "pushed as root:root 0700"
    );
}

#[tokio::test]
async fn a_pre_created_directory_with_the_wrong_owner_or_mode_gets_no_secret() {
    for (uid, mode) in [
        (1000, 0o700),
        (0, 0o755),
        (0, 0o770),
        (0, 0o701),
        (1000, 0o755),
    ] {
        let fake = running().await;
        // Pre-created by the container before the first push (push_dir leaves it alone).
        fake.with(|s| {
            s.dirs.insert("/run/hx-provision".into(), (uid, 0, mode));
        });
        let err = try_change(&fake).await.unwrap_err();
        let shown = format!("{err:?}");
        assert!(
            shown.contains("not a root-owned 0700 directory"),
            "{uid} {mode:o}: {shown}"
        );
        assert!(
            !wrote_a_secret(&fake),
            "{uid} {mode:o}: a secret was written"
        );
        assert!(!shown.contains("new-pw-1234") && !shown.contains("old-pw-1234"));
    }
}

#[tokio::test]
async fn a_file_where_the_directory_should_be_gets_no_secret() {
    let fake = running().await;
    fake.with(|s| {
        s.files.insert("/run/hx-provision".into(), b"x".to_vec());
    });
    let err = try_change(&fake).await.unwrap_err();
    let shown = format!("{err:?}");
    assert!(
        shown.contains("not a root-owned 0700 directory") || shown.contains("no owner or mode"),
        "{shown}"
    );
    assert!(!wrote_a_secret(&fake));
}

#[tokio::test]
async fn stat_path_reports_owner_mode_and_type() {
    let fake = running().await;
    fake.with(|s| {
        s.dirs.insert("/d".into(), (5, 6, 0o750));
    });
    let st = fake.client().stat_path("c1", "/d").await.unwrap().unwrap();
    assert_eq!(
        (st.kind.as_str(), st.uid, st.gid, st.mode),
        ("directory", 5, 6, 0o750)
    );
    assert!(
        fake.client()
            .stat_path("c1", "/nope")
            .await
            .unwrap()
            .is_none()
    );
    assert!(fake.client().stat_path("c1", "relative").await.is_err());
}
