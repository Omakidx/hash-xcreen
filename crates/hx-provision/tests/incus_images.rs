//! The Incus image API (import with a streamed body, aliases, get, list, guarded delete) against
//! the fake daemon on a real unix socket.

mod common;

use std::io::Write;
use std::time::Duration;

use common::{Fake, OP_ID};
use hx_provision::incus::{
    Client, IMAGE_ALIAS_PREFIX, ImageUpload, IncusError, Request, Response, Transport, UPLOAD_FRAME,
};
use sha2::{Digest, Sha256};

fn sha(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn temp_file(data: &[u8]) -> std::fs::File {
    let mut f = tempfile_in_dir();
    f.write_all(data).unwrap();
    f
}

/// An anonymous file (created, then unlinked) so nothing is left behind.
fn tempfile_in_dir() -> std::fs::File {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let p = std::env::temp_dir().join(format!(
        "hx-img-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&p)
        .unwrap();
    std::fs::remove_file(&p).unwrap();
    f
}

fn upload(data: &[u8]) -> ImageUpload {
    ImageUpload {
        file: temp_file(data),
        len: data.len() as u64,
        fingerprint: sha(data),
    }
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

const T: Duration = Duration::from_secs(30);

#[tokio::test]
async fn import_streams_the_file_and_returns_the_fingerprint() {
    let fake = Fake::start().await;
    // Several frames, the last one short.
    let data = pattern(UPLOAD_FRAME * 3 + 12_345);
    let fp = fake.client().import_image(upload(&data), T).await.unwrap();
    assert_eq!(fp, sha(&data));

    let post = fake
        .log()
        .into_iter()
        .find(|r| r.key() == "POST /1.0/images")
        .unwrap();
    assert_eq!(post.body, data, "every byte arrived, in order");
    assert_eq!(post.headers["x-incus-fingerprint"], fp);
    assert_eq!(post.headers["x-incus-public"], "0");
    assert_eq!(post.headers["content-type"], "application/octet-stream");
    assert_eq!(post.headers["content-length"], data.len().to_string());
    assert!(fake.with(|s| s.images.contains_key(&fp)));
}

#[tokio::test]
async fn a_large_sparse_file_is_streamed() {
    let fake = Fake::start().await;
    let len: u64 = 40 * 1024 * 1024 + 7;
    let f = tempfile_in_dir();
    f.set_len(len).unwrap();
    let mut h = Sha256::new();
    let zeros = vec![0u8; 1024 * 1024];
    let mut left = len;
    while left > 0 {
        let n = left.min(zeros.len() as u64) as usize;
        h.update(&zeros[..n]);
        left -= n as u64;
    }
    let fp: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    let got = fake
        .client()
        .import_image(
            ImageUpload {
                file: f,
                len,
                fingerprint: fp.clone(),
            },
            T,
        )
        .await
        .unwrap();
    assert_eq!(got, fp);
    assert_eq!(fake.with(|s| s.images[&fp].1), len);
}

#[tokio::test]
async fn only_the_declared_length_is_sent() {
    let fake = Fake::start().await;
    let data = pattern(5000);
    let fp = sha(&data[..3000]);
    let got = fake
        .client()
        .import_image(
            ImageUpload {
                file: temp_file(&data),
                len: 3000,
                fingerprint: fp.clone(),
            },
            T,
        )
        .await
        .unwrap();
    assert_eq!(got, fp);
}

#[tokio::test]
async fn a_fingerprint_mismatch_is_rejected_and_nothing_is_stored() {
    let fake = Fake::start().await;
    let data = pattern(10_000);
    let mut up = upload(&data);
    up.fingerprint = sha(b"something else");
    let err = fake.client().import_image(up, T).await.unwrap_err();
    assert!(matches!(err, IncusError::Api { code: 400, .. }), "{err:?}");
    assert!(fake.with(|s| s.images.is_empty()));
}

#[tokio::test]
async fn an_image_stored_under_another_fingerprint_is_an_error() {
    let fake = Fake::start().await;
    fake.with(|s| s.import_reports = Some("f".repeat(64)));
    let err = fake
        .client()
        .import_image(upload(&pattern(100)), T)
        .await
        .unwrap_err();
    assert!(matches!(err, IncusError::Protocol(_)), "{err:?}");
    // No fingerprint at all in the result.
    fake.with(|s| {
        s.images.clear();
        s.import_reports = Some("not a fingerprint".into());
    });
    let err = fake
        .client()
        .import_image(upload(&pattern(100)), T)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, IncusError::Protocol(m) if !m.contains("not a fingerprint")),
        "{err:?}"
    );
}

#[tokio::test]
async fn importing_twice_is_a_conflict() {
    let fake = Fake::start().await;
    let data = pattern(2000);
    fake.client().import_image(upload(&data), T).await.unwrap();
    let err = fake
        .client()
        .import_image(upload(&data), T)
        .await
        .unwrap_err();
    assert!(matches!(err, IncusError::Api { code: 409, .. }), "{err:?}");
}

#[tokio::test]
async fn bad_arguments_never_reach_the_daemon() {
    let fake = Fake::start().await;
    let c = fake.client();
    for bad in ["", "abc", &"A".repeat(64), &"g".repeat(64), &"a".repeat(65)] {
        let mut up = upload(b"x");
        up.fingerprint = bad.to_string();
        assert!(matches!(
            c.import_image(up, T).await,
            Err(IncusError::InvalidArgument(_))
        ));
        assert!(matches!(
            c.get_image(bad).await,
            Err(IncusError::InvalidArgument(_))
        ));
        assert!(matches!(
            c.delete_image(bad).await,
            Err(IncusError::InvalidArgument(_))
        ));
    }
    let empty = ImageUpload {
        file: temp_file(b""),
        len: 0,
        fingerprint: sha(b""),
    };
    assert!(matches!(
        c.import_image(empty, T).await,
        Err(IncusError::InvalidArgument(_))
    ));
    assert_eq!(fake.with(|s| s.import_requests), 0);
    assert!(fake.log().is_empty());
}

#[tokio::test]
async fn a_file_shorter_than_its_length_fails_instead_of_hanging() {
    let fake = Fake::start().await;
    let data = pattern(UPLOAD_FRAME + 10);
    let up = ImageUpload {
        file: temp_file(&data),
        len: data.len() as u64 + 500,
        fingerprint: sha(&data),
    };
    let err = fake.client().import_image(up, T).await.unwrap_err();
    assert!(matches!(err, IncusError::Http(_)), "{err:?}");
    assert!(fake.with(|s| s.images.is_empty()));
}

#[tokio::test]
async fn the_deadline_bounds_the_import() {
    let fake = Fake::start().await;
    fake.with(|s| s.stuck_ops = true);
    let err = fake
        .client()
        .import_image(upload(&pattern(100)), Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(matches!(err, IncusError::Timeout { .. }), "{err:?}");
}

#[tokio::test]
async fn a_purged_import_operation_is_settled_by_the_store() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.forgotten_ops.insert(OP_ID.to_string());
    });
    let data = pattern(300);
    let fp = fake.client().import_image(upload(&data), T).await.unwrap();
    assert_eq!(fp, sha(&data));
}

#[tokio::test]
async fn aliases_get_and_list() {
    let fake = Fake::start().await;
    let c = fake.client();
    let a = pattern(500);
    let fp = c.import_image(upload(&a), T).await.unwrap();

    assert!(c.get_image(&sha(b"nope")).await.unwrap().is_none());
    let info = c.get_image(&fp).await.unwrap().unwrap();
    assert_eq!(info.fingerprint, fp);
    assert_eq!(info.size, 500);
    assert!(info.aliases.is_empty());

    c.create_image_alias("hx-img-ubuntu-24.04-xfce-basic", &fp)
        .await
        .unwrap();
    let info = c.get_image(&fp).await.unwrap().unwrap();
    assert_eq!(info.aliases, ["hx-img-ubuntu-24.04-xfce-basic"]);

    let err = c
        .create_image_alias("hx-img-ubuntu-24.04-xfce-basic", &fp)
        .await
        .unwrap_err();
    assert!(matches!(err, IncusError::Api { code: 409, .. }));

    for bad in ["ubuntu", "hx-img", "hx-img-a/b", "hx-img-a b"] {
        assert!(
            matches!(
                c.create_image_alias(bad, &fp).await,
                Err(IncusError::InvalidName { .. })
            ),
            "{bad}"
        );
    }
    assert!(matches!(
        c.create_image_alias("hx-img-x", "short").await,
        Err(IncusError::InvalidArgument(_))
    ));

    let b = pattern(700);
    let fp2 = c.import_image(upload(&b), T).await.unwrap();
    let mut list = c.list_images().await.unwrap();
    list.sort_by_key(|i| i.size);
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].fingerprint, fp);
    assert_eq!(list[1].fingerprint, fp2);
    assert!(
        fake.keys()
            .contains(&"GET /1.0/images?recursion=1".to_string())
    );
}

#[tokio::test]
async fn delete_refuses_an_image_without_our_alias() {
    let fake = Fake::start().await;
    let c = fake.client();
    let data = pattern(400);
    let fp = c.import_image(upload(&data), T).await.unwrap();

    // No alias at all.
    let err = c.delete_image(&fp).await.unwrap_err();
    assert!(matches!(err, IncusError::InvalidArgument(_)), "{err:?}");
    // An alias that is not ours (put there behind the client's back).
    fake.with(|s| s.images.get_mut(&fp).unwrap().0.push("ubuntu/24.04".into()));
    assert!(c.delete_image(&fp).await.is_err());
    assert!(
        !fake
            .keys()
            .iter()
            .any(|k| k.starts_with("DELETE /1.0/images")),
        "no delete request was sent: {:?}",
        fake.keys()
    );
    assert!(fake.with(|s| s.images.contains_key(&fp)));

    // Ours.
    c.create_image_alias(&format!("{IMAGE_ALIAS_PREFIX}x"), &fp)
        .await
        .unwrap();
    assert!(c.delete_image(&fp).await.unwrap());
    assert!(fake.with(|s| s.images.is_empty()));
    // Gone: not an error, and `false`.
    assert!(!c.delete_image(&fp).await.unwrap());
}

/// A transport that does not implement `send_file`, like the scripted fakes of other crates.
struct NoFiles;

impl Transport for NoFiles {
    async fn send(&self, _request: Request) -> Result<Response, IncusError> {
        Err(IncusError::Http("not reached".into()))
    }
}

#[tokio::test]
async fn a_transport_without_streaming_says_unsupported() {
    let err = Client::new(NoFiles)
        .import_image(upload(b"data"), T)
        .await
        .unwrap_err();
    assert!(matches!(err, IncusError::Unsupported(_)), "{err:?}");
}
