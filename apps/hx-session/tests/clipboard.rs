//! Clipboard manager against a private Xvfb. The "local application" is the hx-capture
//! engine in a second connection, which owns and reads selections like any X client.

#[path = "../../../crates/hx-capture/tests/common/mod.rs"]
mod common;

use common::Xvfb;
use hx_capture::clipboard::{
    Clipboard, ClipboardConfig, ClipboardEvent, MIME_PNG, MIME_TEXT, MIME_URI_LIST, RemoteProvider,
    Selection,
};
use hx_session::clipboard::{
    ClientOffer, ClientSource, ClipboardManager, ClipboardPolicyError, ClipboardSettings,
    ReceivedEntry, RemoteFile, SourceError, StagingDir,
};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SEL: Selection = Selection::Clipboard;

/// A staging base of the test's own (the manager has no default location).
fn staging_base() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let b = std::env::temp_dir().join(format!(
        "hx-clip-it-{}-{}",
        std::process::id(),
        N.fetch_add(1, SeqCst)
    ));
    std::fs::create_dir_all(&b).unwrap();
    b
}

fn manager(x: &Xvfb) -> ClipboardManager {
    ClipboardManager::start(ClipboardSettings {
        display: Some(x.display.clone()),
        staging_base: Some(staging_base()),
        step_timeout: Duration::from_secs(2),
        ..ClipboardSettings::default()
    })
    .expect("start manager")
}

/// A second clipboard engine standing in for any local application.
fn app(x: &Xvfb) -> Clipboard {
    Clipboard::start(ClipboardConfig {
        display: Some(x.display.clone()),
        step_timeout: Duration::from_secs(2),
        ..ClipboardConfig::default()
    })
    .expect("start app")
}

struct Static(HashMap<&'static str, Vec<u8>>);

impl RemoteProvider for Static {
    fn fetch(&self, mime: &str, _max: u64) -> Option<Vec<u8>> {
        self.0.get(mime).cloned()
    }
}

fn app_offers(app: &Clipboard, items: Vec<(&'static str, Vec<u8>)>) {
    let formats = items.iter().map(|(m, _)| (*m).to_owned()).collect();
    app.offer_remote(SEL, formats, Arc::new(Static(items.into_iter().collect())))
        .expect("offer");
}

fn next_offer(m: &ClipboardManager) -> Vec<String> {
    let rx = m.events();
    loop {
        match rx.recv_timeout(Duration::from_secs(5)).expect("event") {
            ClipboardEvent::LocalOffer { formats, .. } => return formats,
            _ => continue,
        }
    }
}

fn png(len: usize) -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    v.extend((0..len).map(|i| (i * 7 % 253) as u8));
    v
}

/// Fake network side of a client offer.
struct FakeClient {
    text: Vec<u8>,
    image: Vec<u8>,
    files: Vec<(String, Vec<u8>)>,
    fetches: AtomicUsize,
    staged: Mutex<Vec<PathBuf>>,
}

impl ClientSource for FakeClient {
    fn fetch(&self, mime: &str, max: u64) -> Result<Vec<u8>, SourceError> {
        self.fetches.fetch_add(1, SeqCst);
        let d = match mime {
            MIME_TEXT => &self.text,
            MIME_PNG => &self.image,
            _ => return Err(SourceError("no such format".into())),
        };
        if d.len() as u64 > max {
            return Err(SourceError("too large".into()));
        }
        Ok(d.clone())
    }

    fn stage_files(
        &self,
        files: &[RemoteFile],
        staging: &StagingDir,
    ) -> Result<Vec<PathBuf>, SourceError> {
        let mut paths = Vec::new();
        for (f, (_, data)) in files.iter().zip(&self.files) {
            let p = staging
                .alloc(&f.name)
                .map_err(|e| SourceError(e.to_string()))?;
            std::fs::write(&p, data).map_err(|e| SourceError(e.to_string()))?;
            paths.push(p);
        }
        self.staged.lock().unwrap().extend(paths.clone());
        Ok(paths)
    }
}

fn client() -> Arc<FakeClient> {
    Arc::new(FakeClient {
        text: "grüße \u{1f600}".as_bytes().to_vec(),
        image: png(1_500_000),
        files: vec![
            ("one.txt".into(), b"first".to_vec()),
            ("two.bin".into(), vec![9; 70_000]),
        ],
        fetches: AtomicUsize::new(0),
        staged: Mutex::new(Vec::new()),
    })
}

#[test]
fn local_text_and_image_reach_the_client_side() {
    let Some(x) = Xvfb::start(320, 200) else {
        return;
    };
    let m = manager(&x);
    let a = app(&x);
    let image = png(2_000_000);
    app_offers(
        &a,
        vec![
            (MIME_TEXT, "h\u{e9}llo \u{2713}".as_bytes().to_vec()),
            (MIME_PNG, image.clone()),
        ],
    );
    assert_eq!(
        next_offer(&m),
        vec![MIME_TEXT.to_owned(), MIME_PNG.to_owned()]
    );
    assert_eq!(m.read_text(SEL).unwrap(), "h\u{e9}llo \u{2713}");
    assert_eq!(m.read_image(SEL).unwrap(), image);
}

#[test]
fn local_image_that_is_not_a_png_is_refused() {
    let Some(x) = Xvfb::start(320, 200) else {
        return;
    };
    let m = manager(&x);
    let a = app(&x);
    app_offers(&a, vec![(MIME_PNG, b"GIF89a....".to_vec())]);
    next_offer(&m);
    assert!(matches!(
        m.read_image(SEL),
        Err(ClipboardPolicyError::Invalid { .. })
    ));
}

#[test]
fn client_text_and_image_reach_local_applications() {
    let Some(x) = Xvfb::start(320, 200) else {
        return;
    };
    let m = manager(&x);
    let a = app(&x);
    let c = client();
    let formats = m
        .offer(
            SEL,
            ClientOffer {
                formats: vec![
                    "text/plain;charset=UTF-8".into(),
                    "image/png".into(),
                    "image/webp".into(), // unsupported: ignored
                ],
                files: vec![],
            },
            c.clone(),
        )
        .unwrap();
    assert_eq!(formats, vec![MIME_TEXT.to_owned(), MIME_PNG.to_owned()]);
    assert_eq!(
        app_offer(&a),
        vec![MIME_TEXT.to_owned(), MIME_PNG.to_owned()]
    );
    assert_eq!(a.fetch_local(SEL, MIME_TEXT).unwrap(), c.text);
    assert_eq!(a.fetch_local(SEL, MIME_PNG).unwrap(), c.image);
    assert_eq!(c.fetches.load(SeqCst), 2, "fetched lazily, once per format");
}

/// The next non-empty offer a bare engine (a local application) sees.
fn app_offer(a: &Clipboard) -> Vec<String> {
    loop {
        match a
            .events()
            .recv_timeout(Duration::from_secs(5))
            .expect("event")
        {
            ClipboardEvent::LocalOffer { formats, .. } => return formats,
            _ => continue,
        }
    }
}

#[test]
fn local_files_become_a_validated_transfer_list() {
    let Some(x) = Xvfb::start(320, 200) else {
        return;
    };
    let dir = std::env::temp_dir().join(format!("hx-files-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("a b.txt"), b"hello").unwrap();
    std::fs::write(dir.join("big.bin"), vec![1u8; 12345]).unwrap();
    std::fs::write(dir.join("bad:name.txt"), b"x").unwrap();
    std::os::unix::fs::symlink(dir.join("a b.txt"), dir.join("link.txt")).unwrap();
    let uri = |name: &str| {
        let p = dir.join(name);
        let enc: String = p
            .to_str()
            .unwrap()
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"/-_.".contains(&b) {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        format!("file://{enc}\r\n")
    };
    let list = [
        uri("a b.txt"),
        uri("big.bin"),
        uri("sub"),
        uri("bad:name.txt"),
        uri("link.txt"),
        "http://example.com/x\r\n".to_owned(),
        uri("missing"),
    ]
    .concat();
    let m = manager(&x);
    let a = app(&x);
    app_offers(&a, vec![(MIME_URI_LIST, list.into_bytes())]);
    assert_eq!(next_offer(&m), vec![MIME_URI_LIST.to_owned()]);
    let t = m.read_files(SEL).unwrap();
    let names: Vec<&str> = t.files.iter().map(|f| f.name.as_str()).collect();
    // The symlink is resolved to its target (which is then offered under that name).
    assert_eq!(names, vec!["a b.txt", "big.bin", "a b.txt"]);
    assert_eq!(t.total_bytes(), 5 + 12345 + 5);
    let reasons: Vec<&str> = t.skipped.iter().map(|s| s.reason).collect();
    assert_eq!(
        reasons,
        vec![
            "directories are not supported",
            "name not allowed",
            "not a file: URI",
            "cannot be read"
        ]
    );
    let mut s = String::new();
    t.files[0].open().unwrap().read_to_string(&mut s).unwrap();
    assert_eq!(s, "hello");
    // A file that changed size after listing is refused.
    std::fs::write(dir.join("big.bin"), b"short").unwrap();
    assert!(t.files[1].open().is_err());
    // So is one swapped for a symlink.
    std::fs::remove_file(dir.join("a b.txt")).unwrap();
    std::os::unix::fs::symlink(dir.join("big.bin"), dir.join("a b.txt")).unwrap();
    assert!(t.files[0].open().is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn client_files_are_staged_when_pasted_and_cleaned_up() {
    let Some(x) = Xvfb::start(320, 200) else {
        return;
    };
    let m = manager(&x);
    let a = app(&x);
    let c = client();
    let formats = m
        .offer(
            SEL,
            ClientOffer {
                formats: vec![],
                files: vec![
                    RemoteFile {
                        name: "one.txt".into(),
                        size: 5,
                    },
                    RemoteFile {
                        name: "two.bin".into(),
                        size: 70_000,
                    },
                ],
            },
            c.clone(),
        )
        .unwrap();
    assert_eq!(formats, vec![MIME_URI_LIST.to_owned()]);
    assert_eq!(app_offer(&a), vec![MIME_URI_LIST.to_owned()]);
    // Nothing is downloaded until a local application pastes.
    assert!(c.staged.lock().unwrap().is_empty());
    let list = String::from_utf8(a.fetch_local(SEL, MIME_URI_LIST).unwrap()).unwrap();
    let uris: Vec<&str> = list.lines().collect();
    assert_eq!(uris.len(), 2);
    let staged = c.staged.lock().unwrap().clone();
    assert_eq!(staged.len(), 2);
    for (u, p) in uris.iter().zip(&staged) {
        assert!(u.starts_with("file:///"), "{u}");
        assert!(p.exists());
    }
    assert_eq!(std::fs::read(&staged[0]).unwrap(), b"first");
    assert_eq!(std::fs::read(&staged[1]).unwrap().len(), 70_000);
    // Withdrawing the offer deletes what was staged.
    m.withdraw(SEL).unwrap();
    assert!(!staged[0].exists() && !staged[1].exists());
}

#[test]
fn hostile_client_offers_are_rejected() {
    let Some(x) = Xvfb::start(320, 200) else {
        return;
    };
    let m = manager(&x);
    let c = client();
    let offer = |formats: Vec<&str>, files: Vec<(&str, u64)>| ClientOffer {
        formats: formats.into_iter().map(String::from).collect(),
        files: files
            .into_iter()
            .map(|(n, s)| RemoteFile {
                name: n.into(),
                size: s,
            })
            .collect(),
    };
    let bad = [
        offer(vec!["not a mime"], vec![]),
        offer(vec!["text/plain\n"], vec![]),
        offer(vec![], vec![("../evil", 1)]),
        offer(vec![], vec![("a/b", 1)]),
        offer(vec![], vec![("NUL", 1)]),
        offer(vec![], vec![("ok.txt", u64::MAX), ("ok2.txt", 1)]),
        offer(vec![], (0..1001).map(|_| ("f.txt", 1)).collect()),
        offer(vec!["application/x-unsupported"], vec![]),
        offer(vec![], vec![]),
    ];
    for (i, o) in bad.into_iter().enumerate() {
        assert!(
            matches!(
                m.offer(SEL, o, c.clone()),
                Err(ClipboardPolicyError::Invalid { .. })
            ),
            "offer {i} should be refused"
        );
    }
    assert_eq!(c.fetches.load(SeqCst), 0);
}

#[test]
fn bad_data_from_the_client_is_not_pasted() {
    let Some(x) = Xvfb::start(320, 200) else {
        return;
    };
    let m = manager(&x);
    let a = app(&x);
    let c = Arc::new(FakeClient {
        text: b"ok\xff\x00text".to_vec(),
        image: b"definitely not a png".to_vec(),
        files: vec![],
        fetches: AtomicUsize::new(0),
        staged: Mutex::new(Vec::new()),
    });
    m.offer(
        SEL,
        ClientOffer {
            formats: vec![MIME_TEXT.into(), MIME_PNG.into()],
            files: vec![],
        },
        c,
    )
    .unwrap();
    app_offer(&a);
    // Invalid UTF-8 is replaced and NUL dropped; a fake PNG is refused outright.
    assert_eq!(
        String::from_utf8(a.fetch_local(SEL, MIME_TEXT).unwrap()).unwrap(),
        "ok\u{fffd}text"
    );
    assert!(a.fetch_local(SEL, MIME_PNG).is_err());
}

#[test]
fn switching_the_clipboard_off_makes_no_x_connection() {
    let m = ClipboardManager::start(ClipboardSettings {
        enabled: false,
        display: Some(":99999".into()), // would fail to connect if it were used
        ..ClipboardSettings::default()
    })
    .unwrap();
    assert!(!m.is_enabled());
    assert!(matches!(
        m.offer(SEL, ClientOffer::default(), client()),
        Err(ClipboardPolicyError::Disabled)
    ));
}

#[test]
fn received_files_are_offered_as_a_file_list_pointing_into_the_received_directory() {
    let Some(x) = Xvfb::start(320, 200) else {
        return;
    };
    let m = manager(&x);
    let a = app(&x);
    let dir = std::env::temp_dir().join(format!("hx-recv-offer-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.txt"), b"alpha").unwrap();
    std::fs::write(dir.join("b c.txt"), b"bravo!").unwrap();
    let files = [
        ReceivedEntry {
            name: "a.txt".into(),
            size: 5,
        },
        ReceivedEntry {
            name: "b c.txt".into(),
            size: 6,
        },
    ];
    m.offer_received_files(SEL, &dir, &files).unwrap();
    assert_eq!(app_offer(&a), vec![MIME_URI_LIST.to_owned()]);
    // Pasting: file URIs of the files themselves, not a copy.
    let list = String::from_utf8(a.fetch_local(SEL, MIME_URI_LIST).unwrap()).unwrap();
    let root = std::fs::canonicalize(&dir).unwrap();
    let uris: Vec<&str> = list.lines().collect();
    assert_eq!(
        uris,
        [
            format!("file://{}/a.txt", root.display()),
            format!("file://{}/b%20c.txt", root.display()),
        ]
    );
    assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"alpha");

    // A received file replaced by a symlink (or resized) before the paste is not handed out.
    // (The engine keeps the answer of one offer, so a new offer is made first.)
    m.offer_received_files(SEL, &dir, &files).unwrap();
    std::fs::remove_file(dir.join("a.txt")).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", dir.join("a.txt")).unwrap();
    assert!(a.fetch_local(SEL, MIME_URI_LIST).is_err());

    // Names that are not plain names are refused before anything is offered.
    for bad in ["", "../x", "a/b", "CON", "x\0y"] {
        let e = [ReceivedEntry {
            name: bad.into(),
            size: 1,
        }];
        assert!(
            matches!(
                m.offer_received_files(SEL, &dir, &e),
                Err(ClipboardPolicyError::Invalid { .. })
            ),
            "{bad:?}"
        );
    }
    assert!(m.offer_received_files(SEL, &dir, &[]).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
