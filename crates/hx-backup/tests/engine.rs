#![cfg(feature = "engine")]
//! Engine integration tests against rustic's local backend in a temp directory.
//!
//! Offline, no root, no network. The ownership test that needs root is `#[ignore]`d.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hx_backup::engine::{
    BackupRequest, CancelToken, Engine, EngineError, EngineOptions, ForgetRequest, KeepRules,
    NullSink, OpenMode, Ownership, Phase, ProgressEvent, ProgressSink, ReadData, RepoKey,
    RepositoryBackends, RestoreRequest, Resume, SnapshotSelector,
};
use hx_backup::manifest::{Distro, ManifestInput};
use hx_backup::rules::{DockerMode, MOUNT_POINTS, RuleSet};
use jiff::Timestamp;
use rustic_backend::BackendOptions;

const KEY: &str = "correct horse battery staple 1f2e3d";

fn backends(repo: &Path) -> RepositoryBackends {
    BackendOptions::default()
        .repository(repo.to_str().unwrap())
        .to_backends()
        .unwrap()
}

fn key() -> RepoKey {
    RepoKey::from_bytes(KEY).unwrap()
}

fn open_with(
    repo: &Path,
    mode: OpenMode,
    sink: Arc<dyn ProgressSink>,
) -> Result<Engine, EngineError> {
    let o = EngineOptions {
        open_mode: mode,
        ..EngineOptions::default()
    };
    Engine::open(&backends(repo), &key(), &o, sink)
}

fn open(repo: &Path) -> Engine {
    open_with(repo, OpenMode::OpenOrInit, Arc::new(NullSink)).unwrap()
}

fn manifest_input() -> ManifestInput {
    ManifestInput {
        agent_version: "0.1.0-test".into(),
        distro: Distro {
            id: "ubuntu".into(),
            version_id: "24.04".into(),
            pretty_name: None,
        },
        desktop: "xfce4".into(),
        preset: "dev".into(),
        docker_mode: Some(DockerMode::Complete),
        container_config: BTreeMap::from([("limits.cpu".to_owned(), "4".to_owned())]),
    }
}

fn request(source: &Path) -> BackupRequest {
    BackupRequest {
        source: source.to_owned(),
        rules: RuleSet::with_defaults(DockerMode::Complete),
        manifest: manifest_input(),
        tags: vec!["nightly".into()],
        host: "hx-desktop".into(),
        time: None,
    }
}

/// Deterministic incompressible bytes.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn put(root: &Path, rel: &str, data: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, data).unwrap();
}

/// A desktop-like tree. Returns whether the sparse file really is sparse on this filesystem.
fn make_tree(root: &Path) -> bool {
    put(root, "etc/hostname", b"hx-desktop\n");
    put(root, "etc/os-release", b"ID=ubuntu\nVERSION_ID=\"24.04\"\n");
    put(
        root,
        "home/alice/.claude/.credentials.json",
        b"{\"token\":\"x\"}",
    );
    put(
        root,
        "home/alice/.claude/projects/p/s.jsonl",
        &noise(1, 40_000),
    );
    put(root, "home/alice/.claude.json", b"{}");
    put(root, "home/alice/docs/report.txt", &noise(2, 300_000));
    put(root, "home/alice/docs/empty.txt", b"");
    put(
        root,
        "home/alice/.local/share/app/state.db",
        &noise(3, 70_000),
    );
    put(
        root,
        "home/alice/.local/share/Trash/files/old.bin",
        &noise(4, 90_000),
    );
    put(root, "home/alice/.cache/thumbs/t1", &noise(5, 100_000));
    put(
        root,
        "home/alice/.config/Slack/Cache/blob",
        &noise(6, 100_000),
    );
    put(
        root,
        "home/alice/.config/Slack/Local Storage/leveldb/1.ldb",
        &noise(7, 30_000),
    );
    put(root, "home/alice/.config/Odd [1]/Cache/x", &noise(8, 5_000));
    put(
        root,
        "home/alice/.config/Odd [1]/Cachex/keep",
        &noise(9, 5_000),
    );
    put(
        root,
        "home/alice/.config/chromium/Default/Cookies",
        &noise(10, 20_000),
    );
    put(
        root,
        "home/alice/.config/chromium/Default/Cache/Cache_Data/f_1",
        &noise(11, 200_000),
    );
    put(
        root,
        "home/alice/.config/chromium/Default/Code Cache/js/x",
        &noise(12, 50_000),
    );
    put(root, "tmp/scratch", &noise(13, 10_000));
    put(root, "var/tmp/scratch", &noise(14, 10_000));
    fs::create_dir_all(root.join("proc")).unwrap();
    fs::create_dir_all(root.join("home/alice/empty-dir")).unwrap();

    // Permissions.
    fs::set_permissions(
        root.join("home/alice/.claude/.credentials.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    put(root, "usr/local/bin/tool", b"#!/bin/sh\nexit 0\n");
    fs::set_permissions(
        root.join("usr/local/bin/tool"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::set_permissions(
        root.join("home/alice/docs"),
        fs::Permissions::from_mode(0o750),
    )
    .unwrap();

    // Symlinks: relative, absolute, dangling, and one pointing out of the tree.
    symlink("docs/report.txt", root.join("home/alice/link-rel")).unwrap();
    symlink("/etc/hostname", root.join("home/alice/link-abs")).unwrap();
    symlink("nowhere", root.join("home/alice/link-dangling")).unwrap();
    symlink("/", root.join("home/alice/link-out")).unwrap();

    // Hard links.
    put(root, "home/alice/hl/a", &noise(15, 60_000));
    fs::hard_link(root.join("home/alice/hl/a"), root.join("home/alice/hl/b")).unwrap();

    // Sparse file: 16 MiB with data only at both ends.
    let sp = root.join("home/alice/sparse.img");
    let mut f = File::create(&sp).unwrap();
    f.set_len(16 << 20).unwrap();
    f.write_all(b"head").unwrap();
    f.seek(SeekFrom::Start((16 << 20) - 4)).unwrap();
    f.write_all(b"tail").unwrap();
    drop(f);
    fs::metadata(&sp).unwrap().blocks() * 512 < 1 << 20
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    kind: char,
    mode: u32,
    uid: u32,
    gid: u32,
    len: u64,
    mtime: i64,
    content: Vec<u8>,
    link: Option<PathBuf>,
}

/// Every entry below `root` (rootfs-relative key), skipping what `skip` says (and below it).
fn tree_of(
    root: &Path,
    skip: &dyn Fn(&Path) -> bool,
) -> (BTreeMap<PathBuf, Entry>, Vec<Vec<PathBuf>>) {
    let mut out = BTreeMap::new();
    let mut inodes: BTreeMap<(u64, u64), Vec<PathBuf>> = BTreeMap::new();
    let mut stack = vec![root.to_owned()];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            let rel = Path::new("/").join(p.strip_prefix(root).unwrap());
            if skip(&rel) {
                continue;
            }
            let md = fs::symlink_metadata(&p).unwrap();
            let ft = md.file_type();
            let (kind, content, link) = if ft.is_dir() {
                stack.push(p.clone());
                ('d', Vec::new(), None)
            } else if ft.is_symlink() {
                ('l', Vec::new(), Some(fs::read_link(&p).unwrap()))
            } else {
                if md.nlink() > 1 {
                    inodes
                        .entry((md.dev(), md.ino()))
                        .or_default()
                        .push(rel.clone());
                }
                ('f', fs::read(&p).unwrap(), None)
            };
            out.insert(
                rel,
                Entry {
                    kind,
                    mode: md.mode() & 0o7777,
                    uid: md.uid(),
                    gid: md.gid(),
                    len: if ft.is_file() { md.len() } else { 0 },
                    mtime: if ft.is_file() { md.mtime() } else { 0 },
                    content,
                    link,
                },
            );
        }
    }
    let mut groups: Vec<Vec<PathBuf>> = inodes
        .into_values()
        .map(|mut v| {
            v.sort();
            v
        })
        .collect();
    groups.sort();
    (out, groups)
}

fn is_mount_point(rel: &Path) -> bool {
    MOUNT_POINTS.iter().any(|(mp, _)| rel == Path::new(mp))
}

fn dir_size(root: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![root.to_owned()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(d).unwrap() {
            let e = e.unwrap();
            let md = e.metadata().unwrap();
            if md.is_dir() {
                stack.push(e.path());
            } else {
                total += md.len();
            }
        }
    }
    total
}

#[derive(Default)]
struct Collect(Mutex<Vec<ProgressEvent>>);

impl ProgressSink for Collect {
    fn event(&self, e: &ProgressEvent) {
        self.0.lock().unwrap().push(e.clone());
    }
}

fn skip_none(_: &Path) -> bool {
    false
}

#[test]
fn backup_and_restore_round_trip() {
    let src = tempfile::tempdir().unwrap();
    let repo_dir = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let truly_sparse = make_tree(src.path());

    let sink = Arc::new(Collect::default());
    let mut engine = open_with(repo_dir.path(), OpenMode::OpenOrInit, sink.clone()).unwrap();
    assert_eq!(engine.compression_level().unwrap(), Some(3), "zstd level 3");
    assert_eq!(
        engine.pack_size_limits().unwrap(),
        (Some(64 << 20), Some(16 << 20))
    );
    assert!(!repo_dir.path().join("cache").exists());

    let cancel = CancelToken::new();
    let out = engine.backup(&request(src.path()), &cancel).unwrap();

    // Rules: caches out, agent state and web data in.
    let r = &out.resolved;
    let excl = |p: &str| r.is_excluded(Path::new(p));
    for gone in [
        "/home/alice/.cache",
        "/home/alice/.local/share/Trash",
        "/home/alice/.config/Slack/Cache",
        "/home/alice/.config/Odd [1]/Cache",
        "/home/alice/.config/chromium/Default/Cache",
        "/home/alice/.config/chromium/Default/Code Cache",
        "/tmp",
        "/var/tmp",
        "/proc",
    ] {
        assert!(excl(gone), "{gone} should be excluded\n{r}");
    }
    for kept in [
        "/home/alice/.claude/.credentials.json",
        "/home/alice/.claude.json",
        "/home/alice/.local/share/app/state.db",
        "/home/alice/.config/Slack/Local Storage/leveldb/1.ldb",
        "/home/alice/.config/Odd [1]/Cachex/keep",
        "/home/alice/.config/chromium/Default/Cookies",
    ] {
        assert!(!excl(kept), "{kept} should be kept\n{r}");
    }

    // Manifest: stored in the snapshot, readable back, carries the snapshot id.
    let m = engine.read_manifest(&SnapshotSelector::Latest).unwrap();
    assert_eq!(m, out.manifest);
    assert_eq!(
        m.rustic_snapshot_id.as_deref(),
        Some(out.snapshot_id.as_str())
    );
    assert_eq!(m.docker_mode, Some(DockerMode::Complete));
    assert!(
        m.source_sizes.files >= 13 && m.source_sizes.excluded_paths >= 9,
        "{:?}",
        m.source_sizes
    );
    let listed = engine.snapshots().unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].tags.iter().any(|t| t == "hx-backup"));
    assert!(listed[0].tags.iter().any(|t| t == "nightly"));
    assert_eq!(listed[0].host, "hx-desktop");
    assert_eq!(listed[0].manifest.as_ref(), Some(&m));
    assert_eq!(out.summary.total_files, out.summary.files_new);

    // Progress was reported for the steps.
    let phases: Vec<Phase> = sink.0.lock().unwrap().iter().map(|e| e.phase).collect();
    for p in [Phase::RepairIndex, Phase::ScanSource, Phase::Backup] {
        assert!(phases.contains(&p), "no event for {p:?}: {phases:?}");
    }

    // Restore into a fresh directory and compare.
    let mut rq = RestoreRequest::new(SnapshotSelector::Id(out.snapshot_id.clone()), dst.path());
    rq.ownership = Ownership::Numeric;
    let res = engine.restore(&rq, &cancel).unwrap();
    assert!(res.files_restored > 10);
    assert_eq!(res.files_unchanged + res.files_verified, 0);

    let (want, want_links) = tree_of(src.path(), &|p| r.is_excluded(p));
    let (got, got_links) = tree_of(dst.path(), &is_mount_point);
    assert_eq!(
        want.keys().collect::<Vec<_>>(),
        got.keys().collect::<Vec<_>>(),
        "same set of paths"
    );
    for (path, w) in &want {
        let g = &got[path];
        if w.kind == 'd' {
            // Directory mtimes are not part of the comparison; the rest is.
            assert_eq!(
                (w.mode, w.uid, w.gid),
                (g.mode, g.uid, g.gid),
                "{}",
                path.display()
            );
        } else {
            assert_eq!(w, g, "{}", path.display());
        }
    }
    assert_eq!(want_links, got_links, "hard links restored as hard links");
    assert_eq!(want_links.len(), 1);
    assert_eq!(
        got[Path::new("/home/alice/.claude/.credentials.json")].mode,
        0o600
    );
    assert_eq!(got[Path::new("/home/alice/docs")].mode, 0o750);
    assert_eq!(
        got[Path::new("/home/alice/link-dangling")].link.as_deref(),
        Some(Path::new("nowhere"))
    );

    // Sparse file stays sparse where the filesystem has holes at all.
    let sp = dst.path().join("home/alice/sparse.img");
    let md = fs::metadata(&sp).unwrap();
    assert_eq!(md.len(), 16 << 20);
    if truly_sparse {
        assert!(
            md.blocks() * 512 < 4 << 20,
            "restored sparse file occupies {} bytes",
            md.blocks() * 512
        );
        // Control: without the sparse option the same file is written out in full.
        let dense = tempfile::tempdir().unwrap();
        let mut dq = RestoreRequest::new(SnapshotSelector::Latest, dense.path());
        dq.sparse = false;
        engine.restore(&dq, &cancel).unwrap();
        let md = fs::metadata(dense.path().join("home/alice/sparse.img")).unwrap();
        assert!(
            md.blocks() * 512 >= 16 << 20,
            "control restore is not dense"
        );
    } else {
        eprintln!("SKIP sparse assertion: the temp filesystem does not create holes");
    }

    // Mount points recreated with the standard modes, even though the backup skipped them.
    for (mp, mode) in MOUNT_POINTS {
        let md = fs::symlink_metadata(dst.path().join(mp.trim_start_matches('/'))).unwrap();
        assert!(md.is_dir(), "{mp}");
        assert_eq!(md.mode() & 0o7777, mode, "{mp}");
    }
    assert_eq!(res.mount_points_created.len(), MOUNT_POINTS.len());
    // Excluded content did not come back.
    assert!(!dst.path().join("home/alice/.cache").exists());
    assert!(!dst.path().join("tmp/scratch").exists());
    assert!(!dst.path().join("home/alice/.local/share/Trash").exists());
}

#[test]
fn numeric_ownership_is_applied_without_name_lookups() {
    // Without root only the caller's own ids can be restored; they must come back unchanged.
    let src = tempfile::tempdir().unwrap();
    let repo_dir = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    put(src.path(), "home/a/f", b"x");
    let mut engine = open(repo_dir.path());
    engine
        .backup(&request(src.path()), &CancelToken::new())
        .unwrap();
    let mut rq = RestoreRequest::new(SnapshotSelector::Latest, dst.path());
    rq.ownership = Ownership::Numeric;
    engine.restore(&rq, &CancelToken::new()).unwrap();
    let want = fs::metadata(src.path().join("home/a/f")).unwrap();
    let got = fs::metadata(dst.path().join("home/a/f")).unwrap();
    assert_eq!((want.uid(), want.gid()), (got.uid(), got.gid()));
}

#[test]
#[ignore = "needs root: chown to arbitrary numeric ids that exist in no passwd database"]
fn numeric_owner_ids_survive_a_restore() {
    use std::os::unix::fs::chown;
    let src = tempfile::tempdir().unwrap();
    let repo_dir = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    put(src.path(), "home/x/file", b"data");
    chown(
        src.path().join("home/x/file"),
        Some(1_234_567),
        Some(7_654_321),
    )
    .unwrap();
    chown(src.path().join("home/x"), Some(1_234_567), Some(7_654_321)).unwrap();
    let mut engine = open(repo_dir.path());
    engine
        .backup(&request(src.path()), &CancelToken::new())
        .unwrap();
    let mut rq = RestoreRequest::new(SnapshotSelector::Latest, dst.path());
    rq.ownership = Ownership::Numeric;
    engine.restore(&rq, &CancelToken::new()).unwrap();
    let md = fs::metadata(dst.path().join("home/x/file")).unwrap();
    assert_eq!((md.uid(), md.gid()), (1_234_567, 7_654_321));
    let md = fs::metadata(dst.path().join("home/x")).unwrap();
    assert_eq!((md.uid(), md.gid()), (1_234_567, 7_654_321));
}

#[test]
fn xattrs_survive_a_restore() {
    // Needs the `setfattr` tool and a filesystem with user xattrs.
    let src = tempfile::tempdir().unwrap();
    put(src.path(), "home/a/f", b"x");
    let f = src.path().join("home/a/f");
    let ok = std::process::Command::new("setfattr")
        .args(["-n", "user.hx", "-v", "kept"])
        .arg(&f)
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("SKIP xattr test: setfattr missing or the filesystem has no user xattrs");
        return;
    }
    let repo_dir = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let mut engine = open(repo_dir.path());
    engine
        .backup(&request(src.path()), &CancelToken::new())
        .unwrap();
    engine
        .restore(
            &RestoreRequest::new(SnapshotSelector::Latest, dst.path()),
            &CancelToken::new(),
        )
        .unwrap();
    let out = std::process::Command::new("getfattr")
        .args(["-n", "user.hx", "--only-values"])
        .arg(dst.path().join("home/a/f"))
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"kept");
}

#[test]
fn second_backup_adds_only_what_changed() {
    let src = tempfile::tempdir().unwrap();
    let repo_dir = tempfile::tempdir().unwrap();
    make_tree(src.path());
    let mut engine = open(repo_dir.path());
    let cancel = CancelToken::new();
    let first = engine.backup(&request(src.path()), &cancel).unwrap();
    let repo_after_first = dir_size(repo_dir.path());

    put(src.path(), "etc/hostname", b"renamed-desktop\n"); // changed
    put(src.path(), "home/alice/docs/new.txt", &noise(98, 10_000)); // new
    let second = engine.backup(&request(src.path()), &cancel).unwrap();

    assert_eq!(second.summary.files_new, 1);
    assert_eq!(second.summary.files_changed, 1);
    assert_eq!(
        second.summary.files_unmodified,
        first.summary.total_files - 1,
        "everything else is recognised from the parent"
    );
    assert!(
        second.summary.data_added_packed < first.summary.data_added_packed / 5,
        "second run added {} bytes, first {}",
        second.summary.data_added_packed,
        first.summary.data_added_packed
    );
    let growth = dir_size(repo_dir.path()) - repo_after_first;
    assert!(growth < repo_after_first / 3, "repository grew by {growth}");
    assert_eq!(engine.snapshots().unwrap().len(), 2);
}

#[test]
fn restore_resumes_and_repairs_a_partial_target() {
    let src = tempfile::tempdir().unwrap();
    let repo_dir = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    make_tree(src.path());
    let mut engine = open(repo_dir.path());
    let cancel = CancelToken::new();
    let out = engine.backup(&request(src.path()), &cancel).unwrap();
    let rq = RestoreRequest::new(SnapshotSelector::Latest, dst.path());
    let full = engine.restore(&rq, &cancel).unwrap();
    let total = full.files_restored;

    // Simulate a kill: one file never written, one cut short, one with right size and wrong
    // content (a block that was allocated but not filled).
    fs::remove_file(dst.path().join("home/alice/docs/report.txt")).unwrap();
    let cut = dst.path().join("home/alice/.claude/projects/p/s.jsonl");
    let data = fs::read(&cut).unwrap();
    fs::write(&cut, &data[..1000]).unwrap();
    let bad = dst.path().join("home/alice/.local/share/app/state.db");
    let md = fs::metadata(&bad).unwrap();
    fs::write(&bad, vec![0u8; md.len() as usize]).unwrap();
    filetime_like_restore(&bad, &md);

    let again = engine.restore(&rq, &cancel).unwrap();
    assert_eq!(
        again.files_restored, 3,
        "only the damaged files are written again"
    );
    assert!(
        again.files_unchanged + again.files_verified >= total - 3,
        "the rest was skipped: {again:?}"
    );
    assert!(again.bytes_restored < full.bytes_restored / 2);

    let (want, _) = tree_of(src.path(), &|p| out.resolved.is_excluded(p));
    let (got, _) = tree_of(dst.path(), &is_mount_point);
    for (path, w) in want.iter().filter(|(_, w)| w.kind == 'f') {
        assert_eq!(w.content, got[path].content, "{}", path.display());
    }

    // A third run finds nothing to do.
    let third = engine.restore(&rq, &cancel).unwrap();
    assert_eq!(third.files_restored, 0);
    assert_eq!(third.bytes_restored, 0);
}

/// Give `path` the size-and-mtime of the original so only a content check can notice.
fn filetime_like_restore(path: &Path, original: &fs::Metadata) {
    let f = File::options().write(true).open(path).unwrap();
    f.set_modified(original.modified().unwrap()).unwrap();
}

#[test]
fn forget_and_prune_remove_data() {
    let src = tempfile::tempdir().unwrap();
    let repo_dir = tempfile::tempdir().unwrap();
    let mut engine = open(repo_dir.path());
    let cancel = CancelToken::new();
    let mut ids = Vec::new();
    for (i, t) in [
        "2026-01-01T00:00:00Z",
        "2026-01-02T00:00:00Z",
        "2026-01-03T00:00:00Z",
    ]
    .iter()
    .enumerate()
    {
        // Each snapshot owns a distinct 1 MiB blob, so removing a snapshot frees real data.
        let _ = fs::remove_dir_all(src.path().join("data"));
        put(src.path(), "data/blob", &noise(100 + i as u64, 1 << 20));
        put(src.path(), "data/common", &noise(7, 200_000));
        let mut rq = request(src.path());
        rq.time = Some(t.parse::<Timestamp>().unwrap());
        ids.push(engine.backup(&rq, &cancel).unwrap().snapshot_id);
    }
    let size_before = dir_size(repo_dir.path());

    // Nothing to keep is not a plan.
    assert!(matches!(
        engine.forget(&ForgetRequest::new(KeepRules::default()), &cancel),
        Err(EngineError::InvalidInput { .. })
    ));

    // Dry run changes nothing.
    let mut fr = ForgetRequest::new(KeepRules {
        last: Some(1),
        ..KeepRules::default()
    });
    fr.dry_run = true;
    let dry = engine.forget(&fr, &cancel).unwrap();
    assert_eq!(dry.removed, vec![ids[0].clone()]);
    assert_eq!(engine.snapshots().unwrap().len(), 3);

    // keep-last 1 would remove two; the two newest are protected, so only the oldest goes.
    fr.dry_run = false;
    let done = engine.forget(&fr, &cancel).unwrap();
    assert_eq!(done.removed, vec![ids[0].clone()]);
    assert_eq!(done.protected, vec![ids[1].clone()]);
    assert_eq!(done.kept.len(), 2);
    let left: Vec<_> = engine
        .snapshots()
        .unwrap()
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(left, vec![ids[1].clone(), ids[2].clone()]);

    let pruned = engine.prune(&cancel).unwrap();
    assert!(pruned.removed_bytes > 0, "{pruned:?}");
    let size_after = dir_size(repo_dir.path());
    assert!(
        size_after + (1 << 19) < size_before,
        "instant prune must free the packs now: {size_before} -> {size_after}"
    );
    assert!(engine.check(ReadData::All, &cancel).unwrap().ok);

    // The surviving snapshots still restore.
    let dst = tempfile::tempdir().unwrap();
    engine
        .restore(
            &RestoreRequest::new(SnapshotSelector::Id(ids[1].clone()), dst.path()),
            &cancel,
        )
        .unwrap();
    assert_eq!(
        fs::read(dst.path().join("data/blob")).unwrap(),
        noise(101, 1 << 20)
    );
}

#[test]
fn check_passes_and_read_data_finds_a_corrupted_pack() {
    let src = tempfile::tempdir().unwrap();
    let repo_dir = tempfile::tempdir().unwrap();
    make_tree(src.path());
    let mut engine = open(repo_dir.path());
    let cancel = CancelToken::new();
    engine.backup(&request(src.path()), &cancel).unwrap();

    for r in [ReadData::None, ReadData::Percent(100.0), ReadData::All] {
        let rep = engine.check(r, &cancel).unwrap();
        assert!(rep.ok, "{r:?}: {:?}", rep.findings);
    }
    assert!(matches!(
        engine.check(ReadData::Percent(0.0), &cancel),
        Err(EngineError::InvalidInput { .. })
    ));
    assert!(matches!(
        engine.check(ReadData::Percent(101.0), &cancel),
        Err(EngineError::InvalidInput { .. })
    ));

    // Flip bytes in the middle of the biggest data pack.
    let mut biggest: Option<(u64, PathBuf)> = None;
    for sub in fs::read_dir(repo_dir.path().join("data")).unwrap() {
        for f in fs::read_dir(sub.unwrap().path()).unwrap() {
            let f = f.unwrap();
            let len = f.metadata().unwrap().len();
            if biggest.as_ref().is_none_or(|(l, _)| len > *l) {
                biggest = Some((len, f.path()));
            }
        }
    }
    let (len, pack) = biggest.unwrap();
    let mut bytes = fs::read(&pack).unwrap();
    for b in &mut bytes[len as usize / 3..len as usize / 3 + 64] {
        *b ^= 0xA5;
    }
    fs::write(&pack, bytes).unwrap();

    // Metadata checks do not read data packs: still fine. Reading the data notices.
    assert!(engine.check(ReadData::None, &cancel).unwrap().ok);
    let rep = engine.check(ReadData::All, &cancel);
    match rep {
        Ok(r) => assert!(!r.ok && !r.findings.is_empty(), "corruption missed: {r:?}"),
        Err(e) => panic!("check should report, not fail: {e}"),
    }
    let rep = engine.check(ReadData::Percent(100.0), &cancel).unwrap();
    assert!(!rep.ok, "100% subset must also notice");
}

#[test]
fn keys_and_open_modes() {
    let repo_dir = tempfile::tempdir().unwrap();
    // OpenExisting on nothing.
    assert!(matches!(
        open_with(repo_dir.path(), OpenMode::OpenExisting, Arc::new(NullSink)),
        Err(EngineError::RepositoryNotFound)
    ));
    // OpenOrInit creates; reopening works and keeps the repository.
    let engine = open(repo_dir.path());
    drop(engine);
    let engine = open_with(repo_dir.path(), OpenMode::OpenExisting, Arc::new(NullSink)).unwrap();
    assert_eq!(engine.compression_level().unwrap(), Some(3));
    drop(engine);

    // A wrong key is an error even in OpenOrInit mode, and never re-initialises.
    let other = RepoKey::from_bytes("a different key, certainly").unwrap();
    let err = Engine::open(
        &backends(repo_dir.path()),
        &other,
        &EngineOptions::default(),
        Arc::new(NullSink),
    )
    .unwrap_err();
    assert!(matches!(err, EngineError::WrongKey), "{err}");
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains("different key") && !shown.contains(KEY));
    open_with(repo_dir.path(), OpenMode::OpenExisting, Arc::new(NullSink)).unwrap();

    // Secrets never show up in Debug.
    let k = key();
    let dbg = format!("{k:?}");
    assert!(!dbg.contains("horse") && dbg.contains("redacted"));
    assert!(RepoKey::from_bytes(Vec::new()).is_err());
    assert!(RepoKey::from_bytes(vec![b'a'; 2000]).is_err());
    assert!(RepoKey::from_bytes(vec![0xff, 0xfe]).is_err());

    // Compression level is validated before anything is written.
    let fresh = tempfile::tempdir().unwrap();
    let o = EngineOptions {
        compression_level: 99,
        ..EngineOptions::default()
    };
    assert!(matches!(
        Engine::open(&backends(fresh.path()), &key(), &o, Arc::new(NullSink)),
        Err(EngineError::InvalidInput { .. })
    ));
    assert!(fs::read_dir(fresh.path()).unwrap().next().is_none());
}

#[test]
fn bad_requests_fail_cleanly() {
    let src = tempfile::tempdir().unwrap();
    let repo_dir = tempfile::tempdir().unwrap();
    put(src.path(), "f", b"x");
    let mut engine = open(repo_dir.path());
    let cancel = CancelToken::new();

    let mut rq = request(src.path());
    rq.tags = vec!["has space".into()];
    assert!(matches!(
        engine.backup(&rq, &cancel),
        Err(EngineError::InvalidInput { what: "tag", .. })
    ));
    rq.tags = vec!["a,b".into()];
    assert!(engine.backup(&rq, &cancel).is_err());
    rq.tags = (0..40).map(|i| format!("t{i}")).collect();
    assert!(engine.backup(&rq, &cancel).is_err());
    rq.tags = vec![];
    rq.host = String::new();
    assert!(engine.backup(&rq, &cancel).is_err());

    let mut rq = request(&src.path().join("f"));
    assert!(matches!(
        engine.backup(&rq, &cancel),
        Err(EngineError::InvalidInput { what: "source", .. })
    ));
    rq.source = src.path().join("missing");
    assert!(matches!(
        engine.backup(&rq, &cancel),
        Err(EngineError::Io { .. })
    ));

    // Nothing was written by the failures.
    assert!(engine.snapshots().unwrap().is_empty());

    // Restore of what does not exist.
    let dst = tempfile::tempdir().unwrap();
    assert!(matches!(
        engine.restore(
            &RestoreRequest::new(SnapshotSelector::Latest, dst.path()),
            &cancel
        ),
        Err(EngineError::SnapshotNotFound(_))
    ));
    let bogus = "0".repeat(64).parse().unwrap();
    assert!(matches!(
        engine.restore(
            &RestoreRequest::new(SnapshotSelector::Id(bogus), dst.path()),
            &cancel
        ),
        Err(EngineError::SnapshotNotFound(_))
    ));
    assert!(
        "../../etc"
            .parse::<hx_backup::engine::SnapshotId>()
            .is_err()
    );
    assert!("ABCDEF".parse::<hx_backup::engine::SnapshotId>().is_err());

    // Restore target that is a file.
    let file = src.path().join("f");
    engine.backup(&request(src.path()), &cancel).unwrap();
    assert!(
        engine
            .restore(
                &RestoreRequest::new(SnapshotSelector::Latest, &file),
                &cancel
            )
            .is_err()
    );
}

#[test]
fn cancellation_stops_between_steps() {
    let src = tempfile::tempdir().unwrap();
    let repo_dir = tempfile::tempdir().unwrap();
    make_tree(src.path());
    let mut engine = open(repo_dir.path());
    let cancel = CancelToken::new();
    cancel.cancel();
    assert!(matches!(
        engine.backup(&request(src.path()), &cancel),
        Err(EngineError::Cancelled)
    ));
    assert!(engine.snapshots().unwrap().is_empty());

    // A fresh token works on the same engine.
    let ok = CancelToken::new();
    engine.backup(&request(src.path()), &ok).unwrap();
    let dst = tempfile::tempdir().unwrap();
    assert!(matches!(
        engine.restore(
            &RestoreRequest::new(SnapshotSelector::Latest, dst.path()),
            &cancel
        ),
        Err(EngineError::Cancelled)
    ));
    assert!(matches!(engine.prune(&cancel), Err(EngineError::Cancelled)));
    assert!(matches!(
        engine.check(ReadData::None, &cancel),
        Err(EngineError::Cancelled)
    ));
}

#[test]
fn protected_state_survives_a_hostile_exclude_list() {
    let src = tempfile::tempdir().unwrap();
    let repo_dir = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    put(
        src.path(),
        "home/alice/.claude/.credentials.json",
        b"secret",
    );
    put(src.path(), "home/alice/.codex/auth.json", b"secret2");
    put(src.path(), "home/alice/junk/x", b"junk");
    let mut engine = open(repo_dir.path());
    let mut rq = request(src.path());
    rq.rules = RuleSet::new(
        DockerMode::Complete,
        [
            "/home",
            "/home/*",
            "/home/*/.claude",
            "/home/*/.codex",
            "/home/alice/junk",
        ],
    )
    .unwrap();
    let out = engine.backup(&rq, &CancelToken::new()).unwrap();
    assert_eq!(out.resolved.excluded().len(), 1, "{}", out.resolved);
    engine
        .restore(
            &RestoreRequest::new(SnapshotSelector::Latest, dst.path()),
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(
        fs::read(dst.path().join("home/alice/.claude/.credentials.json")).unwrap(),
        b"secret"
    );
    assert_eq!(
        fs::read(dst.path().join("home/alice/.codex/auth.json")).unwrap(),
        b"secret2"
    );
    assert!(!dst.path().join("home/alice/junk").exists());
}

#[test]
fn mount_points_do_not_follow_symlinks_in_the_target() {
    // A restored tree whose `var` is a symlink must not make us create directories elsewhere.
    let src = tempfile::tempdir().unwrap();
    let repo_dir = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    put(src.path(), "f", b"x");
    symlink(elsewhere.path(), src.path().join("var")).unwrap();
    let mut engine = open(repo_dir.path());
    engine
        .backup(&request(src.path()), &CancelToken::new())
        .unwrap();
    engine
        .restore(
            &RestoreRequest::new(SnapshotSelector::Latest, dst.path()),
            &CancelToken::new(),
        )
        .unwrap();
    assert!(!elsewhere.path().join("tmp").exists());
    assert!(dst.path().join("tmp").is_dir());
    let (_, _) = tree_of(dst.path(), &skip_none);
    let _ = Resume::TrustMetadata;
}

#[test]
fn recovery_key_can_replace_the_original() {
    let repo_dir = tempfile::tempdir().unwrap();
    let a = key();
    let b = RepoKey::from_bytes("recovery key B, written on paper").unwrap();
    let opts = EngineOptions::default();
    let mk = || backends(repo_dir.path());

    let engine = Engine::open(&mk(), &a, &opts, Arc::new(NullSink)).unwrap();
    let id_b = engine.add_key(&b).unwrap();
    drop(engine);

    // B opens the repository; the key in use cannot be removed.
    let engine_b = Engine::open(&mk(), &b, &opts, Arc::new(NullSink)).unwrap();
    assert!(
        engine_b.remove_key(&id_b).is_err(),
        "the key in use must stay"
    );
    let id_a: hx_backup::engine::KeyId = {
        let mut ids: Vec<String> = fs::read_dir(repo_dir.path().join("keys"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n != id_b.as_str())
            .collect();
        assert_eq!(ids.len(), 1);
        ids.remove(0).parse().unwrap()
    };
    engine_b.remove_key(&id_a).unwrap();
    drop(engine_b);

    assert!(matches!(
        Engine::open(&mk(), &a, &opts, Arc::new(NullSink)),
        Err(EngineError::WrongKey)
    ));
    Engine::open(&mk(), &b, &opts, Arc::new(NullSink)).unwrap();
    assert!("zz".parse::<hx_backup::engine::KeyId>().is_err());
}

// --- write audit: what a backup does to the repository --------------------------------------

mod audit {
    use super::*;
    use bytes::Bytes;
    use rustic_core::{BytesList, FileType, Id, ReadBackend, RusticResult, WriteBackend};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Op {
        Write { tpe: FileType, replaced: bool },
        Remove { tpe: FileType },
    }

    pub struct Recorder {
        inner: Arc<dyn WriteBackend>,
        pub ops: Mutex<Vec<Op>>,
    }

    impl Recorder {
        pub fn new(inner: Arc<dyn WriteBackend>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                ops: Mutex::new(Vec::new()),
            })
        }
    }

    impl ReadBackend for Recorder {
        fn location(&self) -> String {
            self.inner.location()
        }
        fn list_with_size(&self, tpe: FileType) -> RusticResult<Vec<(Id, u32)>> {
            self.inner.list_with_size(tpe)
        }
        fn warmup_path(&self, tpe: FileType, id: &Id) -> String {
            self.inner.warmup_path(tpe, id)
        }
        fn read_full(&self, tpe: FileType, id: &Id) -> RusticResult<Bytes> {
            self.inner.read_full(tpe, id)
        }
        fn read_partial(
            &self,
            tpe: FileType,
            id: &Id,
            cacheable: bool,
            offset: u32,
            length: u32,
        ) -> RusticResult<Bytes> {
            self.inner.read_partial(tpe, id, cacheable, offset, length)
        }
    }

    impl WriteBackend for Recorder {
        fn create(&self) -> RusticResult<()> {
            self.inner.create()
        }
        fn write_bytes(
            &self,
            tpe: FileType,
            id: &Id,
            cacheable: bool,
            content: BytesList,
        ) -> RusticResult<()> {
            let replaced = self.inner.read_full(tpe, id).is_ok();
            self.ops.lock().unwrap().push(Op::Write { tpe, replaced });
            self.inner.write_bytes(tpe, id, cacheable, content)
        }
        fn remove(&self, tpe: FileType, id: &Id, cacheable: bool) -> RusticResult<()> {
            self.ops.lock().unwrap().push(Op::Remove { tpe });
            self.inner.remove(tpe, id, cacheable)
        }
    }
}

#[test]
fn backup_only_writes_new_pack_index_snapshot_and_removes_index() {
    use audit::{Op, Recorder};
    use rustic_core::FileType;

    let src = tempfile::tempdir().unwrap();
    let repo_dir = tempfile::tempdir().unwrap();
    make_tree(src.path());
    // Initialise through the plain backend, then run every backup through the recorder.
    drop(open(repo_dir.path()));
    let rec = Recorder::new(backends(repo_dir.path()).repository());
    let mut engine = Engine::open_with_backend(
        rec.clone(),
        &key(),
        &EngineOptions::default(),
        Arc::new(NullSink),
    )
    .unwrap();
    let cancel = CancelToken::new();
    engine.backup(&request(src.path()), &cancel).unwrap();
    put(src.path(), "etc/hostname", b"changed\n");
    engine.backup(&request(src.path()), &cancel).unwrap();

    // An interrupted run: packs on disk, index and snapshots gone. The next backup repairs the
    // index (step 0) and must stay within the allowed operations too.
    for sub in ["index", "snapshots"] {
        for f in fs::read_dir(repo_dir.path().join(sub)).unwrap() {
            fs::remove_file(f.unwrap().path()).unwrap();
        }
    }
    engine.backup(&request(src.path()), &cancel).unwrap();

    let ops = rec.ops.lock().unwrap().clone();
    assert!(ops.iter().any(|o| matches!(
        o,
        Op::Write {
            tpe: FileType::Pack,
            ..
        }
    )));
    assert!(ops.iter().any(|o| matches!(
        o,
        Op::Write {
            tpe: FileType::Index,
            ..
        }
    )));
    assert!(ops.iter().any(|o| matches!(
        o,
        Op::Write {
            tpe: FileType::Snapshot,
            ..
        }
    )));
    for o in &ops {
        match o {
            Op::Write { tpe, replaced } => {
                assert!(
                    matches!(tpe, FileType::Pack | FileType::Index | FileType::Snapshot),
                    "unexpected write of {tpe:?}"
                );
                assert!(!replaced, "a backup replaced an existing {tpe:?}");
            }
            Op::Remove { tpe } => assert_eq!(*tpe, FileType::Index, "unexpected remove of {tpe:?}"),
        }
    }
}
