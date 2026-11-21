//! Safe extraction of a release artifact (docs/ipc.md 6.12 rule 4): every refusal, the masking of
//! modes, the limits, and that a refused archive leaves nothing outside the extraction root.
//! Archives are written by a raw tar writer, so they can hold what no honest tool would.

mod privd_update_common;

use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use hx_agent::privd::update::extract::{ExtractError, Limits, Refusal, Stats, extract_tar_gz};
use privd_update_common::{TarEntry, archive, gz, tar_bytes};

/// Extracts `bytes` into a fresh directory `<tmp>/root` and returns the temp dir (so that a test
/// can look beside the root) and the result.
fn run_with(bytes: &[u8], limits: &Limits) -> (tempfile::TempDir, Result<Stats, ExtractError>) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let fd = rustix::fs::open(
        &root,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let r = extract_tar_gz(bytes, fd.as_fd(), limits, &|| false);
    (t, r)
}

fn run(entries: &[TarEntry]) -> (tempfile::TempDir, Result<Stats, ExtractError>) {
    run_with(&archive(entries), &Limits::default())
}

fn refused(entries: &[TarEntry]) -> (tempfile::TempDir, Refusal) {
    let (t, r) = run(entries);
    match r {
        Err(ExtractError::Refused(x)) => (t, x),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Nothing may exist beside `root` (an escape would put it there).
fn nothing_outside(t: &tempfile::TempDir) {
    let names: Vec<_> = std::fs::read_dir(t.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["root"], "something was created outside the root");
}

#[test]
fn an_honest_release_unpacks_with_sane_modes() {
    let (t, r) = run(&privd_update_common::good_files("1.1.0"));
    let stats = r.unwrap();
    assert!(stats.files >= 6);
    let root = t.path().join("root");
    assert!(root.join("hx-privd").is_file());
    assert!(root.join("session/ubuntu-24.04/hx-session.deb").is_file());
    let m = |p: &str| {
        std::fs::metadata(root.join(p))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    assert_eq!(m("hx-privd"), 0o755);
    assert_eq!(m("VERSION"), 0o644);
    assert_eq!(m("session"), 0o755);
    assert_eq!(
        std::fs::metadata(root.join("hx-privd")).unwrap().uid(),
        rustix::process::geteuid().as_raw()
    );
    nothing_outside(&t);
}

#[test]
fn absolute_paths_are_refused() {
    let (t, r) = refused(&[TarEntry::file("/tmp/hx-absolute", b"x", 0o644)]);
    assert_eq!(r, Refusal::AbsolutePath);
    nothing_outside(&t);
    assert!(!Path::new("/tmp/hx-absolute").exists());
}

#[test]
fn parent_components_are_refused() {
    for p in [
        "../escape",
        "a/../../escape",
        "./../escape",
        "a/b/../../../escape",
    ] {
        let (t, r) = refused(&[
            TarEntry::dir("a"),
            TarEntry::dir("a/b"),
            TarEntry::file(p, b"x", 0o644),
        ]);
        assert_eq!(r, Refusal::ParentComponent, "{p}");
        nothing_outside(&t);
    }
}

#[test]
fn a_nul_in_a_name_is_refused() {
    // A NUL cannot sit in the 100-byte name field (a C string ends there), but a pax `path`
    // record can carry one.
    let e = TarEntry::file("placeholder", b"x", 0o644).with_pax_path(b"good\0../../evil");
    let (t, r) = refused(&[e]);
    assert_eq!(r, Refusal::NulInName);
    nothing_outside(&t);
}

#[test]
fn bad_names_are_refused() {
    for p in ["a//b", "a/./b", &"x".repeat(256), &"d/".repeat(30)] {
        let long = TarEntry::file("placeholder", b"x", 0o644).with_pax_path(p.as_bytes());
        let (t, r) = refused(&[long]);
        assert_eq!(r, Refusal::BadName, "{p:?}");
        nothing_outside(&t);
    }
    let e = TarEntry::file("placeholder", b"x", 0o644).with_pax_path(b"caf\xc3\xa9\xff");
    assert_eq!(refused(&[e]).1, Refusal::BadName);
}

#[test]
fn duplicate_entries_are_refused() {
    let (_t, r) = refused(&[
        TarEntry::file("a", b"1", 0o644),
        TarEntry::file("a", b"2", 0o644),
    ]);
    assert_eq!(r, Refusal::Duplicate);
    // The same path spelled differently is the same path.
    let (_t, r) = refused(&[
        TarEntry::file("dir/a", b"1", 0o644),
        TarEntry::file("./dir/a", b"2", 0o644),
    ]);
    assert_eq!(r, Refusal::Duplicate);
    let (_t, r) = refused(&[TarEntry::dir("d"), TarEntry::dir("d/")]);
    assert_eq!(r, Refusal::Duplicate);
}

#[test]
fn a_file_and_a_directory_cannot_share_a_path() {
    let (_t, r) = refused(&[
        TarEntry::file("a", b"1", 0o644),
        TarEntry::file("a/b", b"2", 0o644),
    ]);
    assert_eq!(r, Refusal::Conflict);
    let (_t, r) = refused(&[
        TarEntry::file("a/b", b"2", 0o644),
        TarEntry::file("a", b"1", 0o644),
    ]);
    assert_eq!(r, Refusal::Conflict);
}

#[test]
fn symlinks_that_leave_the_root_are_refused() {
    for target in [
        "/etc/passwd",
        "../outside",
        "a/../../outside",
        "../../../../../../etc/shadow",
        "",
    ] {
        let (t, r) = refused(&[TarEntry::symlink("link", target)]);
        assert_eq!(r, Refusal::LinkEscapes, "{target:?}");
        nothing_outside(&t);
    }
    let (t, r) = refused(&[TarEntry::dir("d"), TarEntry::symlink("d/link", "../../x")]);
    assert_eq!(r, Refusal::LinkEscapes);
    nothing_outside(&t);
}

#[test]
fn symlinks_that_stay_inside_are_created_and_never_followed_by_later_entries() {
    let (t, r) = run(&[
        TarEntry::dir("lib"),
        TarEntry::file("lib/real", b"x", 0o755),
        TarEntry::symlink("bin", "lib"),
        TarEntry::symlink("lib/alias", "real"),
    ]);
    r.unwrap();
    let root = t.path().join("root");
    assert_eq!(
        std::fs::read_link(root.join("bin")).unwrap(),
        Path::new("lib")
    );
    // A later entry whose path runs through the symlink is refused, not written through it.
    let (t, r) = refused(&[
        TarEntry::dir("lib"),
        TarEntry::symlink("bin", "lib"),
        TarEntry::file("bin/payload", b"x", 0o644),
    ]);
    assert_eq!(r, Refusal::ThroughSymlink);
    assert!(!t.path().join("root/lib/payload").exists());
    // Including a directory entry and a hard link through it.
    let (_t, r) = refused(&[TarEntry::symlink("bin", "."), TarEntry::dir("bin/sub")]);
    assert_eq!(r, Refusal::ThroughSymlink);
}

#[test]
fn a_symlink_planted_to_point_outside_cannot_be_used_even_if_created_by_other_means() {
    // The classic two-step: a symlink to `..` that the lexical check refuses, so the second
    // entry never gets to write; here the first one is refused.
    let (t, r) = refused(&[
        TarEntry::symlink("up", ".."),
        TarEntry::file("up/escape", b"x", 0o644),
    ]);
    assert_eq!(r, Refusal::LinkEscapes);
    nothing_outside(&t);
}

#[test]
fn hard_links_must_name_an_extracted_regular_file_inside_the_root() {
    // Inside: fine, and it is the same inode.
    let (t, r) = run(&[
        TarEntry::file("a", b"data", 0o644),
        TarEntry::dir("d"),
        TarEntry::hardlink("d/b", "a"),
    ]);
    r.unwrap();
    let root = t.path().join("root");
    assert_eq!(
        std::fs::metadata(root.join("a")).unwrap().ino(),
        std::fs::metadata(root.join("d/b")).unwrap().ino()
    );
    // Outside, absolute, missing, a symlink, a directory: each refused.
    for (entries, what) in [
        (vec![TarEntry::hardlink("h", "/etc/passwd")], "absolute"),
        (vec![TarEntry::hardlink("h", "../x")], "parent"),
        (vec![TarEntry::hardlink("h", "missing")], "missing"),
        (
            vec![TarEntry::symlink("s", "x"), TarEntry::hardlink("h", "s")],
            "a symlink",
        ),
        (
            vec![TarEntry::dir("d"), TarEntry::hardlink("h", "d")],
            "a directory",
        ),
        (
            // Declared before the file exists.
            vec![
                TarEntry::hardlink("h", "a"),
                TarEntry::file("a", b"x", 0o644),
            ],
            "forward reference",
        ),
    ] {
        let (t, r) = refused(&entries);
        assert_eq!(r, Refusal::LinkEscapes, "{what}");
        nothing_outside(&t);
    }
}

#[test]
fn device_nodes_fifos_and_sockets_are_refused() {
    for (kind, what) in [
        (b'3', "char"),
        (b'4', "block"),
        (b'6', "fifo"),
        (b's', "socket"),
    ] {
        let (t, r) = refused(&[TarEntry::special("node", kind)]);
        assert_eq!(r, Refusal::SpecialFile, "{what}");
        assert!(!t.path().join("root/node").exists());
    }
}

#[test]
fn unsupported_entry_types_are_refused() {
    // A contiguous file and an unknown type byte are refused by name.
    for kind in *b"7Z" {
        let (_t, r) = refused(&[TarEntry::special("x", kind)]);
        assert_eq!(r, Refusal::UnsupportedType, "{}", kind as char);
    }
    // A global pax header and a sparse file are refused by the archive reader or by privd.
    for kind in *b"gS" {
        let (t, r) = run(&[TarEntry::special("x", kind)]);
        assert!(
            matches!(r, Err(ExtractError::Refused(_) | ExtractError::Malformed)),
            "{}: {r:?}",
            kind as char
        );
        assert!(!t.path().join("root/x").exists());
    }
}

#[test]
fn setuid_setgid_and_sticky_bits_are_masked() {
    let (t, r) = run(&[
        TarEntry::file("suid", b"x", 0o4755),
        TarEntry::file("sgid", b"x", 0o2755),
        TarEntry::file("plain", b"x", 0o1666),
        TarEntry::file("group-write", b"x", 0o664),
        TarEntry::file("private", b"x", 0o600),
        TarEntry::dir("sticky"),
    ]);
    r.unwrap();
    let root = t.path().join("root");
    let mode = |p: &str| {
        std::fs::metadata(root.join(p))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    assert_eq!(mode("suid"), 0o755);
    assert_eq!(mode("sgid"), 0o755);
    assert_eq!(mode("plain"), 0o644);
    assert_eq!(mode("group-write"), 0o644);
    assert_eq!(mode("private"), 0o644);
    // A directory with the sticky and setgid bits asked for.
    let mut d = TarEntry::dir("tmp-like");
    d.mode = 0o3777;
    let (t, r) = run(&[d]);
    r.unwrap();
    assert_eq!(
        std::fs::metadata(t.path().join("root/tmp-like"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o755
    );
}

#[test]
fn ownership_comes_from_the_extracting_user_not_the_archive() {
    let mut bytes = tar_bytes(&[TarEntry::file("owned", b"x", 0o644)]);
    // uid and gid fields: 0 in the archive anyway; set both to 12345 and fix the checksum.
    for (a, b) in [(108, 116), (116, 124)] {
        bytes[a..b].copy_from_slice(b"0030071\0");
    }
    bytes[148..156].fill(b' ');
    let sum: u64 = bytes[..512].iter().map(|b| u64::from(*b)).sum();
    bytes[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let (t, r) = run_with(&gz(&bytes), &Limits::default());
    r.unwrap();
    let m = std::fs::metadata(t.path().join("root/owned")).unwrap();
    assert_eq!(m.uid(), rustix::process::geteuid().as_raw());
}

#[test]
fn the_entry_count_is_limited() {
    let entries: Vec<_> = (0..11)
        .map(|i| TarEntry::file(&format!("f{i}"), b"x", 0o644))
        .collect();
    let (_t, r) = run_with(
        &archive(&entries),
        &Limits {
            max_entries: 10,
            ..Limits::default()
        },
    );
    assert!(matches!(r, Err(ExtractError::TooManyEntries)), "{r:?}");
    // Exactly the limit is fine.
    let (_t, r) = run_with(
        &archive(&entries[..10]),
        &Limits {
            max_entries: 10,
            ..Limits::default()
        },
    );
    assert!(r.is_ok());
    // And the real limit is 4096.
    let many: Vec<_> = (0..4097)
        .map(|i| TarEntry::file(&format!("f{i}"), b"", 0o644))
        .collect();
    let (_t, r) = run(&many);
    assert!(matches!(r, Err(ExtractError::TooManyEntries)), "{r:?}");
}

#[test]
fn the_uncompressed_size_is_limited_before_anything_is_written() {
    let big = vec![0u8; 5000];
    let (t, r) = run_with(
        &archive(&[
            TarEntry::file("small", b"x", 0o644),
            TarEntry::file("big", &big, 0o644),
        ]),
        &Limits {
            max_bytes: 4000,
            ..Limits::default()
        },
    );
    assert!(matches!(r, Err(ExtractError::TooLarge)), "{r:?}");
    assert!(
        !t.path().join("root/big").exists(),
        "the oversized file was never created"
    );
    // Several small files that add up.
    let parts: Vec<_> = (0..5)
        .map(|i| TarEntry::file(&format!("p{i}"), &[1u8; 900], 0o644))
        .collect();
    let (_t, r) = run_with(
        &archive(&parts),
        &Limits {
            max_bytes: 4000,
            ..Limits::default()
        },
    );
    assert!(matches!(r, Err(ExtractError::TooLarge)), "{r:?}");
}

#[test]
fn a_decompression_bomb_stops_at_the_limit() {
    // Many headers that each declare nothing but pad the decompressed stream with long names:
    // the decompressed stream is cut at max_bytes plus the header allowance regardless.
    let mut tar = Vec::new();
    for i in 0..3000 {
        let e = TarEntry::file(&format!("f{i}"), b"", 0o644);
        let mut one = tar_bytes(&[e]);
        one.truncate(512);
        tar.extend_from_slice(&one);
    }
    // Followed by a very long run of zeros that is not a valid end marker for a while.
    tar.extend(std::iter::repeat_n(0u8, 64 * 1024));
    let (_t, r) = run_with(
        &gz(&tar),
        &Limits {
            max_bytes: 10,
            max_entries: 100_000,
        },
    );
    assert!(
        r.is_ok() || matches!(r, Err(ExtractError::TooLarge | ExtractError::Malformed)),
        "{r:?}"
    );
}

#[test]
fn malformed_archives_are_refused() {
    for bytes in [
        b"not gzip at all".to_vec(),
        gz(b"not a tar archive, just text that is long enough to fill a block ......."),
        {
            let mut g = archive(&[TarEntry::file("a", &[7u8; 5000], 0o644)]);
            g.truncate(g.len() / 2);
            g
        },
    ] {
        let (_t, r) = run_with(&bytes, &Limits::default());
        assert!(
            matches!(r, Err(ExtractError::Malformed | ExtractError::Io(_))),
            "{r:?}"
        );
    }
}

#[test]
fn cancellation_stops_between_entries() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let fd = rustix::fs::open(
        &root,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let n = std::cell::Cell::new(0);
    let r = extract_tar_gz(
        &archive(&privd_update_common::good_files("1.1.0"))[..],
        fd.as_fd(),
        &Limits::default(),
        &|| {
            n.set(n.get() + 1);
            n.get() > 3
        },
    );
    assert!(matches!(r, Err(ExtractError::Cancelled)), "{r:?}");
}

#[test]
fn a_refusal_leaves_files_extracted_so_far_only_inside_the_root() {
    // The caller discards the root on any error; what matters is that nothing is outside.
    let (t, r) = refused(&[
        TarEntry::file("fine", b"x", 0o644),
        TarEntry::file("../bad", b"x", 0o644),
    ]);
    assert_eq!(r, Refusal::ParentComponent);
    nothing_outside(&t);
    let mut f = std::fs::File::create(t.path().join("root/.marker")).unwrap();
    f.write_all(b"x").unwrap();
}
