//! The release archive extractor of the root update daemon, run into a fresh temporary
//! directory. Input: `mode byte | bytes`: with an even mode the bytes are the `.tar.gz` itself,
//! with an odd mode they are a raw tar stream that the harness wraps in (stored) gzip, so the
//! fuzzer mutates tar headers directly instead of fighting the gzip checksum.
//!
//! Invariants: nothing is created outside the target directory, nothing is a link or a device,
//! no file is setuid or setgid, and the limits hold.
#![no_main]

use std::io::{Cursor, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

use flate2::{Compression, write::GzEncoder};
use hx_agent::privd::update::extract::{Limits, extract_tar_gz};
use libfuzzer_sys::fuzz_target;

fn walk(dir: &Path, depth: usize, files: &mut usize) {
    assert!(
        depth < 64,
        "extracted tree deeper than the extractor's own limit"
    );
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let entry = entry.expect("entry");
        let meta = std::fs::symlink_metadata(entry.path()).expect("metadata");
        let ft = meta.file_type();
        assert!(
            !ft.is_symlink(),
            "a symlink was created: {:?}",
            entry.path()
        );
        assert!(
            !(ft.is_block_device() || ft.is_char_device() || ft.is_fifo() || ft.is_socket()),
            "a special file was created: {:?}",
            entry.path()
        );
        assert_eq!(meta.mode() & 0o6000, 0, "setuid or setgid bits survived");
        if ft.is_dir() {
            walk(&entry.path(), depth + 1, files);
        } else {
            *files += 1;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, bytes)) = data.split_first() else {
        return;
    };
    let archive = if mode % 2 == 0 {
        bytes.to_vec()
    } else {
        let mut gz = GzEncoder::new(Vec::new(), Compression::none());
        gz.write_all(bytes).expect("in memory");
        gz.finish().expect("in memory")
    };
    // A parent that must stay empty except for `root`, so an escape is visible.
    let parent = tempfile::tempdir().expect("tempdir");
    let root = parent.path().join("root");
    std::fs::create_dir(&root).expect("create root");
    let dir = std::fs::File::open(&root).expect("open root");
    let limits = Limits {
        max_entries: 64,
        max_bytes: 1 << 20,
    };
    let result = extract_tar_gz(Cursor::new(archive), rustix_borrow(&dir), &limits, &|| {
        false
    });
    let names: Vec<_> = std::fs::read_dir(parent.path())
        .expect("read parent")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(
        names,
        ["root"],
        "something was created outside the target directory"
    );
    let mut files = 0;
    walk(&root, 0, &mut files);
    if let Ok(stats) = result {
        assert!(stats.entries <= limits.max_entries);
        assert!(stats.bytes <= limits.max_bytes);
        assert_eq!(files, stats.files);
    }
});

fn rustix_borrow(f: &std::fs::File) -> std::os::fd::BorrowedFd<'_> {
    std::os::fd::AsFd::as_fd(f)
}
