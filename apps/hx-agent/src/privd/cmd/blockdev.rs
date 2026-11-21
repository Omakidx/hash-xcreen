//! Verifying an Admin-supplied pool device (ipc.md 6.4, `pool_device`).
//!
//! `hx-provision` hands the whole device to Incus, so privd (as root) checks what the README
//! demands of the installer: a real block device, a whole disk (not a partition), not mounted and
//! with no mounted or in-use partition, not held by device-mapper, md or LVM, no filesystem or
//! RAID/LVM signature (`blkid -p`), and not the device that holds `/` (the mount check covers it,
//! since `/` is a mount).

use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hx_ipc::privd::pb::ErrorDetail;

use crate::privd::error::CmdError;
use crate::privd::runner::{CommandRunner, Program, Tool};

/// Where the kernel's view of block devices and mounts is read from (replaceable in tests).
#[derive(Debug, Clone)]
pub struct BlockEnv {
    /// `/sys/block`.
    pub sys_block: PathBuf,
    /// `/proc/self/mountinfo`.
    pub mountinfo: PathBuf,
}

impl BlockEnv {
    /// The real files.
    pub fn system() -> Self {
        Self {
            sys_block: "/sys/block".into(),
            mountinfo: "/proc/self/mountinfo".into(),
        }
    }
}

/// The partitions of a whole disk: sysfs entries `<disk>/<name>` that have a `partition` file.
pub fn partitions(sys_block: &Path, disk: &str) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(sys_block.join(disk)) else {
        return Vec::new();
    };
    let mut v: Vec<String> = rd
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name().to_string_lossy().starts_with(disk) && e.path().join("partition").exists()
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// `major:minor` of the disk and of each partition.
pub fn device_numbers(sys_block: &Path, disk: &str, parts: &[String]) -> Vec<String> {
    let read = |p: PathBuf| {
        std::fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_string())
    };
    let mut v: Vec<String> = read(sys_block.join(disk).join("dev")).into_iter().collect();
    for p in parts {
        v.extend(read(sys_block.join(disk).join(p).join("dev")));
    }
    v
}

/// Whether any mount in `mountinfo` is one of `devnums` (`major:minor`) or has a source named
/// `/dev/<name>` for one of `names`.
pub fn mount_conflict(mountinfo: &str, devnums: &[String], names: &[String]) -> bool {
    mountinfo.lines().any(|l| {
        let fields: Vec<&str> = l.split(' ').collect();
        let by_number = fields
            .get(2)
            .is_some_and(|mm| devnums.iter().any(|d| d == mm));
        let by_source = l
            .split_once(" - ")
            .and_then(|(_, rest)| rest.split(' ').nth(1))
            .is_some_and(|src| names.iter().any(|n| src == format!("/dev/{n}")));
        by_number || by_source
    })
}

/// Whether the disk or a partition is held by another device (device-mapper, md, LVM).
pub fn is_held(sys_block: &Path, disk: &str, parts: &[String]) -> bool {
    let nonempty = |p: PathBuf| {
        std::fs::read_dir(p)
            .map(|mut r| r.next().is_some())
            .unwrap_or(false)
    };
    nonempty(sys_block.join(disk).join("holders"))
        || parts
            .iter()
            .any(|p| nonempty(sys_block.join(disk).join(p).join("holders")))
}

/// Verifies `dev` and returns its canonical path for `PoolSource::Device`.
pub async fn verify_pool_device(
    dev: &str,
    env: &BlockEnv,
    runner: &dyn CommandRunner,
) -> Result<String, CmdError> {
    let invalid = |m: &str| CmdError::invalid(format!("setup_host.pool_device: {m}"));
    let in_use =
        |m: &str| CmdError::precondition(ErrorDetail::Pool, format!("setup_host.pool_device: {m}"));
    let canonical = std::fs::canonicalize(dev).map_err(|_| invalid("does not exist"))?;
    let meta = std::fs::metadata(&canonical).map_err(|_| invalid("cannot be read"))?;
    if !meta.file_type().is_block_device() {
        return Err(invalid("is not a block device"));
    }
    let name = canonical
        .strip_prefix("/dev")
        .ok()
        .and_then(|p| p.to_str())
        .filter(|n| !n.is_empty() && !n.contains('/'))
        .ok_or_else(|| invalid("must be directly under /dev"))?
        .to_string();
    if !env.sys_block.join(&name).is_dir() {
        return Err(invalid("is not a whole disk"));
    }
    let parts = partitions(&env.sys_block, &name);
    let mut names = vec![name.clone()];
    names.extend(parts.iter().cloned());
    let nums = device_numbers(&env.sys_block, &name, &parts);
    let mounts = std::fs::read_to_string(&env.mountinfo).map_err(CmdError::from)?;
    if mount_conflict(&mounts, &nums, &names) {
        return Err(in_use("it or one of its partitions is mounted"));
    }
    if is_held(&env.sys_block, &name, &parts) {
        return Err(in_use(
            "it is in use by another device (LVM, RAID or device-mapper)",
        ));
    }
    let path = canonical.to_string_lossy().into_owned();
    let out = runner
        .run(Program::new(Tool::Blkid, &["-p", &path]).with_timeout(Duration::from_secs(30)))
        .await
        .map_err(|_| CmdError::unavailable("cannot probe the device with blkid"))?;
    match out.code {
        // blkid -p exits 2 when it finds nothing.
        Some(2) => Ok(path),
        Some(0) => Err(in_use(
            "it carries a filesystem, RAID, LVM or partition signature",
        )),
        _ => Err(CmdError::unavailable("blkid could not probe the device")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = "\
24 29 0:22 / /sys rw,nosuid shared:7 - sysfs sysfs rw
29 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
40 29 8:17 / /data rw,relatime shared:9 - ext4 /dev/sdb1 rw
";

    #[test]
    fn mounts_are_found_by_number_or_by_source() {
        assert!(mount_conflict(MOUNTINFO, &["8:17".into()], &[]));
        assert!(mount_conflict(MOUNTINFO, &[], &["sdb1".into()]));
        // The disk that holds `/` is covered because `/` is a mount of its partition.
        assert!(mount_conflict(
            MOUNTINFO,
            &["259:2".into()],
            &["nvme0n1".into(), "nvme0n1p2".into()]
        ));
        assert!(!mount_conflict(
            MOUNTINFO,
            &["8:32".into()],
            &["sdc".into()]
        ));
        // A prefix is not a match.
        assert!(!mount_conflict(MOUNTINFO, &[], &["sdb".into()]));
    }

    #[test]
    fn sysfs_partitions_numbers_and_holders() {
        let d = tempfile::tempdir().unwrap();
        let disk = d.path().join("sdb");
        std::fs::create_dir_all(disk.join("sdb1/holders")).unwrap();
        std::fs::create_dir_all(disk.join("sdb2")).unwrap();
        std::fs::create_dir_all(disk.join("queue")).unwrap();
        std::fs::create_dir_all(disk.join("holders")).unwrap();
        std::fs::write(disk.join("dev"), "8:16\n").unwrap();
        for (p, n) in [("sdb1", "8:17\n"), ("sdb2", "8:18\n")] {
            std::fs::write(disk.join(p).join("partition"), "1\n").unwrap();
            std::fs::write(disk.join(p).join("dev"), n).unwrap();
        }
        let parts = partitions(d.path(), "sdb");
        assert_eq!(parts, ["sdb1", "sdb2"]);
        assert_eq!(
            device_numbers(d.path(), "sdb", &parts),
            ["8:16", "8:17", "8:18"]
        );
        assert!(!is_held(d.path(), "sdb", &parts));
        std::fs::write(disk.join("sdb1/holders/dm-0"), "").unwrap();
        assert!(is_held(d.path(), "sdb", &parts));
    }

    #[tokio::test]
    async fn a_regular_file_and_a_missing_path_are_not_pool_devices() {
        let env = BlockEnv::system();
        let runner = crate::privd::runner::SystemRunner;
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("file");
        std::fs::write(&f, b"x").unwrap();
        for p in [f.to_str().unwrap(), "/dev/does-not-exist", "/dev/null"] {
            let e = verify_pool_device(p, &env, &runner).await.unwrap_err();
            assert_eq!(e.code, hx_ipc::privd::pb::ErrorCode::InvalidArgument, "{p}");
        }
    }
}
