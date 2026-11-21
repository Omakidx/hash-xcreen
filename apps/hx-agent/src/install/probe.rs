//! Facts about the host that are not files: machine type, CPUs, free space, whether a port can be
//! bound, what a block device looks like, the clock for waiting. One trait, so preflight and the
//! stages are tested against a fake host.

use std::io::{self, Read, Seek, SeekFrom};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::Path;
use std::time::Duration;

/// What a read-only look at `--storage-device` found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockInfo {
    /// A block device.
    pub is_block: bool,
    /// Size in GiB.
    pub size_gib: u64,
    /// A whole disk (not a partition).
    pub whole_disk: bool,
    /// The device or one of its partitions is mounted.
    pub mounted: bool,
    /// A known filesystem, RAID, LVM or LUKS signature was found.
    pub signature: bool,
}

/// The host, as a trait.
pub trait Probe {
    /// `uname -m`.
    fn machine(&self) -> String;
    /// Usable CPUs.
    fn cpus(&self) -> u32;
    /// Free space in GiB on the filesystem holding `path`.
    fn free_gib(&self, path: &Path) -> io::Result<u64>;
    /// TCP and UDP `port` can both be bound.
    fn port_free(&self, port: u16) -> bool;
    /// A read-only look at a block device (`name` is the path under `/dev/`).
    fn block_device(&self, path: &str) -> io::Result<BlockInfo>;
    /// Waits.
    fn sleep(&self, d: Duration);
    /// Milliseconds from a fixed origin.
    fn mono_ms(&self) -> u64;
}

/// The real host.
#[derive(Debug, Default)]
pub struct SystemProbe;

fn origin() -> std::time::Instant {
    static O: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    *O.get_or_init(std::time::Instant::now)
}

fn can_bind(v6: bool, port: u16) -> bool {
    let addr = if v6 {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))
    };
    TcpListener::bind(addr).is_ok() && UdpSocket::bind(addr).is_ok()
}

impl Probe for SystemProbe {
    fn machine(&self) -> String {
        rustix::system::uname()
            .machine()
            .to_string_lossy()
            .into_owned()
    }

    fn cpus(&self) -> u32 {
        std::thread::available_parallelism()
            .map(|n| u32::try_from(n.get()).unwrap_or(u32::MAX))
            .unwrap_or(1)
    }

    fn free_gib(&self, path: &Path) -> io::Result<u64> {
        let st = rustix::fs::statvfs(path)?;
        Ok(st.f_bavail.saturating_mul(st.f_frsize) / (1024 * 1024 * 1024))
    }

    fn port_free(&self, port: u16) -> bool {
        // A dual-stack bind of `[::]` covers IPv4 too; a host without IPv6 uses `0.0.0.0`.
        can_bind(true, port) || can_bind(false, port)
    }

    fn block_device(&self, path: &str) -> io::Result<BlockInfo> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let meta = std::fs::metadata(path)?;
        let mut info = BlockInfo {
            is_block: meta.file_type().is_block_device(),
            ..BlockInfo::default()
        };
        if !info.is_block {
            return Ok(info);
        }
        let real = std::fs::canonicalize(path)?;
        let name = real
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let sys = Path::new("/sys/class/block").join(&name);
        let sectors: u64 = std::fs::read_to_string(sys.join("size"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(meta.size() / 512);
        info.size_gib = sectors.saturating_mul(512) / (1024 * 1024 * 1024);
        info.whole_disk = !sys.join("partition").exists();
        let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
        let dev = real.to_string_lossy().into_owned();
        info.mounted = mounts.lines().any(|l| {
            l.split_whitespace().next().is_some_and(|d| {
                d == dev
                    || (d.starts_with(&dev)
                        && d[dev.len()..]
                            .trim_start_matches('p')
                            .bytes()
                            .all(|b| b.is_ascii_digit())
                        && d.len() > dev.len())
            })
        });
        let mut f = std::fs::File::open(path)?;
        let mut head = vec![0u8; 132 * 1024];
        let n = f.read(&mut head).unwrap_or(0);
        head.truncate(n);
        info.signature = has_signature(&head);
        let _ = f.seek(SeekFrom::Start(0));
        Ok(info)
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }

    fn mono_ms(&self) -> u64 {
        u64::try_from(origin().elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Looks for the signatures of common filesystems and containers in the first 132 KiB.
pub fn has_signature(head: &[u8]) -> bool {
    let at = |off: usize, magic: &[u8]| head.get(off..off + magic.len()) == Some(magic);
    at(510, &[0x55, 0xaa])
        || at(512, b"EFI PART")
        || at(1080, &[0x53, 0xef])
        || at(65_600, b"_BHRfS_M")
        || at(0, b"LUKS\xba\xbe")
        || at(0, b"XFSB")
        || at(536, b"LVM2 001")
        || at(4086, b"SWAPSPACE2")
        || at(4096, &[0xfc, 0x4e, 0x2b, 0xa9])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_are_found_and_a_blank_disk_has_none() {
        let blank = vec![0u8; 132 * 1024];
        assert!(!has_signature(&blank));
        let mut mbr = blank.clone();
        mbr[510] = 0x55;
        mbr[511] = 0xaa;
        assert!(has_signature(&mbr));
        let mut gpt = blank.clone();
        gpt[512..520].copy_from_slice(b"EFI PART");
        assert!(has_signature(&gpt));
        let mut btrfs = blank.clone();
        btrfs[65_600..65_608].copy_from_slice(b"_BHRfS_M");
        assert!(has_signature(&btrfs));
        assert!(!has_signature(&[]));
    }

    #[test]
    fn the_real_probe_answers() {
        let p = SystemProbe;
        assert!(!p.machine().is_empty());
        assert!(p.cpus() >= 1);
        assert!(p.free_gib(Path::new("/tmp")).is_ok());
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        drop(l);
    }
}
