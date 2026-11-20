//! Spike S2 shared code: clock, CPU accounting, wire format, tiny arg parser.
//! Throwaway spike code, not production.

use std::collections::HashMap;

/// CLOCK_MONOTONIC in nanoseconds. Container and host share the kernel, so values from
/// `s2-server` (in the container) and `s2-client` (on the host) are directly comparable.
pub fn now_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid pointer to a timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Total CPU time (user + system, all threads) consumed by this process, in nanoseconds.
pub fn process_cpu_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid pointer to a timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// CPU time used by the cgroup we run in (the whole container: Xorg, XFCE, apps, server), in microseconds.
pub fn cgroup_cpu_usec() -> Option<u64> {
    let s = std::fs::read_to_string("/sys/fs/cgroup/cpu.stat").ok()?;
    s.lines().find_map(|l| l.strip_prefix("usage_usec ")?.trim().parse().ok())
}

/// Minimal `--key value` / `--flag` argument parser.
pub struct Args(HashMap<String, String>);

impl Args {
    pub fn parse() -> Self {
        let mut m = HashMap::new();
        let v: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        while i < v.len() {
            if let Some(k) = v[i].strip_prefix("--") {
                if i + 1 < v.len() && !v[i + 1].starts_with("--") {
                    m.insert(k.to_string(), v[i + 1].clone());
                    i += 2;
                    continue;
                }
                m.insert(k.to_string(), "1".to_string());
            }
            i += 1;
        }
        Args(m)
    }
    pub fn get<T: std::str::FromStr>(&self, k: &str, default: T) -> T {
        self.0.get(k).and_then(|s| s.parse().ok()).unwrap_or(default)
    }
    pub fn get_str(&self, k: &str, default: &str) -> String {
        self.0.get(k).cloned().unwrap_or_else(|| default.to_string())
    }
}

/// Wire format. All integers little-endian.
pub mod wire {
    /// First byte of every unidirectional stream.
    pub const KIND_FRAME: u8 = 1;
    pub const KIND_CURSOR: u8 = 2;

    pub const CODEC_H264: u8 = 1;

    pub const FLAG_KEY: u8 = 1;
    /// Frame is the "fresh image" sent after stale frame streams were cancelled.
    pub const FLAG_RESYNC: u8 = 2;

    /// QUIC application error code used when the server cancels a stale frame stream.
    pub const RESET_STALE: u32 = 0x57A1E;

    /// Fixed header of one video frame stream (60 bytes). The six timestamps are spike
    /// instrumentation; a production header would carry only the capture timestamp.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct FrameHeader {
        pub codec: u8,
        pub flags: u8,
        pub frame_no: u32,
        pub len: u32,
        pub t_damage: u64,
        pub t_capture: u64,
        pub t_convert: u64,
        pub t_enc_start: u64,
        pub t_enc_end: u64,
        pub t_send: u64,
    }

    pub const HEADER_LEN: usize = 60;

    impl FrameHeader {
        pub fn encode(&self) -> [u8; HEADER_LEN] {
            let mut b = [0u8; HEADER_LEN];
            b[0] = KIND_FRAME;
            b[1] = self.codec;
            b[2] = self.flags;
            b[4..8].copy_from_slice(&self.frame_no.to_le_bytes());
            b[8..12].copy_from_slice(&self.len.to_le_bytes());
            for (i, t) in [self.t_damage, self.t_capture, self.t_convert, self.t_enc_start, self.t_enc_end, self.t_send]
                .iter()
                .enumerate()
            {
                b[12 + i * 8..20 + i * 8].copy_from_slice(&t.to_le_bytes());
            }
            b
        }
        /// Decode a header whose first byte (the kind) was already consumed separately is NOT supported:
        /// pass all 60 bytes.
        pub fn decode(b: &[u8; HEADER_LEN]) -> Option<Self> {
            if b[0] != KIND_FRAME {
                return None;
            }
            let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
            Some(Self {
                codec: b[1],
                flags: b[2],
                frame_no: u32::from_le_bytes(b[4..8].try_into().unwrap()),
                len: u32::from_le_bytes(b[8..12].try_into().unwrap()),
                t_damage: u64_at(12),
                t_capture: u64_at(20),
                t_convert: u64_at(28),
                t_enc_start: u64_at(36),
                t_enc_end: u64_at(44),
                t_send: u64_at(52),
            })
        }
    }

    /// Cursor channel message types (one long-lived unidirectional stream, kind byte first).
    pub const CUR_SHAPE: u8 = 1;
    pub const CUR_POS: u8 = 2;

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn header_roundtrip() {
            let h = FrameHeader {
                codec: CODEC_H264,
                flags: FLAG_KEY | FLAG_RESYNC,
                frame_no: 7,
                len: 1234,
                t_damage: 1,
                t_capture: 2,
                t_convert: 3,
                t_enc_start: 4,
                t_enc_end: 5,
                t_send: 6,
            };
            let d = FrameHeader::decode(&h.encode()).unwrap();
            assert_eq!((d.frame_no, d.len, d.flags, d.t_send), (7, 1234, 3, 6));
        }
        #[test]
        fn rejects_wrong_kind() {
            let mut b = FrameHeader::default().encode();
            b[0] = 9;
            assert!(FrameHeader::decode(&b).is_none());
        }
    }
}
