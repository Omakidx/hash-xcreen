//! Real network impairment without privileges: two network namespaces joined by a veth pair,
//! `tc netem` on both ends.
//!
//! ```text
//! host netns                      (untouched)
//!   `unshare -rn` -> userns U + netns A   <- the orchestrator (server side), 10.77.0.1
//!                         |  veth hxs0 <-> hxc0   netem on the egress of BOTH ends
//!                    netns B (made with `unshare -n` inside U: same userns)  <- the client, 10.77.0.2
//! ```
//!
//! Root inside the user namespace holds `CAP_NET_ADMIN` over every namespace that user namespace
//! owns, so no host privilege and no host network object is involved: the namespaces die with
//! their last process. Each direction gets half of the profile's round trip, so `ping` measures
//! the whole of it. Everything here only shells out to `ip`, `tc`, `nsenter` and `ping`.
//!
//! The first thing a run does with the impairment applied is to *measure* it ([`Net::control`]):
//! an unimpaired ping baseline, then ping RTT, ping loss, jitter, and for rate-limited profiles
//! the UDP throughput that gets through. A profile whose control does not show the impairment
//! fails the run, so a netem that silently does nothing (the S2 finding on the Incus proxy
//! device) cannot pass for a result.
#![allow(dead_code)]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub const SERVER_IP: &str = "10.77.0.1";
pub const CLIENT_IP: &str = "10.77.0.2";
const DEV_S: &str = "hxs0";
const DEV_C: &str = "hxc0";

/// One network condition. `rtt_ms` is the whole round trip; each direction gets half of the
/// delay, of the jitter and, for loss, the full percentage (so a round trip loses about twice).
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Profile {
    pub name: &'static str,
    pub rtt_ms: u32,
    /// Jitter of the one-way delay, in milliseconds, per direction (uniform, +/-).
    pub jitter_ms: u32,
    /// Random loss per direction, percent.
    pub loss_pct: f64,
    /// Rate of each direction in Mbit/s; 0 is unlimited.
    pub rate_mbit: u32,
}

pub const LAN: Profile = Profile {
    name: "lan",
    rtt_ms: 1,
    jitter_ms: 0,
    loss_pct: 0.0,
    rate_mbit: 0,
};
pub const BROADBAND: Profile = Profile {
    name: "broadband",
    rtt_ms: 20,
    jitter_ms: 0,
    loss_pct: 0.0,
    rate_mbit: 50,
};
pub const LOSSY: Profile = Profile {
    name: "lossy",
    rtt_ms: 40,
    jitter_ms: 0,
    loss_pct: 1.5,
    rate_mbit: 0,
};
pub const MOBILE: Profile = Profile {
    name: "mobile",
    rtt_ms: 80,
    jitter_ms: 10,
    loss_pct: 0.0,
    rate_mbit: 10,
};
pub const PROFILES: [Profile; 4] = [LAN, BROADBAND, LOSSY, MOBILE];

pub fn profile_named(name: &str) -> Option<Profile> {
    PROFILES.iter().copied().find(|p| p.name == name)
}

impl Profile {
    /// The `tc` arguments after `netem`, for one direction.
    pub fn netem_args(&self) -> Vec<String> {
        let mut a = vec!["delay".to_string()];
        // Microseconds keep 1 ms of RTT (500 us a way) exact.
        let one_way_us = u64::from(self.rtt_ms) * 500;
        a.push(format!("{one_way_us}us"));
        if self.jitter_ms > 0 {
            a.push(format!("{}ms", self.jitter_ms));
        }
        if self.loss_pct > 0.0 {
            a.push("loss".into());
            a.push(format!("{}%", self.loss_pct));
        }
        if self.rate_mbit > 0 {
            a.push("rate".into());
            a.push(format!("{}mbit", self.rate_mbit));
            // A router-sized queue, not the 1000-packet default: 150 packets at 10 Mbit/s is
            // about 180 ms of buffer.
            a.push("limit".into());
            a.push("150".into());
        }
        a
    }
}

/// What the control measured.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Control {
    /// RTT of the unimpaired veth (min/avg/max, ms) and its loss.
    pub baseline_rtt_avg_ms: f64,
    pub baseline_loss_pct: f64,
    /// With netem applied.
    pub rtt_min_ms: f64,
    pub rtt_avg_ms: f64,
    pub rtt_max_ms: f64,
    pub rtt_mdev_ms: f64,
    pub ping_sent: u32,
    pub ping_received: u32,
    pub ping_loss_pct: f64,
    /// UDP bytes per second that crossed the shaped link (server to client), 0 when the
    /// profile has no rate.
    pub udp_mbit: f64,
    /// `tc -s qdisc show` of the server-side and of the client-side device after the control
    /// (the counters show the drops netem made; loss is applied on each end, so a drop in one
    /// direction shows only on that direction's sender).
    pub tc_after: String,
    pub tc_after_client: String,
    /// Drops counted by both qdiscs together.
    pub netem_dropped: u64,
    /// Drops counted by the server-side and by the client-side qdisc alone.
    pub netem_dropped_server: u64,
    pub netem_dropped_client: u64,
    /// Human-readable verdict lines.
    pub notes: Vec<String>,
}

pub struct Net {
    holder: Child,
    pub client_pid: u32,
}

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{cmd} {}: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn netns_inode(pid: &str) -> Option<std::ffi::OsString> {
    std::fs::read_link(format!("/proc/{pid}/ns/net"))
        .ok()
        .map(Into::into)
}

impl Net {
    /// Run in the orchestrator, inside `unshare -rn`. Creates the client namespace and the veth.
    pub fn create() -> Result<Net, String> {
        run("ip", &["link", "set", "lo", "up"])?;
        let holder = Command::new("unshare")
            .args(["-n", "sleep", "100000"])
            .stdin(Stdio::null())
            .spawn()
            .map_err(|e| format!("unshare -n: {e}"))?;
        let pid = holder.id();
        let mine = netns_inode("self");
        let mut up = false;
        for _ in 0..200 {
            let theirs = netns_inode(&pid.to_string());
            if theirs.is_some() && theirs != mine {
                up = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let net = Net {
            holder,
            client_pid: pid,
        };
        if !up {
            return Err("the client network namespace did not appear".into());
        }
        let p = pid.to_string();
        run(
            "ip",
            &[
                "link", "add", DEV_S, "type", "veth", "peer", "name", DEV_C, "netns", &p,
            ],
        )?;
        run(
            "ip",
            &["addr", "add", &format!("{SERVER_IP}/24"), "dev", DEV_S],
        )?;
        run("ip", &["link", "set", DEV_S, "up"])?;
        net.in_client("ip", &["link", "set", "lo", "up"])?;
        net.in_client(
            "ip",
            &["addr", "add", &format!("{CLIENT_IP}/24"), "dev", DEV_C],
        )?;
        net.in_client("ip", &["link", "set", DEV_C, "up"])?;
        Ok(net)
    }

    /// Runs a command inside the client namespace.
    pub fn in_client(&self, cmd: &str, args: &[&str]) -> Result<String, String> {
        let p = self.client_pid.to_string();
        let mut a = vec!["-t", &p, "-n", "--", cmd];
        a.extend_from_slice(args);
        run("nsenter", &a)
    }

    /// A `Command` that runs `program` inside the client namespace (same user namespace, so
    /// `nsenter -n` is enough).
    pub fn client_command(&self, program: &std::path::Path) -> Command {
        let mut c = Command::new("nsenter");
        c.args(["-t", &self.client_pid.to_string(), "-n", "--"])
            .arg(program);
        c
    }

    pub fn clear(&self) {
        let _ = run("tc", &["qdisc", "del", "dev", DEV_S, "root"]);
        let _ = self.in_client("tc", &["qdisc", "del", "dev", DEV_C, "root"]);
    }

    /// Applies `p` to both directions (replacing what was there).
    pub fn apply(&self, p: &Profile) -> Result<(), String> {
        self.clear();
        let args = p.netem_args();
        let mut a: Vec<&str> = vec!["qdisc", "add", "dev", DEV_S, "root", "netem"];
        a.extend(args.iter().map(String::as_str));
        run("tc", &a)?;
        let mut b: Vec<&str> = vec!["qdisc", "add", "dev", DEV_C, "root", "netem"];
        b.extend(args.iter().map(String::as_str));
        self.in_client("tc", &b)?;
        Ok(())
    }

    /// `tc -s qdisc show dev hxs0`.
    pub fn tc_server(&self) -> String {
        run("tc", &["-s", "qdisc", "show", "dev", DEV_S]).unwrap_or_default()
    }

    /// `tc -s qdisc show dev hxc0`, read in the client namespace.
    pub fn tc_client(&self) -> String {
        self.in_client("tc", &["-s", "qdisc", "show", "dev", DEV_C])
            .unwrap_or_default()
    }

    /// Fills the drop counters of `c` from both ends' qdiscs.
    pub fn read_drops(&self, c: &mut Control) {
        c.tc_after = self.tc_server();
        c.tc_after_client = self.tc_client();
        c.netem_dropped_server = parse_dropped(&c.tc_after);
        c.netem_dropped_client = parse_dropped(&c.tc_after_client);
        c.netem_dropped = c.netem_dropped_server + c.netem_dropped_client;
    }

    /// The client interface's (rx, tx) byte counters, read in the client namespace.
    pub fn client_bytes(&self) -> Option<(u64, u64)> {
        let out = self.in_client("cat", &["/proc/net/dev"]).ok()?;
        parse_dev(&out, DEV_C)
    }

    /// Measures what the profile does to the link. Does not judge; see [`judge_control`].
    pub fn control(&self, p: &Profile) -> Result<Control, String> {
        let mut c = Control::default();
        // Baseline first: the same veth with nothing applied.
        self.clear();
        let base = ping(30, 0.02)?;
        c.baseline_rtt_avg_ms = base.avg;
        c.baseline_loss_pct = base.loss;
        self.apply(p)?;
        // Enough probes that a 1.5 % per-direction loss shows with certainty (P(no loss in
        // 400 round trips) < 1e-5), few enough that a 80 ms profile stays under 10 s.
        let count = if p.loss_pct > 0.0 { 400 } else { 60 };
        let interval = 0.02;
        let mut pg = ping(count, interval)?;
        // A lossy profile that shows no loss at all in 400 probes is practically impossible
        // (1.5 % per direction); probe once more before judging, and judge the total.
        if p.loss_pct > 0.0 && pg.received == pg.sent {
            let again = ping(count, interval)?;
            pg.sent += again.sent;
            pg.received += again.received;
            pg.loss = 100.0 * f64::from(pg.sent - pg.received) / f64::from(pg.sent.max(1));
            pg.avg = (pg.avg + again.avg) / 2.0;
            pg.min = pg.min.min(again.min);
            pg.max = pg.max.max(again.max);
        }
        c.rtt_min_ms = pg.min;
        c.rtt_avg_ms = pg.avg;
        c.rtt_max_ms = pg.max;
        c.rtt_mdev_ms = pg.mdev;
        c.ping_sent = pg.sent;
        c.ping_received = pg.received;
        c.ping_loss_pct = pg.loss;
        if p.rate_mbit > 0 {
            c.udp_mbit = self.udp_rate()?;
        }
        self.read_drops(&mut c);
        c.notes = judge_control(p, &c);
        Ok(c)
    }

    /// UDP flood from the server to the client for one second, counted at the client interface:
    /// the rate netem lets through, in Mbit/s.
    fn udp_rate(&self) -> Result<f64, String> {
        let sock = std::net::UdpSocket::bind((SERVER_IP, 0)).map_err(|e| e.to_string())?;
        sock.set_nonblocking(true).ok();
        let payload = [0u8; 1200];
        let to = format!("{CLIENT_IP}:9");
        let before = self.client_bytes().ok_or("no client counters")?.0;
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_millis(1500) {
            let _ = sock.send_to(&payload, &to);
        }
        // Let the queue drain.
        std::thread::sleep(Duration::from_millis(500));
        let after = self.client_bytes().ok_or("no client counters")?.0;
        // Delivered over the send window plus the drain: the queue holds a little more than
        // `rate x window`, so count the window only against the sent period, and add the
        // drain to the denominator for a conservative figure.
        let secs = 1.5 + 0.5;
        Ok((after - before) as f64 * 8.0 / 1e6 / secs)
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        let _ = self.holder.kill();
        let _ = self.holder.wait();
    }
}

#[derive(Debug, Default)]
pub struct Ping {
    pub sent: u32,
    pub received: u32,
    pub loss: f64,
    pub min: f64,
    pub avg: f64,
    pub max: f64,
    pub mdev: f64,
}

/// `ping` from the server to the client address.
pub fn ping(count: u32, interval_s: f64) -> Result<Ping, String> {
    // Not `run`: ping exits 1 when packets were lost, which is a result here.
    let out = Command::new("ping")
        .args([
            "-n",
            "-q",
            "-c",
            &count.to_string(),
            "-i",
            &interval_s.to_string(),
            "-W",
            "3",
            CLIENT_IP,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("ping: {e}"))?;
    parse_ping(&String::from_utf8_lossy(&out.stdout)).ok_or_else(|| {
        format!(
            "ping gave no summary: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

pub fn parse_ping(text: &str) -> Option<Ping> {
    let mut p = Ping::default();
    let stats = text.lines().find(|l| l.contains("packets transmitted"))?;
    // "60 packets transmitted, 60 received, 0% packet loss, time 1180ms"
    let mut it = stats.split(',').map(str::trim);
    p.sent = it.next()?.split_whitespace().next()?.parse().ok()?;
    p.received = it.next()?.split_whitespace().next()?.parse().ok()?;
    p.loss = it.next()?.split('%').next()?.trim().parse::<f64>().ok()?;
    if let Some(rtt) = text.lines().find(|l| l.contains("min/avg/max")) {
        // "rtt min/avg/max/mdev = 0.040/0.060/0.100/0.020 ms"
        // The line may end ", pipe 4" when replies overlap: take the first word after "=".
        let nums: Vec<f64> = rtt
            .split('=')
            .nth(1)?
            .split_whitespace()
            .next()?
            .split('/')
            .filter_map(|v| v.trim().parse().ok())
            .collect();
        if nums.len() >= 4 {
            p.min = nums[0];
            p.avg = nums[1];
            p.max = nums[2];
            p.mdev = nums[3];
        }
    }
    Some(p)
}

/// (rx_bytes, tx_bytes) of `dev` in the text of `/proc/net/dev`.
pub fn parse_dev(text: &str, dev: &str) -> Option<(u64, u64)> {
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with(&format!("{dev}:")))?;
    let f: Vec<&str> = line.split(':').nth(1)?.split_whitespace().collect();
    Some((f.first()?.parse().ok()?, f.get(8)?.parse().ok()?))
}

/// The `dropped N` of the first netem qdisc in `tc -s qdisc` output.
pub fn parse_dropped(tc: &str) -> u64 {
    tc.split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|w| w[0] == "(dropped")
        .and_then(|w| w[1].trim_end_matches(',').parse().ok())
        .unwrap_or(0)
}

/// What the control must show for `p`; an empty list is a pass. Returned lines starting with
/// `FAIL` are failures, the rest evidence.
pub fn judge_control(p: &Profile, c: &Control) -> Vec<String> {
    let mut v = Vec::new();
    let rtt = f64::from(p.rtt_ms);
    v.push(format!(
        "baseline (no netem) rtt avg {:.3} ms, loss {:.1}%; with netem rtt min/avg/max/mdev {:.2}/{:.2}/{:.2}/{:.2} ms, {}/{} answered ({:.1}% loss), netem dropped {} packets{}",
        c.baseline_rtt_avg_ms,
        c.baseline_loss_pct,
        c.rtt_min_ms,
        c.rtt_avg_ms,
        c.rtt_max_ms,
        c.rtt_mdev_ms,
        c.ping_received,
        c.ping_sent,
        c.ping_loss_pct,
        c.netem_dropped,
        if p.rate_mbit > 0 {
            format!(", UDP through {:.2} Mbit/s", c.udp_mbit)
        } else {
            String::new()
        }
    ));
    if c.baseline_loss_pct > 0.0 || c.baseline_rtt_avg_ms > 1.0 {
        v.push(format!(
            "FAIL the unimpaired veth is not clean (rtt {:.3} ms, loss {:.1}%)",
            c.baseline_rtt_avg_ms, c.baseline_loss_pct
        ));
    }
    // The delay must be there: the fastest reply at least 85 % of the RTT less the jitter (a
    // jittered way can be short), and (queueing and a loaded host add some) the average at
    // most 1.3x + 2 ms.
    let floor = (rtt - 2.0 * f64::from(p.jitter_ms)).max(0.0) * 0.85;
    if c.rtt_min_ms < floor || c.rtt_avg_ms > rtt * 1.3 + 2.0 {
        v.push(format!(
            "FAIL ping RTT min {:.2} / avg {:.2} ms is not the profile's {rtt} ms",
            c.rtt_min_ms, c.rtt_avg_ms
        ));
    }
    if p.loss_pct > 0.0 {
        // Loss is applied on each end: count the drops of both qdiscs and the lost pings. A
        // profile that really applies no loss still shows none of the three.
        if c.netem_dropped == 0 && c.ping_received == c.ping_sent {
            v.push(format!(
                "FAIL the lossy profile lost nothing (server qdisc dropped {}, client qdisc dropped {}, {} of {} pings lost)",
                c.netem_dropped_server,
                c.netem_dropped_client,
                c.ping_sent - c.ping_received,
                c.ping_sent
            ));
        }
        if c.ping_loss_pct > 12.0 {
            v.push(format!(
                "FAIL the lossy profile lost {:.1}% of the pings",
                c.ping_loss_pct
            ));
        }
    } else if c.ping_loss_pct > 0.0 {
        v.push(format!(
            "FAIL {:.1}% ping loss on a profile without loss",
            c.ping_loss_pct
        ));
    }
    if p.jitter_ms > 0 && c.rtt_mdev_ms < f64::from(p.jitter_ms) * 0.3 {
        v.push(format!(
            "FAIL no jitter (mdev {:.2} ms for +/-{} ms per direction)",
            c.rtt_mdev_ms, p.jitter_ms
        ));
    }
    if p.rate_mbit > 0 {
        let r = f64::from(p.rate_mbit);
        // Delivered over a 2 s window that includes the drain: between 40 % (drops are
        // heavy under a flood) and 130 % of the rate.
        if c.udp_mbit < r * 0.4 || c.udp_mbit > r * 1.3 {
            v.push(format!(
                "FAIL UDP flood delivered {:.2} Mbit/s through a {r} Mbit/s limit",
                c.udp_mbit
            ));
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_summary_is_parsed() {
        let t = "PING 10.77.0.2 (10.77.0.2) 56(84) bytes of data.\n\n--- 10.77.0.2 ping statistics ---\n400 packets transmitted, 390 received, 2.5% packet loss, time 20399ms\nrtt min/avg/max/mdev = 40.101/40.456/45.899/0.912 ms\n";
        let p = parse_ping(t).unwrap();
        assert_eq!((p.sent, p.received), (400, 390));
        assert!((p.loss - 2.5).abs() < 1e-9);
        assert!((p.avg - 40.456).abs() < 1e-9 && (p.mdev - 0.912).abs() < 1e-9);
        // Everything lost: no rtt line, still a result.
        let t = "60 packets transmitted, 60 received, 0% packet loss, time 3000ms\nrtt min/avg/max/mdev = 80.081/80.333/81.046/0.173 ms, pipe 2\n";
        assert!((parse_ping(t).unwrap().avg - 80.333).abs() < 1e-9);
        let t = "5 packets transmitted, 0 received, 100% packet loss, time 4090ms\n";
        assert_eq!(parse_ping(t).unwrap().loss, 100.0);
    }

    #[test]
    fn proc_net_dev_counters_are_parsed() {
        let t = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n hxc0:    1234      10    0    0    0     0          0         0     5678      12    0    0    0     0       0          0\n";
        assert_eq!(parse_dev(t, "hxc0"), Some((1234, 5678)));
        assert_eq!(parse_dev(t, "nope"), None);
    }

    #[test]
    fn netem_dropped_is_read_from_tc() {
        let t = "qdisc netem 8001: root refcnt 2 limit 1000 delay 20ms loss 1.5%\n Sent 100 bytes 2 pkt (dropped 7, overlimits 0 requeues 0)\n";
        assert_eq!(parse_dropped(t), 7);
        assert_eq!(parse_dropped("nothing"), 0);
    }

    #[test]
    fn a_netem_that_does_nothing_fails_the_control() {
        // The S2 failure mode: the profile is requested but the link is unimpaired.
        let c = Control {
            baseline_rtt_avg_ms: 0.05,
            rtt_min_ms: 0.04,
            rtt_avg_ms: 0.06,
            ping_sent: 60,
            ping_received: 60,
            ..Control::default()
        };
        assert!(
            judge_control(&BROADBAND, &c)
                .iter()
                .any(|l| l.starts_with("FAIL"))
        );
        let c = Control {
            rtt_min_ms: 19.9,
            rtt_avg_ms: 20.2,
            udp_mbit: 48.0,
            ping_sent: 60,
            ping_received: 60,
            baseline_rtt_avg_ms: 0.05,
            ..Control::default()
        };
        assert!(
            !judge_control(&BROADBAND, &c)
                .iter()
                .any(|l| l.starts_with("FAIL")),
            "{:?}",
            judge_control(&BROADBAND, &c)
        );
    }

    #[test]
    fn the_lossy_control_counts_the_drops_of_both_ends() {
        let base = Control {
            baseline_rtt_avg_ms: 0.05,
            rtt_min_ms: 40.0,
            rtt_avg_ms: 40.3,
            ping_sent: 400,
            ping_received: 400,
            ..Control::default()
        };
        let fails = |c: &Control| {
            judge_control(&LOSSY, c)
                .iter()
                .any(|l| l.contains("lost nothing"))
        };
        // CI failure: the pings lost 3 of 400 and the server's qdisc saw none (the drops were on
        // the client's qdisc).
        let c = Control {
            ping_received: 397,
            netem_dropped_client: 3,
            netem_dropped: 3,
            ..base.clone()
        };
        assert!(!fails(&c), "{:?}", judge_control(&LOSSY, &c));
        // Drops on one qdisc alone are enough, with or without lost pings.
        let c = Control {
            netem_dropped_server: 2,
            netem_dropped: 2,
            ..base.clone()
        };
        assert!(!fails(&c));
        // A profile that applies no loss shows none of the three: still a failure, and it says
        // what it counted.
        assert!(fails(&base));
        assert!(
            judge_control(&LOSSY, &base)
                .iter()
                .any(|l| l.contains("server qdisc dropped 0"))
        );
    }

    #[test]
    fn profiles_split_the_rtt_over_both_directions() {
        assert_eq!(LAN.netem_args(), ["delay", "500us"]);
        assert_eq!(
            MOBILE.netem_args(),
            ["delay", "40000us", "10ms", "rate", "10mbit", "limit", "150"]
        );
        assert!(LOSSY.netem_args().contains(&"1.5%".to_string()));
    }
}
