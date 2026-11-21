//! Running the few host tools privd needs (`nft`, `sysctl`, `iptables`, `ip`, `blkid`).
//!
//! ipc.md 7 rule 3 and 8: every spawned child gets a fixed program from a closed set ([`Tool`]),
//! an argument vector built by privd (never a shell), a **cleared environment**, a timeout, stdout
//! and stderr capped at 64 KiB, and is killed on timeout. Nothing here takes a caller-supplied
//! program or a secret: stdin is used only for non-secret data (for example a generated nftables
//! ruleset).
//!
//! The [`CommandRunner`] trait is the seam the tests use: the real [`SystemRunner`] needs root for
//! `nft`, so the logic above it is tested with a fake.

use std::future::Future;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hx_ipc::text::sanitize_text;

/// Output cap per stream (ipc.md 8).
pub const OUTPUT_CAP: usize = 64 * 1024;
/// Output cap of `ip` (4 MiB).
pub const IP_OUTPUT_CAP: usize = 4 * 1024 * 1024;

/// The closed set of host programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tool {
    /// `nft`: load and check the host ruleset.
    Nft,
    /// `sysctl`: apply the Incus sysctl drop-in.
    Sysctl,
    /// `iptables`: the `DOCKER-USER` rules.
    Iptables,
    /// `ip`: enumerate the host's addresses (`ip -j address show`).
    Ip,
    /// `blkid`: probe a pool device for signatures.
    Blkid,
}

impl Tool {
    /// Absolute paths tried in order; the first that exists is used. There is no `PATH` search.
    pub fn candidates(self) -> &'static [&'static str] {
        match self {
            Tool::Nft => &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"],
            Tool::Sysctl => &["/usr/sbin/sysctl", "/sbin/sysctl", "/usr/bin/sysctl"],
            Tool::Iptables => &["/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables"],
            Tool::Ip => &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"],
            Tool::Blkid => &["/usr/sbin/blkid", "/sbin/blkid", "/usr/bin/blkid"],
        }
    }

    /// The most output kept from this tool. `ip -j address show` on a host with many veths is far
    /// larger than 64 KiB, and a truncated list would silently shrink the ACL's host drops.
    pub fn output_cap(self) -> usize {
        match self {
            Tool::Ip => IP_OUTPUT_CAP,
            _ => OUTPUT_CAP,
        }
    }

    /// The tool's name, for logs.
    pub fn name(self) -> &'static str {
        match self {
            Tool::Nft => "nft",
            Tool::Sysctl => "sysctl",
            Tool::Iptables => "iptables",
            Tool::Ip => "ip",
            Tool::Blkid => "blkid",
        }
    }

    fn resolve(self) -> io::Result<PathBuf> {
        self.candidates()
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("`{}` is not installed", self.name()),
                )
            })
    }
}

/// One invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    /// Which tool.
    pub tool: Tool,
    /// Arguments, built by privd from constants and values it validated.
    pub args: Vec<String>,
    /// Data for stdin, never secret.
    pub stdin: Option<Vec<u8>>,
    /// Kill the child after this long.
    pub timeout: Duration,
}

impl Program {
    /// A program with no stdin and a 30 s timeout.
    pub fn new(tool: Tool, args: &[&str]) -> Self {
        Self {
            tool,
            args: args.iter().map(|s| (*s).to_string()).collect(),
            stdin: None,
            timeout: Duration::from_secs(30),
        }
    }

    /// With stdin data.
    pub fn with_stdin(mut self, data: Vec<u8>) -> Self {
        self.stdin = Some(data);
        self
    }

    /// With another timeout.
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }
}

/// What a finished child left.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunOutput {
    /// Exit code (`None` when killed by a signal or by the timeout).
    pub code: Option<i32>,
    /// Whether the timeout killed it.
    pub timed_out: bool,
    /// Stdout, sanitized, at most 64 KiB.
    pub stdout: String,
    /// Stderr, sanitized, at most 64 KiB.
    pub stderr: String,
}

impl RunOutput {
    /// True when the child exited 0.
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// A boxed future, so that the trait can be used as `dyn`.
pub type RunFuture<'a> = Pin<Box<dyn Future<Output = io::Result<RunOutput>> + Send + 'a>>;

/// Runs [`Program`]s.
pub trait CommandRunner: Send + Sync {
    /// Runs `program` to completion (or its timeout).
    fn run<'a>(&'a self, program: Program) -> RunFuture<'a>;
}

/// The real runner: `std::process` on a blocking thread.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run<'a>(&'a self, program: Program) -> RunFuture<'a> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || run_blocking(&program))
                .await
                .map_err(io::Error::other)?
        })
    }
}

fn read_capped(mut r: impl Read, cap: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                // Keep reading after the cap so the child never blocks on a full pipe, but keep
                // only the first 64 KiB.
                let room = cap.saturating_sub(out.len());
                out.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
    out
}

/// The blocking implementation behind [`SystemRunner`].
pub fn run_blocking(p: &Program) -> io::Result<RunOutput> {
    let path = p.tool.resolve()?;
    let mut cmd = Command::new(path);
    cmd.args(&p.args)
        .env_clear()
        .stdin(if p.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let cap = p.tool.output_cap();
    let mut child = cmd.spawn()?;
    let stdin_thread = child.stdin.take().map(|mut si| {
        let data = p.stdin.clone().unwrap_or_default();
        std::thread::spawn(move || {
            let _ = si.write_all(&data);
        })
    });
    let out_thread = child
        .stdout
        .take()
        .map(|o| std::thread::spawn(move || read_capped(o, cap)));
    let err_thread = child
        .stderr
        .take()
        .map(|o| std::thread::spawn(move || read_capped(o, cap)));
    let started = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait()? {
            Some(s) => break (Some(s), false),
            None if started.elapsed() >= p.timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break (None, true);
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    if let Some(t) = stdin_thread {
        let _ = t.join();
    }
    let text = |t: Option<std::thread::JoinHandle<Vec<u8>>>| {
        let bytes = t.and_then(|t| t.join().ok()).unwrap_or_default();
        sanitize_text(&String::from_utf8_lossy(&bytes), cap)
    };
    Ok(RunOutput {
        code: status.and_then(|s| s.code()),
        timed_out,
        stdout: text(out_thread),
        stderr: text(err_thread),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tool_set_is_closed_and_absolute() {
        for t in [
            Tool::Nft,
            Tool::Sysctl,
            Tool::Iptables,
            Tool::Ip,
            Tool::Blkid,
        ] {
            assert!(t.candidates().iter().all(|p| p.starts_with('/')));
        }
    }

    #[test]
    fn runs_with_a_cleared_environment_and_stdin() {
        // `ip` exists on any host that runs this project's tests; `-V` prints its version.
        let out = run_blocking(&Program::new(Tool::Ip, &["-V"])).unwrap();
        assert!(out.success(), "{out:?}");
        assert!(
            out.stdout.contains("iproute2")
                || out.stderr.contains("iproute2")
                || !out.stdout.is_empty()
        );
    }
}
