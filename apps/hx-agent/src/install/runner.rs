//! The closed set of programs the installer runs, and the one way it runs them.
//!
//! Rules (design D3, `docs/ipc.md` 5.2 rule 5):
//!
//! * The program is a [`Tool`], a closed enum with fixed absolute paths; there is no way to name
//!   another program.
//! * The argv is built from constants and from values that were validated at the boundary (a
//!   port, a package name from our table, a unit name from our table). **No secret is ever an
//!   argument.** A secret may be the standard input of a tool (`systemd-creds encrypt`), from a
//!   [`Zeroizing`] buffer.
//! * The child gets a **cleared environment**: a fixed `PATH`, `LC_ALL=C`, and for apt
//!   `DEBIAN_FRONTEND=noninteractive` and `NEEDRESTART_MODE=a` (the only variables, all constants).
//! * No shell, a timeout, and an output cap.
//!
//! [`Runner`] is the seam: [`RealRunner`] runs the tool, [`DenyRunner`] refuses (a non-production
//! configuration must never reach the host), and `install::testing::FakeRunner` simulates a host.

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::paths::CHILD_PATH;

/// Every program the installer may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Tool {
    /// `apt-get`.
    AptGet,
    /// `dpkg-query`.
    DpkgQuery,
    /// `apt-cache`.
    AptCache,
    /// `systemctl`.
    Systemctl,
    /// `systemd-creds`.
    SystemdCreds,
    /// `systemd-sysusers`.
    SystemdSysusers,
    /// `systemd-tmpfiles`.
    SystemdTmpfiles,
    /// `systemd-detect-virt`.
    SystemdDetectVirt,
    /// `ufw`.
    Ufw,
    /// `nft`.
    Nft,
    /// `iptables` (read only: `-S INPUT`).
    Iptables,
    /// `userdel`.
    Userdel,
    /// `ip`.
    Ip,
}

impl Tool {
    /// Every tool.
    pub const ALL: [Tool; 13] = [
        Tool::AptGet,
        Tool::DpkgQuery,
        Tool::AptCache,
        Tool::Systemctl,
        Tool::SystemdCreds,
        Tool::SystemdSysusers,
        Tool::SystemdTmpfiles,
        Tool::SystemdDetectVirt,
        Tool::Ufw,
        Tool::Nft,
        Tool::Iptables,
        Tool::Userdel,
        Tool::Ip,
    ];

    /// The name used in the log.
    pub fn name(self) -> &'static str {
        match self {
            Self::AptGet => "apt-get",
            Self::DpkgQuery => "dpkg-query",
            Self::AptCache => "apt-cache",
            Self::Systemctl => "systemctl",
            Self::SystemdCreds => "systemd-creds",
            Self::SystemdSysusers => "systemd-sysusers",
            Self::SystemdTmpfiles => "systemd-tmpfiles",
            Self::SystemdDetectVirt => "systemd-detect-virt",
            Self::Ufw => "ufw",
            Self::Nft => "nft",
            Self::Iptables => "iptables",
            Self::Userdel => "userdel",
            Self::Ip => "ip",
        }
    }

    /// The absolute paths tried in order (merged-usr and split-usr hosts differ).
    pub fn candidates(self) -> &'static [&'static str] {
        match self {
            Self::AptGet => &["/usr/bin/apt-get"],
            Self::DpkgQuery => &["/usr/bin/dpkg-query"],
            Self::AptCache => &["/usr/bin/apt-cache"],
            Self::Systemctl => &["/usr/bin/systemctl", "/bin/systemctl"],
            Self::SystemdCreds => &["/usr/bin/systemd-creds", "/bin/systemd-creds"],
            Self::SystemdSysusers => &["/usr/bin/systemd-sysusers", "/bin/systemd-sysusers"],
            Self::SystemdTmpfiles => &["/usr/bin/systemd-tmpfiles", "/bin/systemd-tmpfiles"],
            Self::SystemdDetectVirt => {
                &["/usr/bin/systemd-detect-virt", "/bin/systemd-detect-virt"]
            }
            Self::Ufw => &["/usr/sbin/ufw"],
            Self::Nft => &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"],
            Self::Iptables => &["/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables"],
            Self::Userdel => &["/usr/sbin/userdel", "/sbin/userdel"],
            Self::Ip => &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"],
        }
    }
}

/// One invocation: a tool, its argv, an optional secret standard input, a timeout.
#[derive(Debug)]
pub struct Call {
    /// The program.
    pub tool: Tool,
    /// The arguments (never a secret).
    pub args: Vec<String>,
    /// Standard input (may be a secret; wiped when the call is dropped).
    pub stdin: Option<Zeroizing<Vec<u8>>>,
    /// Extra environment: constants only (`DEBIAN_FRONTEND`, ...).
    pub env: &'static [(&'static str, &'static str)],
    /// Kill the child after this long.
    pub timeout: Duration,
    /// Keep at most this many bytes of each output stream.
    pub cap: usize,
}

/// The variables apt needs to stay non-interactive.
pub const APT_ENV: &[(&str, &str)] = &[
    ("DEBIAN_FRONTEND", "noninteractive"),
    ("NEEDRESTART_MODE", "a"),
    ("APT_LISTCHANGES_FRONTEND", "none"),
];

impl Call {
    /// A call with a 60 s timeout and a 64 KiB output cap.
    pub fn new(tool: Tool, args: &[&str]) -> Self {
        Self {
            tool,
            args: args.iter().map(|a| (*a).to_owned()).collect(),
            stdin: None,
            env: &[],
            timeout: Duration::from_secs(60),
            cap: 64 * 1024,
        }
    }

    /// A call whose argv includes values built at run time.
    pub fn owned(tool: Tool, args: Vec<String>) -> Self {
        Self {
            tool,
            args,
            stdin: None,
            env: &[],
            timeout: Duration::from_secs(60),
            cap: 64 * 1024,
        }
    }

    /// Sets the standard input.
    pub fn with_stdin(mut self, stdin: Zeroizing<Vec<u8>>) -> Self {
        self.stdin = Some(stdin);
        self
    }

    /// Sets the timeout in seconds.
    pub fn timeout_secs(mut self, s: u64) -> Self {
        self.timeout = Duration::from_secs(s);
        self
    }

    /// Sets the environment.
    pub fn with_env(mut self, env: &'static [(&'static str, &'static str)]) -> Self {
        self.env = env;
        self
    }

    /// The argv as one line for the log.
    pub fn line(&self) -> String {
        let mut s = self.tool.name().to_owned();
        for a in &self.args {
            s.push(' ');
            s.push_str(a);
        }
        s
    }
}

/// What a tool produced. Both streams are wiped on drop (`systemd-creds decrypt` prints a secret).
#[derive(Debug)]
pub struct Output {
    /// The exit status; -1 when the process was killed by a signal.
    pub status: i32,
    /// Standard output (capped).
    pub stdout: Zeroizing<Vec<u8>>,
    /// Standard error (capped).
    pub stderr: Zeroizing<Vec<u8>>,
}

impl Output {
    /// Exit status 0.
    pub fn ok(&self) -> bool {
        self.status == 0
    }

    /// Standard output as text (lossy).
    pub fn out_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// The last bytes of standard error, for a message.
    pub fn err_tail(&self) -> String {
        let t = String::from_utf8_lossy(&self.stderr);
        let t = t.trim();
        let start = t.len().saturating_sub(300);
        let mut s = start;
        while !t.is_char_boundary(s) {
            s += 1;
        }
        t[s..].to_owned()
    }
}

/// Runs tools.
pub trait Runner {
    /// Runs `call` to completion. `Err` means the tool could not be started or timed out; a
    /// non-zero exit is an `Ok` with that status.
    fn run(&mut self, call: &Call) -> io::Result<Output>;
}

/// Runs the real programs.
#[derive(Debug, Default)]
pub struct RealRunner;

fn resolve(tool: Tool) -> io::Result<PathBuf> {
    for c in tool.candidates() {
        let p = PathBuf::from(c);
        if p.is_file() {
            return Ok(p);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("{} is not installed", tool.name()),
    ))
}

/// Reads up to `cap` bytes and discards the rest (so the child never blocks on a full pipe).
fn drain(mut r: impl Read, cap: usize) -> Zeroizing<Vec<u8>> {
    let mut kept = Zeroizing::new(Vec::new());
    let mut buf = Zeroizing::new([0u8; 8192]);
    loop {
        match r.read(&mut *buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = cap.saturating_sub(kept.len());
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
    kept
}

impl Runner for RealRunner {
    fn run(&mut self, call: &Call) -> io::Result<Output> {
        run_path(resolve(call.tool)?, call)
    }
}

/// Runs the program at `path` with the call's argv and the cleared environment.
fn run_path(path: PathBuf, call: &Call) -> io::Result<Output> {
    {
        let mut cmd = Command::new(path);
        cmd.args(&call.args)
            .env_clear()
            .env("PATH", CHILD_PATH)
            .env("LC_ALL", "C")
            .stdin(if call.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in call.env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn()?;
        let stdin_thread = match (child.stdin.take(), call.stdin.as_ref()) {
            (Some(mut pipe), Some(data)) => {
                // The data is copied into the thread's own zeroizing buffer; small (a key).
                let data = Zeroizing::new(data.to_vec());
                Some(std::thread::spawn(move || {
                    let _ = pipe.write_all(&data);
                }))
            }
            _ => None,
        };
        let cap = call.cap;
        let out = child
            .stdout
            .take()
            .map(|s| std::thread::spawn(move || drain(s, cap)));
        let err = child
            .stderr
            .take()
            .map(|s| std::thread::spawn(move || drain(s, cap)));
        let deadline = Instant::now() + call.timeout;
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break st;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{} timed out", call.tool.name()),
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        if let Some(t) = stdin_thread {
            let _ = t.join();
        }
        let stdout = out.and_then(|t| t.join().ok()).unwrap_or_default();
        let stderr = err.and_then(|t| t.join().ok()).unwrap_or_default();
        Ok(Output {
            status: status.code().unwrap_or(-1),
            stdout,
            stderr,
        })
    }
}

/// Refuses every call: the runner of a non-production configuration, which must never reach the
/// real host (tests build their own `Config` with sockets in a temporary directory).
#[derive(Debug, Default)]
pub struct DenyRunner;

impl Runner for DenyRunner {
    fn run(&mut self, call: &Call) -> io::Result<Output> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is not run: this is not the production configuration",
                call.tool.name()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tool_set_is_closed_and_every_tool_has_an_absolute_path() {
        for t in Tool::ALL {
            assert!(!t.candidates().is_empty(), "{t:?}");
            for c in t.candidates() {
                assert!(c.starts_with('/'), "{t:?}: {c}");
            }
        }
        // 13 tools: adding one is a deliberate change of this number and of the design.
        assert_eq!(Tool::ALL.len(), 13);
    }

    #[test]
    fn a_child_gets_a_cleared_environment_and_only_the_constants() {
        // `/usr/bin/env` stands in for a tool: the point is what the child sees.
        let call = Call::new(Tool::Ip, &[]).with_env(APT_ENV);
        let out = run_path(PathBuf::from("/usr/bin/env"), &call).unwrap();
        let mut seen: Vec<String> = out.out_text().lines().map(str::to_owned).collect();
        seen.sort();
        let mut want = vec![
            format!("PATH={CHILD_PATH}"),
            "LC_ALL=C".to_owned(),
            "DEBIAN_FRONTEND=noninteractive".to_owned(),
            "NEEDRESTART_MODE=a".to_owned(),
            "APT_LISTCHANGES_FRONTEND=none".to_owned(),
        ];
        want.sort();
        assert_eq!(seen, want, "nothing of this process's environment leaks");
    }

    #[test]
    fn standard_input_reaches_the_child_and_a_timeout_kills_it() {
        let call = Call::new(Tool::Ip, &[]).with_stdin(Zeroizing::new(b"secret-in".to_vec()));
        let out = run_path(PathBuf::from("/usr/bin/cat"), &call).unwrap();
        assert_eq!(&*out.stdout, b"secret-in");
        let slow = Call::new(Tool::Ip, &["5"]).timeout_secs(0);
        let e = run_path(PathBuf::from("/usr/bin/sleep"), &slow).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn the_deny_runner_refuses() {
        let e = DenyRunner
            .run(&Call::new(Tool::Systemctl, &["daemon-reload"]))
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_call_line_is_the_tool_and_its_argv() {
        let c = Call::new(Tool::Ufw, &["allow", "443/tcp"]);
        assert_eq!(c.line(), "ufw allow 443/tcp");
    }
}
