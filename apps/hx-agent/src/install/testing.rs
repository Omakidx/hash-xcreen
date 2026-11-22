//! Fakes for the installer's tests (feature `install-test-hooks`, never in a release build):
//! a **simulated host** behind the [`Runner`] seam (packages, systemd units, `systemd-creds`,
//! ufw, nft, users), fake privd and gatewayd behind [`Daemons`], a fake [`Probe`], and a scripted
//! terminal. Nothing here runs a real program or touches a real path: the host is a temporary
//! directory and a set of maps.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use hx_ipc::admin::pb as apb;
use hx_ipc::privd::pb::{self, LockoutPurpose};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::daemons::{Daemons, OnProgress, PrivdHello, UninstallSummary};
use super::error::{InstallError, Result};
use super::paths::{self, Paths};
use super::probe::{BlockInfo, Probe};
use super::runner::{Call, Output, Runner, Tool};
use crate::cli::error::CliError;
use crate::cli::privd::ProgressLine;
use crate::cli::{Prompter, text::hex};

// ----- the simulated host -----------------------------------------------------------------------

/// One recorded tool call: what a canary test searches for secrets.
#[derive(Debug, Clone)]
pub struct Recorded {
    /// The tool.
    pub tool: Tool,
    /// The argv.
    pub args: Vec<String>,
    /// The extra environment of the call (the real runner adds only `PATH` and `LC_ALL`).
    pub env: Vec<(String, String)>,
    /// The standard input, if any (test data; a canary test never looks for secrets *here*).
    pub stdin: Option<Vec<u8>>,
}

impl Recorded {
    /// `tool arg arg ...`.
    pub fn line(&self) -> String {
        let mut s = self.tool.name().to_owned();
        for a in &self.args {
            s.push(' ');
            s.push_str(a);
        }
        s
    }
}

/// An injected failure.
#[derive(Debug, Clone)]
pub struct FailRule {
    /// Which tool.
    pub tool: Tool,
    /// The call line must contain this.
    pub contains: String,
    /// The exit status to return.
    pub status: i32,
    /// How many times it fires (`None`: always).
    pub times: Option<u32>,
}

/// State that the fake runner and the fake daemons share (a restart of privd is seen by both).
#[derive(Debug, Default)]
pub struct Shared {
    /// How many times `systemctl restart hx-privd.service` ran.
    pub privd_restarts: u32,
}

/// The simulated host.
pub struct FakeRunner {
    /// The root of the host's files.
    pub root: PathBuf,
    /// Everything that ran, in order.
    pub calls: Vec<Recorded>,
    /// Installed packages and versions.
    pub installed: BTreeMap<String, String>,
    /// The version apt would install per package (`incus` has one by default).
    pub apt_versions: BTreeMap<String, String>,
    /// `apt-cache policy incus` candidate.
    pub apt_candidate: Option<String>,
    /// Enabled units.
    pub enabled: BTreeSet<String>,
    /// Active units.
    pub active: BTreeSet<String>,
    /// Units that exist without a file (the distro's).
    pub system_units: BTreeSet<String>,
    /// Files to create when a unit is started (`incus.socket` makes the Incus socket).
    pub on_start: BTreeMap<String, PathBuf>,
    /// `systemd-detect-virt -c` answer.
    pub virt: String,
    /// `systemd --version` number.
    pub systemd: u32,
    /// ufw: `None` is not installed, `Some(active)`.
    pub ufw: Option<bool>,
    /// ufw rules added.
    pub ufw_rules: Vec<String>,
    /// ufw rules that are the administrator's (no `hash-xcreen` comment).
    pub ufw_foreign: BTreeSet<String>,
    /// nft ruleset items (`chain`, `rule`, ...), as `nft -j` prints them.
    pub nft_items: Vec<Value>,
    /// nft is installed.
    pub nft: bool,
    /// iptables `-S INPUT` output.
    pub iptables_input: String,
    /// `ip -j addr` output.
    pub ip_json: String,
    /// Injected failures.
    pub fail: Vec<FailRule>,
    /// Shared with the fake daemons.
    pub shared: Rc<RefCell<Shared>>,
    next_handle: u64,
}

impl FakeRunner {
    /// A fresh Ubuntu 24.04 host under `root`.
    pub fn new(root: &Path, shared: Rc<RefCell<Shared>>) -> Self {
        let mut apt_versions = BTreeMap::new();
        apt_versions.insert("incus".to_owned(), "1:6.0.4-1".to_owned());
        let mut on_start = BTreeMap::new();
        on_start.insert(
            "incus.socket".to_owned(),
            root.join("var/lib/incus/unix.socket"),
        );
        Self {
            root: root.to_path_buf(),
            calls: Vec::new(),
            installed: BTreeMap::from([("ca-certificates".to_owned(), "20240203".to_owned())]),
            apt_versions,
            apt_candidate: Some("1:6.0.0-1".to_owned()),
            enabled: BTreeSet::new(),
            active: BTreeSet::new(),
            system_units: BTreeSet::from([
                "incus.socket".to_owned(),
                "nftables.service".to_owned(),
            ]),
            on_start,
            virt: "none".to_owned(),
            systemd: 255,
            ufw: None,
            ufw_rules: Vec::new(),
            ufw_foreign: BTreeSet::new(),
            nft_items: Vec::new(),
            nft: true,
            iptables_input: "-P INPUT ACCEPT\n".to_owned(),
            ip_json:
                r#"[{"ifname":"eth0","addr_info":[{"local":"203.0.113.9","scope":"global"}]}]"#
                    .to_owned(),
            fail: Vec::new(),
            shared,
            next_handle: 100,
        }
    }

    /// The calls whose line contains `needle`.
    pub fn lines(&self) -> Vec<String> {
        self.calls.iter().map(Recorded::line).collect()
    }

    /// Calls that change the host (everything except the read-only queries).
    pub fn mutating(&self) -> Vec<String> {
        self.calls
            .iter()
            .filter(|c| {
                let a0 = c.args.first().map(String::as_str).unwrap_or("");
                match c.tool {
                    Tool::DpkgQuery
                    | Tool::AptCache
                    | Tool::SystemdDetectVirt
                    | Tool::Ip
                    | Tool::Iptables => false,
                    Tool::Systemctl => !matches!(a0, "--version" | "is-enabled" | "is-active"),
                    Tool::Ufw => !matches!(a0, "status" | "show"),
                    Tool::Nft => !(a0 == "-j" && c.args.get(1).map(String::as_str) == Some("list")),
                    Tool::SystemdCreds => a0 == "encrypt",
                    _ => true,
                }
            })
            .map(Recorded::line)
            .collect()
    }

    /// Adds an injected failure.
    pub fn fail_on(&mut self, tool: Tool, contains: &str, status: i32, times: Option<u32>) {
        self.fail.push(FailRule {
            tool,
            contains: contains.to_owned(),
            status,
            times,
        });
    }

    fn unit_exists(&self, name: &str) -> bool {
        self.system_units.contains(name)
            || self
                .root
                .join("usr/local/lib/systemd/system")
                .join(name)
                .exists()
    }

    fn ok(out: &str) -> Output {
        Output {
            status: 0,
            stdout: Zeroizing::new(out.as_bytes().to_vec()),
            stderr: Zeroizing::new(Vec::new()),
        }
    }

    fn status(status: i32, err: &str) -> Output {
        Output {
            status,
            stdout: Zeroizing::new(Vec::new()),
            stderr: Zeroizing::new(err.as_bytes().to_vec()),
        }
    }

    fn systemctl(&mut self, a: &[String]) -> Output {
        let verb = a.first().map(String::as_str).unwrap_or("");
        let units: Vec<String> = a
            .iter()
            .skip(1)
            .filter(|x| !x.starts_with('-'))
            .cloned()
            .collect();
        let now = a.iter().any(|x| x == "--now");
        match verb {
            "--version" => Self::ok(&format!(
                "systemd {} ({}.1-test)\n+PAM\n",
                self.systemd, self.systemd
            )),
            "daemon-reload" | "reset-failed" => Self::ok(""),
            "enable" => {
                for u in &units {
                    if !self.unit_exists(u) {
                        return Self::status(
                            1,
                            &format!("Failed to enable unit: Unit file {u} does not exist."),
                        );
                    }
                }
                for u in &units {
                    self.enabled.insert(u.clone());
                    if now {
                        self.active.insert(u.clone());
                        if let Some(f) = self.on_start.get(u) {
                            if let Some(d) = f.parent() {
                                let _ = std::fs::create_dir_all(d);
                            }
                            let _ = std::fs::write(f, b"");
                        }
                    }
                }
                Self::ok("")
            }
            "disable" => {
                for u in &units {
                    self.enabled.remove(u);
                    if now {
                        self.active.remove(u);
                    }
                }
                Self::ok("")
            }
            "start" => {
                for u in &units {
                    self.active.insert(u.clone());
                }
                Self::ok("")
            }
            "stop" => {
                for u in &units {
                    self.active.remove(u);
                }
                Self::ok("")
            }
            "restart" => {
                for u in &units {
                    if u == "hx-privd.service" {
                        self.shared.borrow_mut().privd_restarts += 1;
                    }
                    if self.unit_exists(u) {
                        self.active.insert(u.clone());
                    }
                }
                Self::ok("")
            }
            "is-enabled" => {
                if units.iter().all(|u| self.enabled.contains(u)) {
                    Self::ok("enabled\n")
                } else {
                    Self::status(1, "")
                }
            }
            "is-active" => {
                if units.iter().all(|u| self.active.contains(u)) {
                    Self::ok("active\n")
                } else {
                    Self::status(3, "")
                }
            }
            _ => Self::status(1, "unknown verb"),
        }
    }

    fn dpkg_query(&self, a: &[String]) -> Output {
        let (Some(pkg), Some(fmt)) = (
            a.last(),
            a.iter().position(|x| x == "-f").and_then(|i| a.get(i + 1)),
        ) else {
            return Self::status(2, "usage");
        };
        match self.installed.get(pkg) {
            Some(v) => Self::ok(
                &fmt.replace("${db:Status-Abbrev}", "ii ")
                    .replace("${Version}", v)
                    .replace("\\n", "\n"),
            ),
            None => Self::status(1, &format!("dpkg-query: no packages found matching {pkg}")),
        }
    }

    fn apt_get(&mut self, a: &[String]) -> Output {
        if a.iter().any(|x| x == "update") && !a.iter().any(|x| x == "install") {
            return Self::ok("");
        }
        let mut pkgs = Vec::new();
        let mut it = a.iter().peekable();
        let mut seen_install = false;
        while let Some(x) = it.next() {
            if x == "-o" {
                it.next();
            } else if x == "install" {
                seen_install = true;
            } else if seen_install && !x.starts_with('-') {
                pkgs.push(x.clone());
            }
        }
        for p in pkgs {
            let v = self
                .apt_versions
                .get(&p)
                .cloned()
                .unwrap_or_else(|| "1.0".to_owned());
            self.installed.insert(p, v);
        }
        Self::ok("")
    }

    fn creds(&mut self, a: &[String]) -> Output {
        let name = a
            .iter()
            .find_map(|x| x.strip_prefix("--name="))
            .unwrap_or("")
            .to_owned();
        match a.first().map(String::as_str) {
            Some("encrypt") => {
                // encrypt --name=n - <path>; the plaintext is in the call's stdin (handled by run()).
                Self::status(70, "stdin missing")
            }
            Some("decrypt") => {
                let Some(path) = a.get(2) else {
                    return Self::status(2, "usage");
                };
                let Ok(text) = std::fs::read_to_string(path) else {
                    return Self::status(1, "no such credential");
                };
                let prefix = format!("FAKE-SEALED:{name}:");
                match text.strip_prefix(&prefix).and_then(|h| unhex(h.trim())) {
                    Some(plain) => Output {
                        status: 0,
                        stdout: Zeroizing::new(plain),
                        stderr: Zeroizing::new(Vec::new()),
                    },
                    None => Self::status(1, "wrong name or not a credential"),
                }
            }
            _ => Self::status(2, "usage"),
        }
    }

    fn nft_list(&self) -> String {
        let mut items = vec![json!({"metainfo": {"version": "1.0.9"}})];
        items.extend(self.nft_items.iter().cloned());
        json!({"nftables": items}).to_string()
    }

    fn nft(&mut self, a: &[String]) -> Output {
        if !self.nft {
            return Self::status(127, "nft: not found");
        }
        match (a.first().map(String::as_str), a.get(1).map(String::as_str)) {
            (Some("-j"), Some("list")) => Self::ok(&self.nft_list()),
            (Some("insert"), Some("rule")) => {
                let (fam, tab, chain) = (a[2].clone(), a[3].clone(), a[4].clone());
                let port = a
                    .iter()
                    .position(|x| x == "dport")
                    .and_then(|i| a.get(i + 1))
                    .and_then(|p| p.parse::<u64>().ok());
                let comment = a
                    .last()
                    .map(|c| c.trim_matches('"').to_owned())
                    .unwrap_or_default();
                self.next_handle += 1;
                let expr = if comment == "hx-agent-port" {
                    json!([{"match": {"left": {"payload": {"protocol": "th", "field": "dport"}}, "op": "==", "right": port}}, {"accept": null}])
                } else {
                    json!([{"accept": null}])
                };
                self.nft_items.push(json!({"rule": {"family": fam, "table": tab, "chain": chain, "handle": self.next_handle,
                    "comment": comment, "expr": expr}}));
                Self::ok("")
            }
            (Some("delete"), Some("rule")) => {
                let h = a.last().and_then(|x| x.parse::<u64>().ok());
                self.nft_items.retain(|i| {
                    i.get("rule")
                        .and_then(|r| r.get("handle"))
                        .and_then(Value::as_u64)
                        != h
                });
                Self::ok("")
            }
            _ => Self::status(1, "unsupported"),
        }
    }

    fn passwd_path(&self) -> PathBuf {
        self.root.join("etc/passwd")
    }
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

impl Runner for FakeRunner {
    fn run(&mut self, call: &Call) -> io::Result<Output> {
        self.calls.push(Recorded {
            tool: call.tool,
            args: call.args.clone(),
            env: call
                .env
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            stdin: call.stdin.as_ref().map(|s| s.to_vec()),
        });
        let line = call.line();
        for f in &mut self.fail {
            if f.tool == call.tool && line.contains(&f.contains) {
                match &mut f.times {
                    Some(0) => continue,
                    Some(n) => *n -= 1,
                    None => {}
                }
                return Ok(Self::status(f.status, "injected failure"));
            }
        }
        let a = &call.args;
        let out = match call.tool {
            Tool::Systemctl => self.systemctl(a),
            Tool::DpkgQuery => self.dpkg_query(a),
            Tool::AptGet => self.apt_get(a),
            Tool::AptCache => match &self.apt_candidate {
                Some(c) => Self::ok(&format!("incus:\n  Installed: (none)\n  Candidate: {c}\n")),
                None => Self::ok("incus:\n  Installed: (none)\n  Candidate: (none)\n"),
            },
            Tool::SystemdCreds => {
                if a.first().map(String::as_str) == Some("encrypt") {
                    let name = a
                        .iter()
                        .find_map(|x| x.strip_prefix("--name="))
                        .unwrap_or("");
                    match (call.stdin.as_ref(), a.last()) {
                        (Some(plain), Some(path)) => {
                            std::fs::write(path, format!("FAKE-SEALED:{name}:{}", hex(plain)))?;
                            Self::ok("")
                        }
                        _ => Self::status(1, "no input"),
                    }
                } else {
                    self.creds(a)
                }
            }
            Tool::SystemdSysusers => {
                let p = self.passwd_path();
                let cur = std::fs::read_to_string(&p).unwrap_or_default();
                if !cur.lines().any(|l| l.starts_with("hx-gatewayd:")) {
                    if let Some(d) = p.parent() {
                        std::fs::create_dir_all(d)?;
                    }
                    std::fs::write(
                        &p,
                        format!(
                            "{cur}hx-gatewayd:x:998:998:hash-xcreen gateway:/var/lib/hx-gatewayd:/usr/sbin/nologin\n"
                        ),
                    )?;
                }
                Self::ok("")
            }
            Tool::SystemdTmpfiles => Self::ok(""),
            Tool::SystemdDetectVirt => {
                if self.virt == "none" {
                    let mut o = Self::status(1, "");
                    o.stdout = Zeroizing::new(b"none\n".to_vec());
                    o
                } else {
                    Self::ok(&format!("{}\n", self.virt))
                }
            }
            Tool::Ufw => match self.ufw {
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "ufw is not installed",
                    ));
                }
                Some(active) => match a.first().map(String::as_str) {
                    Some("status") => Self::ok(if active {
                        "Status: active\n"
                    } else {
                        "Status: inactive\n"
                    }),
                    // `allow ...`, `route allow ...` (a trailing `comment X` is dropped).
                    Some("allow") | Some("route")
                        if a.get(1).map(String::as_str) != Some("delete") =>
                    {
                        let end = a.iter().position(|x| x == "comment").unwrap_or(a.len());
                        let rule = a[..end].join(" ");
                        if self.ufw_rules.contains(&rule) {
                            Self::ok("Skipping adding existing rule\n")
                        } else {
                            self.ufw_rules.push(rule);
                            Self::ok("Rule added\n")
                        }
                    }
                    Some("show") => {
                        let mut t = String::from(
                            "Added user rules (see 'ufw status' for running firewall):\n",
                        );
                        for r in &self.ufw_rules {
                            if self.ufw_foreign.contains(r) {
                                t.push_str(&format!("ufw {r}\n"));
                            } else {
                                t.push_str(&format!("ufw {r} comment 'hash-xcreen'\n"));
                            }
                        }
                        Self::ok(&t)
                    }
                    // `delete <rule>` and `route delete <rule>`.
                    Some("delete") | Some("route") => {
                        let spec = if a[0] == "route" {
                            format!("route {}", a[2..].join(" "))
                        } else {
                            a[1..].join(" ")
                        };
                        self.ufw_rules.retain(|r| *r != spec);
                        Self::ok("Rule deleted\n")
                    }
                    _ => Self::status(1, "usage"),
                },
            },
            Tool::Nft => {
                if !self.nft {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "nft is not installed",
                    ));
                }
                self.nft(a)
            }
            Tool::Iptables => Self::ok(&self.iptables_input.clone()),
            Tool::Userdel => {
                let p = self.passwd_path();
                let cur = std::fs::read_to_string(&p).unwrap_or_default();
                let user = a.last().cloned().unwrap_or_default();
                let kept: String = cur
                    .lines()
                    .filter(|l| !l.starts_with(&format!("{user}:")))
                    .map(|l| format!("{l}\n"))
                    .collect();
                std::fs::write(&p, kept)?;
                Self::ok("")
            }
            Tool::Ip => Self::ok(&self.ip_json.clone()),
        };
        Ok(out)
    }
}

// ----- fake daemons -----------------------------------------------------------------------------

/// What fake privd and gatewayd have seen and hold.
pub struct FakeDaemons {
    /// Shared with the runner.
    pub shared: Rc<RefCell<Shared>>,
    /// privd answers.
    pub up: bool,
    /// privd's phase.
    pub phase: pb::Phase,
    /// The desktop.
    pub desktop: Option<pb::Desktop>,
    /// The pool exists.
    pub pool: bool,
    /// The host firewall is loaded.
    pub firewall: bool,
    /// Incus version reported.
    pub incus_version: Option<String>,
    /// Command names, in order.
    pub log: Vec<String>,
    /// The pepper (changes the MACs).
    pub pepper: [u8; 32],
    /// The pepper privd has after a restart (to test a failed migration).
    pub pepper_after_restart: Option<[u8; 32]>,
    /// The PIN verifier set.
    pub pin_verifier: Option<Vec<u8>>,
    /// The password verifier set.
    pub password_verifier: Option<Vec<u8>>,
    /// The token installed, with how many times.
    pub tokens: Vec<Vec<u8>>,
    /// Pairing codes made.
    pub codes: u32,
    /// The password the desktop was created with (test data).
    pub desktop_password: Option<Vec<u8>>,
    /// Requests of `CreateDesktop`.
    pub create_requests: Vec<pb::CreateDesktopRequest>,
    /// Requests of `SetupHost`.
    pub host_requests: Vec<pb::SetupHostRequest>,
    /// Limits applied by `SetLimits`.
    pub limit_calls: Vec<pb::Limits>,
    /// The owner key enrolled.
    pub owner_key: Option<Vec<u8>>,
    /// What `Uninstall` answers.
    pub uninstall_answer: Option<InstallError>,
    /// `Uninstall` requests: keep flags.
    pub uninstalls: Vec<bool>,
    /// Failures to inject, by command name (fires once).
    pub fail: BTreeMap<&'static str, InstallError>,
    /// The clock the expiry is computed from.
    pub now: u64,
}

impl FakeDaemons {
    /// Fake daemons of a fresh host.
    pub fn new(shared: Rc<RefCell<Shared>>) -> Self {
        Self {
            shared,
            up: true,
            phase: pb::Phase::Uninitialized,
            desktop: None,
            pool: false,
            firewall: false,
            incus_version: Some("6.0.4".into()),
            log: Vec::new(),
            pepper: [3u8; 32],
            pepper_after_restart: None,
            pin_verifier: None,
            password_verifier: None,
            tokens: Vec::new(),
            codes: 0,
            desktop_password: None,
            create_requests: Vec::new(),
            host_requests: Vec::new(),
            limit_calls: Vec::new(),
            owner_key: None,
            uninstall_answer: None,
            uninstalls: Vec::new(),
            fail: BTreeMap::new(),
            now: 1_800_000_000,
        }
    }

    fn enter(&mut self, name: &'static str) -> Result<()> {
        self.log.push(name.to_owned());
        if !self.up && name != "hello" {
            return Err(InstallError::unavailable("hx-privd is not running"));
        }
        if let Some(e) = self.fail.remove(name) {
            return Err(e);
        }
        Ok(())
    }

    /// How many times `name` was called.
    pub fn count(&self, name: &str) -> usize {
        self.log.iter().filter(|l| *l == name).count()
    }

    fn pepper_now(&self) -> [u8; 32] {
        if self.shared.borrow().privd_restarts > 0 {
            self.pepper_after_restart.unwrap_or(self.pepper)
        } else {
            self.pepper
        }
    }
}

impl Daemons for FakeDaemons {
    fn hello(&mut self) -> Result<PrivdHello> {
        self.log.push("hello".into());
        if !self.up {
            return Err(InstallError::unavailable("hx-privd is not running"));
        }
        if let Some(e) = self.fail.remove("hello") {
            return Err(e);
        }
        Ok(PrivdHello {
            version: "0.0.0-test".into(),
            phase: self.phase,
        })
    }

    fn host_info(&mut self) -> Result<pb::GetHostInfoResult> {
        self.enter("host_info")?;
        Ok(pb::GetHostInfoResult {
            privd_version: "0.0.0-test".into(),
            phase: self.phase as i32,
            pool: Some(pb::PoolInfo {
                exists: self.pool,
                driver: "btrfs".into(),
                total_gib: 100,
                free_gib: 90,
            }),
            incus_version: self.incus_version.clone(),
            host_firewall_loaded: self.firewall,
            sysctl_ok: true,
            desktop_exists: self.desktop.is_some(),
            ..Default::default()
        })
    }

    fn begin_setup(&mut self, secs: u32) -> Result<u64> {
        self.enter("begin_setup")?;
        self.phase = pb::Phase::SetupOpen;
        Ok(self.now + u64::from(secs))
    }

    fn finish_setup(&mut self, _force: bool) -> Result<()> {
        self.enter("finish_setup")?;
        self.phase = pb::Phase::Ready;
        Ok(())
    }

    fn setup_host(
        &mut self,
        req: pb::SetupHostRequest,
        on: OnProgress<'_>,
    ) -> Result<pb::SetupHostResult> {
        self.enter("setup_host")?;
        on(&ProgressLine {
            stage: "HOST".into(),
            index: 1,
            total: 2,
            step: "pool".into(),
            percent: None,
            ok: true,
        });
        self.host_requests.push(req);
        self.pool = true;
        self.firewall = true;
        Ok(pb::SetupHostResult::default())
    }

    fn create_desktop(
        &mut self,
        req: pb::CreateDesktopRequest,
        password: &[u8],
        on: OnProgress<'_>,
    ) -> Result<pb::CreateDesktopResult> {
        self.enter("create_desktop")?;
        on(&ProgressLine {
            stage: "BUILD".into(),
            index: 3,
            total: 12,
            step: "install packages".into(),
            percent: Some(40),
            ok: false,
        });
        self.desktop_password = Some(password.to_vec());
        let limits = req.limits.unwrap_or_default();
        self.desktop = Some(pb::Desktop {
            desktop_id: req.desktop_id.clone(),
            state: pb::DesktopState::Ready as i32,
            username: req.username.clone(),
            limits: Some(pb::Limits {
                cpu: if limits.cpu == 0 { 4 } else { limits.cpu },
                memory_mib: if limits.memory_mib == 0 {
                    4096
                } else {
                    limits.memory_mib
                },
                disk_gib: if limits.disk_gib == 0 {
                    50
                } else {
                    limits.disk_gib
                },
            }),
            ..Default::default()
        });
        let id = req.desktop_id.clone();
        self.create_requests.push(req);
        Ok(pb::CreateDesktopResult {
            desktop_id: id,
            path_taken: pb::PathTaken::Build as i32,
            reason: "built on the server".into(),
            warnings: vec!["hx-session package missing".into()],
            ..Default::default()
        })
    }

    fn get_desktop(&mut self, _id: &str) -> Result<Option<pb::Desktop>> {
        self.enter("get_desktop")?;
        Ok(self.desktop.clone())
    }

    fn set_limits(&mut self, _id: &str, limits: pb::Limits) -> Result<()> {
        self.enter("set_limits")?;
        self.limit_calls.push(limits);
        if let Some(d) = self.desktop.as_mut() {
            d.limits = Some(limits);
        }
        Ok(())
    }

    fn pepper_enrol(&mut self, purpose: LockoutPurpose, input: &[u8]) -> Result<Vec<u8>> {
        self.enter("pepper_enrol")?;
        let mut h = Sha256::new();
        h.update(self.pepper_now());
        h.update([purpose as u8]);
        h.update(input);
        Ok(h.finalize().to_vec())
    }

    fn enrol_owner_key(&mut self, key: &[u8]) -> Result<()> {
        self.enter("enrol_owner_key")?;
        self.owner_key = Some(key.to_vec());
        Ok(())
    }

    fn uninstall(&mut self, keep_desktop: bool, _on: OnProgress<'_>) -> Result<UninstallSummary> {
        self.log.push("uninstall".into());
        self.uninstalls.push(keep_desktop);
        match self.uninstall_answer.clone() {
            Some(e) => Err(e),
            None => Ok(UninstallSummary::default()),
        }
    }

    fn gateway_setup_window(&mut self, action: apb::SetupWindowAction, _secs: u32) -> Result<()> {
        self.enter(match action {
            apb::SetupWindowAction::Open => "window_open",
            apb::SetupWindowAction::Close => "window_close",
            _ => "window_extend",
        })
    }

    fn set_pin_verifier_all(&mut self, record: Vec<u8>) -> Result<()> {
        self.enter("set_pin_verifier")?;
        self.pin_verifier = Some(record);
        Ok(())
    }

    fn set_password_verifier(&mut self, record: Vec<u8>) -> Result<()> {
        self.enter("set_password_verifier")?;
        self.password_verifier = Some(record);
        Ok(())
    }

    fn create_pairing_token(&mut self, token: &[u8], ttl_s: u32) -> Result<u64> {
        self.enter("create_pairing_token")?;
        self.tokens.push(token.to_vec());
        Ok(self.now + u64::from(ttl_s))
    }

    fn create_pairing_code(&mut self, ttl_s: u32) -> Result<(Zeroizing<String>, u64)> {
        self.enter("create_pairing_code")?;
        self.codes += 1;
        Ok((
            Zeroizing::new("ABCD-EFGH".to_owned()),
            self.now + u64::from(ttl_s),
        ))
    }
}

// ----- fake probe, scripted terminal --------------------------------------------------------------

/// A host that answers from fields.
pub struct FakeProbe {
    /// `uname -m`.
    pub machine: String,
    /// CPUs.
    pub cpus: u32,
    /// Free GiB everywhere.
    pub free_gib: u64,
    /// Ports that cannot be bound.
    pub busy_ports: BTreeSet<u16>,
    /// Block devices by path.
    pub blocks: BTreeMap<String, BlockInfo>,
    /// Total time "slept".
    pub slept: RefCell<Duration>,
    ms: RefCell<u64>,
}

impl Default for FakeProbe {
    fn default() -> Self {
        Self {
            machine: "x86_64".into(),
            cpus: 4,
            free_gib: 100,
            busy_ports: BTreeSet::new(),
            blocks: BTreeMap::new(),
            slept: RefCell::new(Duration::ZERO),
            ms: RefCell::new(0),
        }
    }
}

impl Probe for FakeProbe {
    fn machine(&self) -> String {
        self.machine.clone()
    }
    fn cpus(&self) -> u32 {
        self.cpus
    }
    fn free_gib(&self, _path: &Path) -> io::Result<u64> {
        Ok(self.free_gib)
    }
    fn port_free(&self, port: u16) -> bool {
        !self.busy_ports.contains(&port)
    }
    fn block_device(&self, path: &str) -> io::Result<BlockInfo> {
        self.blocks
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such device"))
    }
    fn sleep(&self, d: Duration) {
        *self.slept.borrow_mut() += d;
    }
    fn mono_ms(&self) -> u64 {
        let mut m = self.ms.borrow_mut();
        *m += 7;
        *m
    }
}

/// A terminal that answers from queues and records the questions.
#[derive(Default)]
pub struct ScriptedTty {
    /// Visible answers.
    pub lines: VecDeque<String>,
    /// Hidden answers.
    pub secrets: VecDeque<Vec<u8>>,
    /// Every question asked (the text of the prompt, never an answer).
    pub asked: Vec<String>,
}

impl ScriptedTty {
    /// A terminal with these answers.
    pub fn new(lines: &[&str], secrets: &[&[u8]]) -> Self {
        Self {
            lines: lines.iter().map(|s| (*s).to_owned()).collect(),
            secrets: secrets.iter().map(|s| s.to_vec()).collect(),
            asked: Vec::new(),
        }
    }
}

impl Prompter for ScriptedTty {
    fn secret(
        &mut self,
        prompt: &str,
        _max: usize,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, CliError> {
        self.asked.push(prompt.to_owned());
        self.secrets
            .pop_front()
            .map(Zeroizing::new)
            .ok_or_else(|| CliError::Declined("no terminal".into()))
    }
    fn line(&mut self, prompt: &str) -> std::result::Result<String, CliError> {
        self.asked.push(prompt.to_owned());
        self.lines
            .pop_front()
            .ok_or_else(|| CliError::Declined("no terminal".into()))
    }
}

// ----- a whole fake machine ---------------------------------------------------------------------

/// Everything one install run needs, owned in one place.
pub struct Machine {
    /// The temporary directory holding the host's files.
    pub dir: tempfile::TempDir,
    /// The host's paths.
    pub paths: Paths,
    /// The simulated tools.
    pub runner: FakeRunner,
    /// Fake privd and gatewayd.
    pub daemons: FakeDaemons,
    /// The host probe.
    pub probe: FakeProbe,
    /// The terminal.
    pub tty: ScriptedTty,
    /// Standard output of the last run.
    pub out: Vec<u8>,
    /// Standard error of the last run.
    pub err: Vec<u8>,
    /// The release keys.
    pub keys: crate::privd::update::keys::UpdateKeys,
    /// `--json`.
    pub json: bool,
}

fn fixed_now() -> u64 {
    1_800_000_000
}

impl Machine {
    /// A supported host (Ubuntu 24.04, 16 GiB, 4 CPUs) in a fresh temporary directory.
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths::under(dir.path());
        let w = |abs: &str, text: &str| {
            let p = paths.at(abs);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        };
        w(
            paths::OS_RELEASE,
            "ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n",
        );
        w("/proc/meminfo", "MemTotal:       16384000 kB\n");
        w("/proc/sys/user/max_user_namespaces", "63000\n");
        w("/sys/fs/cgroup/cgroup.controllers", "cpu memory\n");
        w(paths::RESOLV_CONF, "nameserver 127.0.0.53\n");
        w(paths::PASSWD, "root:x:0:0:root:/root:/bin/bash\n");
        std::fs::create_dir_all(paths.at("/run/systemd/system")).unwrap();
        std::fs::create_dir_all(paths.at(paths::ZONEINFO).join("Europe")).unwrap();
        std::fs::write(paths.at(paths::ZONEINFO).join("Europe/Berlin"), b"tz").unwrap();
        std::fs::write(paths.at(paths::ZONEINFO).join("UTC"), b"tz").unwrap();
        let shared = Rc::new(RefCell::new(Shared::default()));
        Self {
            runner: FakeRunner::new(dir.path(), shared.clone()),
            daemons: FakeDaemons::new(shared),
            probe: FakeProbe::default(),
            tty: ScriptedTty::default(),
            out: Vec::new(),
            err: Vec::new(),
            keys: crate::privd::update::keys::UpdateKeys::embedded(),
            json: true,
            paths,
            dir,
        }
    }

    /// Runs `hx-agent install` with `args` against this machine; returns the exit code.
    pub fn install(
        &mut self,
        args: super::InstallArgs,
        frames: Option<super::stdin::Frames>,
    ) -> u8 {
        self.out.clear();
        self.err.clear();
        let deps = super::Deps {
            paths: self.paths.clone(),
            runner: &mut self.runner,
            daemons: &mut self.daemons,
            probe: &self.probe,
            prompt: &mut self.tty,
            out: &mut self.out,
            err: &mut self.err,
            json: self.json,
            now: fixed_now,
            keys: self.keys.clone(),
            verifier_params: hx_crypto::PinParams {
                memory_kib: 64,
                iterations: 1,
                parallelism: 1,
            },
            euid: 0,
            timing: super::ctx::Timing {
                socket_wait: Duration::ZERO,
                apt_secs: 5,
            },
            stdin: super::StdinSource::Frames(frames),
        };
        super::run(args, deps)
    }

    /// The JSON lines of the last run's standard output.
    pub fn json_lines(&self) -> Vec<Value> {
        String::from_utf8_lossy(&self.out)
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    /// The last `result` line.
    pub fn result(&self) -> Value {
        self.json_lines()
            .into_iter()
            .rev()
            .find(|v| v["t"] == "result")
            .unwrap_or(Value::Null)
    }

    /// The state file.
    pub fn state(&self) -> Option<super::state::InstallState> {
        super::state::load(&self.paths.at(paths::STATE_FILE))
            .ok()
            .flatten()
    }

    /// The text of a file of the host.
    pub fn read(&self, abs: &str) -> Option<String> {
        std::fs::read_to_string(self.paths.at(abs)).ok()
    }
}

impl Default for Machine {
    fn default() -> Self {
        Self::new()
    }
}
