//! The Add server wizard as a state machine: steps, validation, the one-liner command and the
//! options handed to the engines. Pure logic, no UI and no I/O, so it is unit tested.
//!
//! Paths (design/mockups/add-server-*.html):
//! * SSH: Method, Connection, Desktop, Account, Backups, Resources, Review, then progress.
//! * One-liner: Method, Server, Desktop, Account, Backups, Resources, Review, Run on server.
//! * Pairing code: Method, Pairing code.
//!
//! "Restore from backup" is Phase 2 and not offered. Backups in Phase 1 is a fixed "Off".

use crate::backend::{InstallOptions, Preflight};
use zeroize::Zeroize;

/// How the server is set up.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Method {
    /// The app installs over SSH.
    #[default]
    Ssh,
    /// The user pastes a command on the server.
    OneLiner,
    /// The server was installed with `--interactive` and printed a code.
    Code,
}

/// A wizard step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Step {
    /// 1: choose the method.
    Method,
    /// 2 (SSH): connection details, host key and checks.
    Connection,
    /// 2 (one-liner): the server address and port.
    Server,
    /// 2 (code): address, port and the code.
    PairingCode,
    /// 3: distro, desktop, preset, Docker.
    Desktop,
    /// 4: account.
    Account,
    /// 5: backups (Phase 1: fixed Off).
    Backups,
    /// 6: resources.
    Resources,
    /// 7: review.
    Review,
    /// 8 (one-liner): command, token, waiting, paired.
    RunOnServer,
}

impl Step {
    /// Title shown in the step list.
    pub fn title(self) -> &'static str {
        match self {
            Self::Method => "Method",
            Self::Connection => "Connection",
            Self::Server => "Server",
            Self::PairingCode => "Pairing code",
            Self::Desktop => "Desktop",
            Self::Account => "Account",
            Self::Backups => "Backups",
            Self::Resources => "Resources",
            Self::Review => "Review",
            Self::RunOnServer => "Run on server",
        }
    }
}

/// The steps of a method, in order.
pub fn steps(m: Method) -> &'static [Step] {
    match m {
        Method::Ssh => &[
            Step::Method,
            Step::Connection,
            Step::Desktop,
            Step::Account,
            Step::Backups,
            Step::Resources,
            Step::Review,
        ],
        Method::OneLiner => &[
            Step::Method,
            Step::Server,
            Step::Desktop,
            Step::Account,
            Step::Backups,
            Step::Resources,
            Step::Review,
            Step::RunOnServer,
        ],
        Method::Code => &[Step::Method, Step::PairingCode],
    }
}

/// SSH authentication choice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuthMode {
    /// A key file.
    #[default]
    Key,
    /// A password.
    Password,
}

/// Where the SSH check is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnPhase {
    /// Entering details.
    Form,
    /// Probing the host key.
    Probing,
    /// Waiting for the user to trust this fingerprint.
    HostKey {
        /// Algorithm.
        algorithm: String,
        /// `SHA256:...`
        fingerprint: String,
    },
    /// Authenticating and running checks.
    Checking,
    /// The checks passed.
    ChecksOk,
    /// A requirement is not met: Next stays disabled.
    ChecksBad,
    /// The connection or login failed, with the sentence to show.
    Error(String),
}

/// What the user chose and typed. Secrets live here only until the install starts.
#[derive(Debug)]
pub struct Wizard {
    /// Method.
    pub method: Method,
    /// Current step.
    pub step: Step,
    /// Set by "Edit" on Review: after the edited step, go straight back to Review.
    pub return_to_review: bool,
    /// Server address (SSH, one-liner and code paths).
    pub address: String,
    /// SSH port text.
    pub ssh_port: String,
    /// SSH username.
    pub ssh_user: String,
    /// Key or password.
    pub auth_mode: AuthMode,
    /// Selected key in the key list.
    pub key_index: usize,
    /// SSH password (cleared when the install starts).
    pub ssh_password: String,
    /// SSH progress.
    pub conn: ConnPhase,
    /// The fingerprint the user trusted.
    pub trusted: Option<(String, String)>,
    /// Result of the checks.
    pub preflight: Option<Preflight>,
    /// Distro index into [`DISTROS`].
    pub distro: usize,
    /// `basic` or `developer`.
    pub developer: bool,
    /// Docker switch.
    pub docker: bool,
    /// Docker isolation acknowledged.
    pub docker_ack: bool,
    /// Linux username.
    pub username: String,
    /// Linux password.
    pub password: String,
    /// Confirmation.
    pub password2: String,
    /// PIN.
    pub pin: String,
    /// PIN confirmation.
    pub pin2: String,
    /// Resource sliders.
    pub cpu: u32,
    /// GiB.
    pub memory_gb: u32,
    /// GiB.
    pub disk_gb: u32,
    /// Agent port text.
    pub agent_port: String,
    /// Domain (optional).
    pub domain: String,
    /// Pairing code text.
    pub code: String,
    /// Which fields were touched, for "errors show on blur and on Next".
    pub show_errors: bool,
}

/// The distributions the installer supports: (id, label, tag).
pub const DISTROS: [(&str, &str, &str); 4] = [
    ("ubuntu-24.04", "Ubuntu 24.04 LTS", "Recommended"),
    ("ubuntu-26.04", "Ubuntu 26.04", "Newest"),
    ("debian-12", "Debian 12", "Stable"),
    ("debian-13", "Debian 13", "Current stable"),
];

impl Default for Wizard {
    fn default() -> Self {
        Self::new()
    }
}

impl Wizard {
    /// A fresh wizard at the Method step.
    pub fn new() -> Self {
        Self {
            method: Method::Ssh,
            step: Step::Method,
            return_to_review: false,
            address: String::new(),
            ssh_port: "22".into(),
            ssh_user: "root".into(),
            auth_mode: AuthMode::Key,
            key_index: 0,
            ssh_password: String::new(),
            conn: ConnPhase::Form,
            trusted: None,
            preflight: None,
            distro: 0,
            developer: true,
            docker: false,
            docker_ack: false,
            username: String::new(),
            password: String::new(),
            password2: String::new(),
            pin: String::new(),
            pin2: String::new(),
            cpu: 2,
            memory_gb: 4,
            disk_gb: 30,
            agent_port: "443".into(),
            domain: String::new(),
            code: String::new(),
            show_errors: false,
        }
    }

    /// Chooses the method (before leaving the first step).
    pub fn set_method(&mut self, m: Method) {
        self.method = m;
    }

    /// Index of the current step among the steps of the method.
    pub fn index(&self) -> usize {
        steps(self.method)
            .iter()
            .position(|s| *s == self.step)
            .unwrap_or(0)
    }

    /// Slider limits from the checks: (cpu max, memory max GiB, disk max GiB). Before the checks
    /// (one-liner path) generous defaults apply.
    pub fn limits(&self) -> ((u32, u32), (u32, u32), (u32, u32)) {
        match &self.preflight {
            Some(p) => {
                let cpu = p.cpus.max(1);
                let mem_mib = p.memory_mib;
                let reserve = 1536u64.max(mem_mib / 4);
                let mem = (mem_mib.saturating_sub(reserve) / 1024).max(1) as u32;
                let disk = (p.disk_free_gib as u32).max(8);
                ((1, cpu), (1, mem), (8, disk))
            }
            None => ((1, 16), (1, 64), (8, 500)),
        }
    }

    /// Clamps the sliders into the limits (after the checks changed them).
    pub fn clamp_resources(&mut self) {
        let (c, m, d) = self.limits();
        self.cpu = self.cpu.clamp(c.0, c.1);
        self.memory_gb = self.memory_gb.clamp(m.0, m.1);
        self.disk_gb = self.disk_gb.clamp(d.0, d.1);
    }

    // ------------------------------------------------------------------ validation of each step

    /// The error of the current step's fields, per field, in display order. Empty when valid.
    pub fn problems(&self) -> Vec<(&'static str, String)> {
        let mut v = Vec::new();
        let mut add = |f: &'static str, r: Result<(), String>| {
            if let Err(e) = r {
                v.push((f, e));
            }
        };
        match self.step {
            Step::Method | Step::Backups | Step::Review | Step::RunOnServer => {}
            Step::Connection => {
                add("address", host_problem(&self.address));
                add("ssh_port", port_problem(&self.ssh_port, true));
                add("ssh_user", ssh_user_problem(&self.ssh_user));
                if self.auth_mode == AuthMode::Password && self.ssh_password.is_empty() {
                    add("ssh_password", Err("Enter the SSH password.".into()));
                }
            }
            Step::Server => {
                add("address", host_problem(&self.address));
                add("agent_port", port_problem(&self.agent_port, false));
            }
            Step::PairingCode => {
                add("address", host_problem(&self.address));
                add("agent_port", port_problem(&self.agent_port, false));
                add("code", code_problem(&self.code));
            }
            Step::Desktop => {
                if self.docker && !self.docker_ack {
                    add(
                        "docker_ack",
                        Err("Tick the box to confirm you understand.".into()),
                    );
                }
            }
            Step::Account => {
                add("username", username_problem(&self.username));
                add("password", password_problem(&self.password));
                add(
                    "password2",
                    confirm_problem(&self.password, &self.password2, "passwords"),
                );
                add("pin", pin_problem(&self.pin));
                add("pin2", confirm_problem(&self.pin, &self.pin2, "PINs"));
            }
            Step::Resources => {
                add("agent_port", port_problem(&self.agent_port, false));
                add("domain", domain_problem(&self.domain));
            }
        }
        v
    }

    /// Whether Next is enabled. On the checks screens it follows the check result.
    pub fn can_next(&self) -> bool {
        if self.step == Step::Connection {
            return self.conn == ConnPhase::ChecksOk;
        }
        self.problems().is_empty()
    }

    /// Goes forward. Returns false (and turns error display on) if the step is not valid.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> bool {
        if self.step == Step::Connection {
            // The SSH step advances only through `ChecksOk`.
            if self.conn != ConnPhase::ChecksOk {
                self.show_errors = true;
                return false;
            }
        } else if !self.problems().is_empty() {
            self.show_errors = true;
            return false;
        }
        self.show_errors = false;
        if self.return_to_review && self.step != Step::Review && self.step != Step::Method {
            self.step = Step::Review;
            self.return_to_review = false;
            return true;
        }
        let list = steps(self.method);
        if let Some(n) = list.get(self.index() + 1) {
            self.step = *n;
            if *n == Step::Resources {
                self.clamp_resources();
            }
            true
        } else {
            false
        }
    }

    /// Goes back one step (or to the Review step if it came from "Edit").
    pub fn back(&mut self) -> bool {
        self.show_errors = false;
        if self.return_to_review {
            self.return_to_review = false;
            self.step = Step::Review;
            return true;
        }
        let i = self.index();
        if i == 0 {
            return false;
        }
        self.step = steps(self.method)[i - 1];
        true
    }

    /// "Edit" on the Review step: jump to `step` and return to Review afterwards.
    pub fn edit(&mut self, step: Step) {
        if steps(self.method).contains(&step) {
            self.step = step;
            self.return_to_review = true;
        }
    }

    /// The step of the one-liner address and the SSH connection are the same screen family;
    /// this tells whether the wizard has anything to install (code path pairs only).
    pub fn installs(&self) -> bool {
        self.method != Method::Code
    }

    // ------------------------------------------------------------------ results for the engines

    /// The non-secret options.
    pub fn options(&self) -> InstallOptions {
        InstallOptions {
            distro: DISTROS[self.distro.min(DISTROS.len() - 1)].0.into(),
            desktop: "xfce".into(),
            apps: if self.developer { "developer" } else { "basic" }.into(),
            docker: self.docker,
            username: self.username.clone(),
            cpu: self.cpu,
            memory_gb: self.memory_gb,
            disk_gb: self.disk_gb,
            port: self.agent_port.trim().parse().unwrap_or(443),
            domain: self.domain.trim().to_owned(),
            backup: "off".into(),
        }
    }

    /// The one-liner shown in the app: no token, no secret (architecture 5.1).
    pub fn one_liner(&self) -> String {
        command_for(&self.options())
    }

    /// Sentence on the Review step for the server.
    pub fn review_server(&self) -> String {
        let port = match self.method {
            Method::Ssh => self.ssh_port.trim(),
            _ => self.agent_port.trim(),
        };
        let addr = crate::servers::format_address(self.address.trim(), port.parse().unwrap_or(0));
        match self.method {
            Method::Ssh => format!(
                "{addr} as {}, {}",
                self.ssh_user.trim(),
                if self.auth_mode == AuthMode::Key {
                    "SSH key"
                } else {
                    "SSH password"
                }
            ),
            _ => addr,
        }
    }

    /// Wipes every secret the wizard holds (after the install started or on cancel).
    pub fn wipe_secrets(&mut self) {
        for s in [
            &mut self.ssh_password,
            &mut self.password,
            &mut self.password2,
            &mut self.pin,
            &mut self.pin2,
        ] {
            // zeroize wipes the allocation with volatile writes the optimizer cannot drop.
            s.zeroize();
        }
    }
}

impl Drop for Wizard {
    fn drop(&mut self) {
        self.wipe_secrets();
    }
}

/// The non-secret command for the options (architecture 5.2).
pub fn command_for(o: &InstallOptions) -> String {
    let mut c = String::from(
        "curl -fsSL https://github.com/Omakidx/hash-xcreen/releases/download/channel-stable/install.sh | sudo sh -s -- --pair",
    );
    c.push_str(&format!(
        " --distro {} --desktop {} --apps {} --user {}",
        o.distro, o.desktop, o.apps, o.username
    ));
    if o.docker {
        c.push_str(" --docker");
    }
    c.push_str(&format!(
        " --cpu {} --memory {}G --disk {}G",
        o.cpu, o.memory_gb, o.disk_gb
    ));
    if o.port != 443 {
        c.push_str(&format!(" --port {}", o.port));
    }
    if !o.domain.is_empty() {
        c.push_str(&format!(" --domain {}", o.domain));
    }
    c.push_str(&format!(" --backup {}", o.backup));
    c
}

// ---------------------------------------------------------------------- field rules

/// Host name or IP address (no scheme, no port, no spaces).
pub fn host_problem(h: &str) -> Result<(), String> {
    let h = h.trim();
    let msg = "Enter the server's public IP address or host name.";
    if h.is_empty() || h.len() > 253 {
        return Err(msg.into());
    }
    if h.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    if h.split('.').all(label_ok) {
        Ok(())
    } else {
        Err(msg.into())
    }
}

/// 1..=65535; the agent port also must not be 22 or 80.
pub fn port_problem(p: &str, ssh: bool) -> Result<(), String> {
    match p.trim().parse::<u32>() {
        Ok(n) if (1..=65535).contains(&n) => {
            if !ssh && (n == 22 || n == 80) {
                Err("Not 22 or 80.".into())
            } else {
                Ok(())
            }
        }
        _ => Err("Enter a port from 1 to 65535.".into()),
    }
}

/// SSH user: non-empty, no whitespace or control characters.
pub fn ssh_user_problem(u: &str) -> Result<(), String> {
    let u = u.trim();
    if u.is_empty() || u.len() > 64 || u.chars().any(|c| c.is_whitespace() || c.is_control()) {
        Err("Enter the SSH username.".into())
    } else {
        Ok(())
    }
}

/// Linux username: lowercase letter first, then letters, digits, dash, underscore.
pub fn username_problem(u: &str) -> Result<(), String> {
    let ok = !u.is_empty()
        && u.len() <= 32
        && u.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && u.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err("Use lowercase letters, digits, dash or underscore, starting with a letter.".into())
    }
}

/// At least 8 characters (the meter is advisory only).
pub fn password_problem(p: &str) -> Result<(), String> {
    if p.chars().count() < 8 {
        Err("A password needs at least 8 characters.".into())
    } else {
        Ok(())
    }
}

/// A PIN is at least 6 digits (and at most 32).
pub fn pin_problem(p: &str) -> Result<(), String> {
    if p.len() > 32 || !p.chars().all(|c| c.is_ascii_digit()) {
        return Err("A PIN is digits only.".into());
    }
    if p.len() < 6 {
        return Err("A PIN needs at least 6 digits.".into());
    }
    Ok(())
}

/// The two entries must match.
pub fn confirm_problem(a: &str, b: &str, what: &str) -> Result<(), String> {
    if a == b {
        Ok(())
    } else {
        Err(format!("The {what} do not match."))
    }
}

/// An optional FQDN.
pub fn domain_problem(d: &str) -> Result<(), String> {
    let d = d.trim();
    if d.is_empty() {
        return Ok(());
    }
    if d.parse::<std::net::IpAddr>().is_ok() || !d.contains('.') {
        return Err("Enter a full domain name, for example desktop.example.com.".into());
    }
    host_problem(d).map_err(|_| "Enter a full domain name, for example desktop.example.com.".into())
}

/// Pairing code: eight characters, case and the dash do not matter.
pub fn code_problem(c: &str) -> Result<(), String> {
    let n: String = normalize_code(c)
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    if n.len() == 8 {
        Ok(())
    } else {
        Err("Check the code and try again.".into())
    }
}

/// `k7qm 4xd2` becomes `K7QM-4XD2`.
pub fn normalize_code(c: &str) -> String {
    let raw: String = c
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if raw.len() > 4 {
        format!("{}-{}", &raw[..4], &raw[4..])
    } else {
        raw
    }
}

/// Advisory strength 0..=4 and a word. Not a security check: the only rule is the length.
pub fn password_strength(p: &str) -> (u8, &'static str) {
    let len = p.chars().count();
    if len == 0 {
        return (0, "");
    }
    let classes = [
        p.chars().any(|c| c.is_ascii_lowercase()),
        p.chars().any(|c| c.is_ascii_uppercase()),
        p.chars().any(|c| c.is_ascii_digit()),
        p.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    let distinct = p.chars().collect::<std::collections::HashSet<_>>().len();
    let common = ["password", "12345678", "qwertyui", "letmein1", "iloveyou"]
        .iter()
        .any(|w| p.to_ascii_lowercase().contains(w));
    let mut score = 0u8;
    if len >= 8 {
        score += 1;
    }
    if len >= 12 && distinct >= 8 {
        score += 1;
    }
    if classes >= 3 {
        score += 1;
    }
    if len >= 16 && distinct >= 10 {
        score += 1;
    }
    if common || distinct <= 3 {
        score = score.min(1);
    }
    let word = match score {
        0 | 1 => "weak",
        2 => "fair",
        3 => "good",
        _ => "strong",
    };
    (score, word)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_account(w: &mut Wizard) {
        w.username = "alex".into();
        w.password = "correct horse battery".into();
        w.password2 = w.password.clone();
        w.pin = "482913".into();
        w.pin2 = "482913".into();
    }

    #[test]
    fn ssh_path_walks_the_seven_steps_and_back() {
        let mut w = Wizard::new();
        assert_eq!(w.step, Step::Method);
        assert!(w.next());
        assert_eq!(w.step, Step::Connection);
        // The SSH step needs the checks, not just a filled form.
        w.address = "203.0.113.10".into();
        assert!(!w.next());
        w.conn = ConnPhase::ChecksOk;
        assert!(w.next());
        assert_eq!(w.step, Step::Desktop);
        assert!(w.next());
        assert_eq!(w.step, Step::Account);
        assert!(!w.next(), "empty account is not valid");
        assert!(w.show_errors);
        valid_account(&mut w);
        assert!(w.next());
        assert_eq!(w.step, Step::Backups);
        assert!(w.next() && w.step == Step::Resources);
        assert!(w.next() && w.step == Step::Review);
        assert!(!w.next(), "Install is not a wizard step");
        assert!(w.back() && w.step == Step::Resources);
    }

    #[test]
    fn one_liner_path_ends_on_run_on_server() {
        let mut w = Wizard::new();
        w.set_method(Method::OneLiner);
        w.next();
        assert_eq!(w.step, Step::Server);
        w.address = "203.0.113.142".into();
        assert!(w.next());
        assert_eq!(steps(Method::OneLiner).last(), Some(&Step::RunOnServer));
    }

    #[test]
    fn edit_from_review_returns_to_review() {
        let mut w = Wizard::new();
        w.step = Step::Review;
        w.edit(Step::Account);
        assert_eq!(w.step, Step::Account);
        valid_account(&mut w);
        assert!(w.next());
        assert_eq!(w.step, Step::Review);
        w.edit(Step::Desktop);
        assert!(w.back());
        assert_eq!(w.step, Step::Review);
    }

    #[test]
    fn docker_needs_the_explicit_tick() {
        let mut w = Wizard::new();
        w.step = Step::Desktop;
        w.docker = true;
        assert!(!w.can_next());
        w.docker_ack = true;
        assert!(w.can_next());
    }

    #[test]
    fn account_rules() {
        assert!(username_problem("alex").is_ok());
        for bad in ["", "Alex", "1alex", "a b", "al.ex", &"a".repeat(33)] {
            assert!(username_problem(bad).is_err(), "{bad}");
        }
        assert!(password_problem("1234567").is_err());
        assert!(password_problem("12345678").is_ok());
        assert!(
            confirm_problem("a", "b", "passwords")
                .unwrap_err()
                .contains("do not match")
        );
        assert!(pin_problem("12345").is_err());
        assert!(pin_problem("123456").is_ok());
        assert!(pin_problem("12345a").is_err());
    }

    #[test]
    fn weak_password_is_only_advisory() {
        // 8 characters, weak meter, still accepted: the meter never blocks.
        let (score, word) = password_strength("aaaaaaaa");
        assert!(score <= 1);
        assert_eq!(word, "weak");
        assert!(password_problem("aaaaaaaa").is_ok());
        assert_eq!(password_strength("correct-Horse-battery-9").1, "strong");
    }

    #[test]
    fn address_and_port_rules() {
        assert!(host_problem("203.0.113.10").is_ok());
        assert!(host_problem("::1").is_ok());
        assert!(host_problem("srv.example.com").is_ok());
        for bad in ["", "http://x", "a b", "x:443", "-a.com", "a..com"] {
            assert!(host_problem(bad).is_err(), "{bad}");
        }
        assert!(port_problem("22", true).is_ok());
        assert!(port_problem("22", false).is_err());
        assert!(port_problem("80", false).is_err());
        assert!(port_problem("0", false).is_err());
        assert!(port_problem("65536", false).is_err());
        assert!(port_problem("443", false).is_ok());
    }

    #[test]
    fn pairing_code_normalisation() {
        assert_eq!(normalize_code(" k7qm 4xd2 "), "K7QM-4XD2");
        assert_eq!(normalize_code("K7QM4XD2"), "K7QM-4XD2");
        assert!(code_problem("K7QM-4XD2").is_ok());
        assert!(code_problem("K7QM").is_err());
    }

    #[test]
    fn command_has_no_secret_and_matches_options() {
        let mut w = Wizard::new();
        valid_account(&mut w);
        w.docker = true;
        w.docker_ack = true;
        w.cpu = 3;
        w.memory_gb = 5;
        w.disk_gb = 60;
        let c = w.one_liner();
        assert!(
            c.contains("--pair --distro ubuntu-24.04 --desktop xfce --apps developer --user alex")
        );
        assert!(c.contains("--docker --cpu 3 --memory 5G --disk 60G"));
        assert!(c.ends_with("--backup off"));
        assert!(!c.contains("hxt1-"));
        assert!(!c.contains("482913"));
        assert!(!c.contains("correct horse"));
    }

    #[test]
    fn limits_follow_the_checks() {
        let mut w = Wizard::new();
        w.preflight = Some(Preflight {
            connected_as: String::new(),
            rows: vec![],
            cpus: 4,
            memory_mib: 7987,
            disk_free_gib: 152,
        });
        let (c, m, d) = w.limits();
        assert_eq!(c, (1, 4));
        // 7987 - max(1536, 1996) = 5991 MiB = 5 GiB
        assert_eq!(m, (1, 5));
        assert_eq!(d, (8, 152));
        w.cpu = 16;
        w.memory_gb = 64;
        w.clamp_resources();
        assert_eq!((w.cpu, w.memory_gb), (4, 5));
    }

    #[test]
    fn wipe_clears_every_secret() {
        let mut w = Wizard::new();
        valid_account(&mut w);
        w.ssh_password = "x".into();
        w.wipe_secrets();
        assert!(w.password.is_empty() && w.pin.is_empty() && w.ssh_password.is_empty());
    }
}
