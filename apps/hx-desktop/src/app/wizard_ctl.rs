//! The Add server wizard: the controller around [`crate::wizard::Wizard`].

use std::rc::Rc;
use std::time::Duration;

use slint::ComponentHandle;

use super::known_hosts::Known;
use super::{App, model, spawn_ui, ss};
use crate::backend::{
    CheckStatus, EngineError, HostKey, InstallRequest, Preflight, Secret, ServerAddr, SetupError, SshAuth, SshTarget,
};
use crate::servers::{Lifecycle, Server, new_id};
use crate::wizard::{AuthMode, ConnPhase, DISTROS, Method, Step, Wizard, password_strength};
use crate::{CheckData, Kv, Screen, StepData, WizardVm};

/// Wizard runtime state beyond the pure machine.
#[derive(Default)]
pub struct Ctx {
    pub w: Wizard,
    /// Bumped to drop the answers of cancelled work.
    pub epoch: u64,
    /// The one-liner token (shown in the UI, so not secret from the user).
    pub token: Option<String>,
    /// Since when the agent has not answered (one-liner waiting).
    pub unreachable_since: Option<std::time::Instant>,
    /// The server entry created for this wizard run.
    pub server_id: Option<String>,
    /// Finishing the setup of a server that is already paired (no Method or Server step).
    pub existing: Option<String>,
}

/// Opens the wizard (at the pairing-code step when `code` is true).
pub fn open(app: &Rc<App>, code: bool) {
    {
        let mut c = app.wiz.borrow_mut();
        c.epoch += 1;
        let epoch = c.epoch;
        *c = Ctx { epoch, ..Ctx::default() };
        if code {
            c.w.set_method(Method::Code);
            c.w.step = Step::PairingCode;
        }
    }
    let ui = app.ui();
    ui.global::<WizardVm>().set_keys(model(key_choices()));
    push_all(app);
    app.go(Screen::Wizard);
}

/// "Reconnect and resume" after a lost SSH connection: the same server, secrets asked again.
pub fn open_resume(app: &Rc<App>, server: &Server) {
    open(app, false);
    {
        let mut c = app.wiz.borrow_mut();
        c.server_id = Some(server.id.clone());
        c.w.address = server.host.clone();
        c.w.step = Step::Connection;
    }
    let vm = app.ui().global::<WizardVm>();
    vm.set_address(ss(&server.host));
    push_all(app);
}

/// "Finish setup" for a server paired through the one-liner: password, PIN and options, then
/// the setup over the paired connection.
pub fn open_finish_setup(app: &Rc<App>, server: &Server) {
    open(app, false);
    {
        let mut c = app.wiz.borrow_mut();
        c.w.set_method(Method::OneLiner);
        c.w.address = server.host.clone();
        c.w.agent_port = server.port.to_string();
        c.w.step = Step::Desktop;
        c.existing = Some(server.id.clone());
        c.server_id = Some(server.id.clone());
    }
    let vm = app.ui().global::<WizardVm>();
    vm.set_address(ss(&server.host));
    vm.set_agent_port(ss(server.port.to_string()));
    push_all(app);
}

/// "Default keys ..." plus the private keys found in `~/.ssh`.
fn key_choices() -> Vec<slint::SharedString> {
    let mut v = vec![ss("Default keys from ~/.ssh and the SSH agent")];
    if let Some(home) = std::env::var_os("HOME") {
        let dir = std::path::Path::new(&home).join(".ssh");
        if let Ok(rd) = std::fs::read_dir(dir) {
            let mut names: Vec<String> = rd
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.starts_with("id_") && !n.ends_with(".pub"))
                .collect();
            names.sort();
            v.extend(names.into_iter().map(|n| ss(format!("~/.ssh/{n}"))));
        }
    }
    v
}

fn pull(app: &Rc<App>) {
    let ui = app.ui();
    let vm = ui.global::<WizardVm>();
    let mut c = app.wiz.borrow_mut();
    let w = &mut c.w;
    w.address = vm.get_address().trim().to_owned();
    w.ssh_port = vm.get_ssh_port().to_string();
    w.ssh_user = vm.get_ssh_user().to_string();
    w.auth_mode = if vm.get_auth_mode() == 1 { AuthMode::Password } else { AuthMode::Key };
    w.key_index = vm.get_key_index().max(0) as usize;
    w.ssh_password = vm.get_ssh_password().to_string();
    w.distro = vm.get_distro().clamp(0, 3) as usize;
    w.developer = vm.get_developer();
    w.docker = vm.get_docker();
    w.docker_ack = vm.get_docker_ack();
    w.username = vm.get_username().to_string();
    w.password = vm.get_password().to_string();
    w.password2 = vm.get_password2().to_string();
    w.pin = vm.get_pin().to_string();
    w.pin2 = vm.get_pin2().to_string();
    w.cpu = vm.get_cpu().max(1) as u32;
    w.memory_gb = vm.get_memory().max(1) as u32;
    w.disk_gb = vm.get_disk().max(1) as u32;
    w.agent_port = vm.get_agent_port().to_string();
    w.domain = vm.get_domain().to_string();
    w.code = crate::wizard::normalize_code(&vm.get_code());
}

fn err_for(w: &Wizard, field: &str) -> slint::SharedString {
    if !w.show_errors {
        return ss("");
    }
    w.problems()
        .into_iter()
        .find(|(f, _)| *f == field)
        .map_or_else(|| ss(""), |(_, e)| ss(e))
}

fn heading(w: &Wizard) -> (&'static str, &'static str) {
    match w.step {
        Step::Method => ("How do you want to set up the server?", "You can add more servers later."),
        Step::Connection => match w.conn {
            ConnPhase::ChecksOk => ("Server checks", "The server meets the minimum. Nothing was changed on it yet."),
            ConnPhase::ChecksBad => ("Server checks", "This server cannot run hash-xcreen yet."),
            _ => (
                "Connect to the server",
                "The app needs SSH access once, to install. Nothing from this step is kept after the install.",
            ),
        },
        Step::Server => (
            "Where is the server?",
            "No SSH from this app. The server needs to be reachable on the address and port below once the agent is installed.",
        ),
        Step::PairingCode => (
            "Enter pairing code",
            "On the server, install.sh --interactive printed a code and the server's addresses. A new code: hx-agent pairing code.",
        ),
        Step::Desktop => (
            "Choose the desktop",
            "These are fixed once the desktop is built. You can change the resource limits and Docker later.",
        ),
        Step::Account => (
            "Account",
            "This is the Linux account inside your desktop. The password signs you in, locks the screen and authorises sudo. The PIN is what you type to connect.",
        ),
        Step::Backups => ("Backups", "Backups arrive in a later release."),
        Step::Resources => (
            "Resources",
            "How much of the server the desktop may use. The sliders stop at what this server has.",
        ),
        Step::Review => ("Review", "Check everything before the install starts. It takes about 12 minutes."),
        Step::RunOnServer => (
            "Run on the server",
            "Open a root shell on the server and run the command. The installer checks the server, installs the agent and opens the port, then asks for the token.",
        ),
    }
}

fn next_label(w: &Wizard, existing: bool) -> &'static str {
    match (w.step, &w.conn, w.method) {
        (Step::Connection, ConnPhase::ChecksOk, _) => "Next",
        (Step::Connection, ConnPhase::ChecksBad, _) => "Check again",
        (Step::Connection, _, _) => "Check server",
        (Step::PairingCode, _, _) => "Pair",
        (Step::Review, _, Method::OneLiner) if existing => "Finish setup",
        (Step::Review, _, Method::OneLiner) => "Show command",
        (Step::Review, _, _) => "Install",
        _ => "Next",
    }
}

/// Pushes the whole machine state to the view model.
pub fn push_all(app: &Rc<App>) {
    let ui = app.ui();
    let vm = ui.global::<WizardVm>();
    let c = app.wiz.borrow();
    let w = &c.w;
    let list = crate::wizard::steps(w.method);
    let cur = w.index();
    // The step list of the SSH path names the second step "Connection"; Method is step 1.
    let steps: Vec<StepData> = if w.step == Step::PairingCode || w.method == Method::Code {
        vec![
            StepData { title: ss("Method"), number: 1, current: false, done: true },
            StepData { title: ss("Pairing code"), number: 2, current: true, done: false },
        ]
    } else {
        list.iter()
            .enumerate()
            .map(|(i, s)| StepData { title: ss(s.title()), number: i as i32 + 1, current: i == cur, done: i < cur })
            .collect()
    };
    vm.set_steps(model(steps));
    vm.set_step(ss(match w.step {
        Step::Method => "method",
        Step::Connection => "connection",
        Step::Server => "server",
        Step::PairingCode => "code",
        Step::Desktop => "desktop",
        Step::Account => "account",
        Step::Backups => "backups",
        Step::Resources => "resources",
        Step::Review => "review",
        Step::RunOnServer => "run",
    }));
    let (h, s) = heading(w);
    vm.set_heading(ss(h));
    vm.set_subheading(ss(s));
    vm.set_next_label(ss(next_label(w, c.existing.is_some())));
    vm.set_next_enabled(match w.step {
        Step::Connection => matches!(w.conn, ConnPhase::Form | ConnPhase::Error(_) | ConnPhase::ChecksOk | ConnPhase::ChecksBad),
        Step::PairingCode => !vm.get_pairing(),
        _ => true,
    });
    vm.set_show_back(w.step != Step::Method);
    vm.set_method(match w.method {
        Method::Ssh => 0,
        Method::OneLiner => 1,
        Method::Code => 2,
    });
    // errors
    for (f, setter) in [("address", 0), ("ssh_port", 1), ("ssh_user", 2), ("ssh_password", 3)] {
        let e = err_for(w, f);
        match setter {
            0 => vm.set_err_address(e),
            1 => vm.set_err_ssh_port(e),
            2 => vm.set_err_ssh_user(e),
            _ => vm.set_err_ssh_password(e),
        }
    }
    vm.set_err_docker_ack(err_for(w, "docker_ack"));
    vm.set_err_username(err_for(w, "username"));
    vm.set_err_password(err_for(w, "password"));
    vm.set_err_password2(err_for(w, "password2"));
    vm.set_err_pin(err_for(w, "pin"));
    vm.set_err_pin2(err_for(w, "pin2"));
    vm.set_err_agent_port(err_for(w, "agent_port"));
    vm.set_err_domain(err_for(w, "domain"));
    vm.set_err_code(err_for(w, "code"));
    // connection phase
    let (phase, algo, fp) = match &w.conn {
        ConnPhase::Form => (0, String::new(), String::new()),
        ConnPhase::Probing => (1, String::new(), String::new()),
        ConnPhase::HostKey { algorithm, fingerprint } => (2, algorithm.clone(), fingerprint.clone()),
        ConnPhase::Checking => (3, String::new(), String::new()),
        ConnPhase::ChecksOk => (4, String::new(), String::new()),
        ConnPhase::ChecksBad => (5, String::new(), String::new()),
        ConnPhase::Error(_) => (6, String::new(), String::new()),
    };
    vm.set_conn_phase(phase);
    vm.set_host_algo(ss(algo));
    vm.set_host_fp(ss(fp));
    match &w.conn {
        ConnPhase::Error(e) => {
            vm.set_banner_title(ss("Could not connect"));
            vm.set_banner_text(ss(e));
        }
        ConnPhase::ChecksBad => {
            let n = w.preflight.as_ref().map_or(0, Preflight::failures);
            vm.set_banner_title(ss(format!("{} not met", if n == 1 { "One requirement is".to_owned() } else { format!("{n} requirements are") })));
            vm.set_banner_text(ss(
                "The install stops here and nothing was changed on the server. Resize the server or pick another one, then check again.",
            ));
        }
        _ => {
            if w.method != Method::Code || vm.get_err_code().is_empty() {
                vm.set_banner_title(ss(""));
                vm.set_banner_text(ss(""));
            }
        }
    }
    if let Some(p) = &w.preflight {
        vm.set_connected_as(ss(&p.connected_as));
        vm.set_checks(model(
            p.rows
                .iter()
                .map(|r| CheckData {
                    title: ss(&r.title),
                    detail: ss(&r.detail),
                    status: match r.status {
                        CheckStatus::Pass => 0,
                        CheckStatus::Fail => 1,
                        CheckStatus::Unknown => 2,
                    },
                })
                .collect(),
        ));
    }
    // strength
    let (score, word) = password_strength(&w.password);
    vm.set_strength(i32::from(score));
    vm.set_strength_word(ss(word));
    // resources
    let (cpu, mem, disk) = w.limits();
    vm.set_cpu_max(cpu.1 as i32);
    vm.set_memory_max(mem.1 as i32);
    vm.set_disk_max(disk.1 as i32);
    if let Some(p) = &w.preflight {
        vm.set_cpu_hint(ss(format!("Server has {} cores. At least 1.", p.cpus)));
        vm.set_memory_hint(ss(format!(
            "Server has {:.1} GB. The rest stays reserved for the host. At least 1 GB.",
            p.memory_mib as f64 / 1024.0
        )));
        vm.set_disk_hint(ss(format!("{} GB free. At least 8 GB.", p.disk_free_gib)));
    } else {
        vm.set_cpu_hint(ss("At least 1 core."));
        vm.set_memory_hint(ss("At least 1 GB. The installer checks the server's memory."));
        vm.set_disk_hint(ss("At least 8 GB."));
    }
    if w.step == Step::Review {
        let kv = |k: &str, v: String| Kv { key: ss(k), value: ss(v) };
        let o = w.options();
        let mut server = vec![kv("Address", w.review_server())];
        if let Some((algo, fp)) = &w.trusted {
            server.push(kv("Host key", format!("{algo} {fp}")));
        } else if w.method == Method::OneLiner {
            server.push(kv("Method", "One-liner, paired through the agent".into()));
        }
        vm.set_review_server(model(server));
        vm.set_review_desktop(model(vec![
            kv("Distribution", DISTROS[w.distro.min(3)].1.into()),
            kv("Desktop", format!("XFCE, {} preset", if w.developer { "Developer" } else { "Basic" })),
            kv("Docker", if w.docker { "On (isolation warning accepted)".into() } else { "Off".into() }),
        ]));
        vm.set_review_account(model(vec![
            kv("Username", w.username.clone()),
            kv("Password", format!("{} ({} characters)", "•".repeat(w.password.chars().count().min(24)), w.password.chars().count())),
            kv("PIN", format!("{} ({} digits)", "•".repeat(w.pin.len().min(12)), w.pin.len())),
        ]));
        vm.set_review_backups(model(vec![kv("Schedule", "Off".into())]));
        vm.set_review_resources(model(vec![
            kv("Limits", format!("{} cores, {} GB memory, {} GB disk", o.cpu, o.memory_gb, o.disk_gb)),
            kv("Port", o.port.to_string()),
        ]));
    }
    if w.step == Step::RunOnServer {
        vm.set_command(ss(w.one_liner()));
        vm.set_token(ss(c.token.clone().unwrap_or_default()));
    }
}

fn target_of(w: &Wizard) -> SshTarget {
    SshTarget { host: w.address.clone(), port: w.ssh_port.trim().parse().unwrap_or(22) }
}

fn auth_of(w: &Wizard, keys: &[slint::SharedString]) -> SshAuth {
    let user = w.ssh_user.trim().to_owned();
    match w.auth_mode {
        AuthMode::Password => SshAuth::Password { user, password: Secret::new(w.ssh_password.clone()) },
        AuthMode::Key if w.key_index == 0 => SshAuth::DefaultKeys { user },
        AuthMode::Key => {
            let name = keys.get(w.key_index).map(|s| s.to_string()).unwrap_or_default();
            let path = name.replacen("~", &std::env::var("HOME").unwrap_or_default(), 1);
            SshAuth::KeyFile { user, path, passphrase: None }
        }
    }
}

fn engine_error_text(e: &EngineError) -> String {
    match e {
        EngineError::Unreachable(m) => format!("Cannot reach the server: {m}. Check the address and port, and that SSH is running."),
        EngineError::HostKeyChanged { .. } => "This server's SSH host key is different from the one you trusted before. This can mean the server was reinstalled, or that someone is intercepting the connection. Nothing was sent.".into(),
        EngineError::AuthFailed => "The server refused these credentials. Check the username and the key or password.".into(),
        EngineError::KeyPassphraseRequired => "This key needs a passphrase. Use a key without one, an SSH agent, or the password option.".into(),
        EngineError::Other(m) => crate::session::connect::sanitize(m),
    }
}

fn next(app: &Rc<App>) {
    pull(app);
    let step = app.wiz.borrow().w.step;
    match step {
        Step::Connection => {
            let phase = app.wiz.borrow().w.conn.clone();
            match phase {
                ConnPhase::ChecksOk => advance(app),
                ConnPhase::ChecksBad => start_checks(app),
                _ => start_probe(app),
            }
        }
        Step::PairingCode => start_code_pairing(app),
        Step::Review => {
            let m = app.wiz.borrow().w.method;
            match m {
                Method::Ssh => start_install(app),
                Method::OneLiner => {
                    let existing = app.wiz.borrow().existing.clone();
                    match existing {
                        Some(id) => finish_existing(app, &id),
                        None => {
                            advance(app);
                            start_one_liner(app);
                        }
                    }
                }
                Method::Code => {}
            }
        }
        _ => advance(app),
    }
}

fn advance(app: &Rc<App>) {
    {
        let mut c = app.wiz.borrow_mut();
        let _ = c.w.next();
    }
    push_all(app);
}

// ------------------------------------------------------------------------------- ssh connection

fn start_probe(app: &Rc<App>) {
    {
        let mut c = app.wiz.borrow_mut();
        if !c.w.problems().is_empty() {
            c.w.show_errors = true;
            drop(c);
            push_all(app);
            return;
        }
        c.w.show_errors = false;
        c.w.conn = ConnPhase::Probing;
        c.epoch += 1;
    }
    push_all(app);
    let (epoch, target) = {
        let c = app.wiz.borrow();
        (c.epoch, target_of(&c.w))
    };
    let engine = app.be.install.clone();
    let t = target.clone();
    spawn_ui(app, async move { engine.probe_host_key(&t).await }, move |a, r| {
        if a.wiz.borrow().epoch != epoch {
            return;
        }
        match r {
            Err(e) => set_conn_error(a, &e),
            Ok(hk) => {
                let known = a.hosts.borrow().check(&target.host, target.port, &hk.fingerprint);
                match known {
                    Known::Changed { .. } => set_conn_error(
                        a,
                        &EngineError::HostKeyChanged { expected: String::new(), actual: hk.fingerprint },
                    ),
                    Known::Same => {
                        a.wiz.borrow_mut().w.trusted = Some((hk.algorithm.clone(), hk.fingerprint.clone()));
                        start_checks(a);
                    }
                    Known::New => {
                        a.wiz.borrow_mut().w.conn = ConnPhase::HostKey { algorithm: hk.algorithm, fingerprint: hk.fingerprint };
                        push_all(a);
                    }
                }
            }
        }
    });
}

fn set_conn_error(app: &Rc<App>, e: &EngineError) {
    app.wiz.borrow_mut().w.conn = ConnPhase::Error(engine_error_text(e));
    push_all(app);
}

fn trust_host_key(app: &Rc<App>) {
    let (host, port, algo, fp) = {
        let c = app.wiz.borrow();
        let ConnPhase::HostKey { algorithm, fingerprint } = &c.w.conn else { return };
        let t = target_of(&c.w);
        (t.host, t.port, algorithm.clone(), fingerprint.clone())
    };
    app.hosts.borrow_mut().trust(&host, port, &fp);
    app.wiz.borrow_mut().w.trusted = Some((algo, fp));
    start_checks(app);
}

fn start_checks(app: &Rc<App>) {
    let (epoch, target, auth, trusted) = {
        let mut c = app.wiz.borrow_mut();
        let Some((algorithm, fingerprint)) = c.w.trusted.clone() else { return };
        c.w.conn = ConnPhase::Checking;
        c.epoch += 1;
        let keys = app.ui().global::<WizardVm>().get_keys();
        let keys: Vec<_> = super::to_vec(keys);
        (c.epoch, target_of(&c.w), auth_of(&c.w, &keys), HostKey { algorithm, fingerprint })
    };
    push_all(app);
    let engine = app.be.install.clone();
    spawn_ui(
        app,
        async move { engine.preflight(&target, &auth, &trusted).await },
        move |a, r| {
            if a.wiz.borrow().epoch != epoch {
                return;
            }
            match r {
                Err(e) => set_conn_error(a, &e),
                Ok(p) => {
                    {
                        let mut c = a.wiz.borrow_mut();
                        c.w.conn = if p.ok() { ConnPhase::ChecksOk } else { ConnPhase::ChecksBad };
                        c.w.preflight = Some(p);
                        c.w.clamp_resources();
                        let (cpu, mem, disk) = (c.w.cpu, c.w.memory_gb, c.w.disk_gb);
                        drop(c);
                        let vm = a.ui().global::<WizardVm>();
                        vm.set_cpu(cpu as i32);
                        vm.set_memory(mem as i32);
                        vm.set_disk(disk as i32);
                    }
                    push_all(a);
                }
            }
        },
    );
}

// ------------------------------------------------------------------------------- pairing code

fn start_code_pairing(app: &Rc<App>) {
    {
        let mut c = app.wiz.borrow_mut();
        if !c.w.problems().is_empty() {
            c.w.show_errors = true;
            drop(c);
            push_all(app);
            return;
        }
        c.epoch += 1;
    }
    let vm = app.ui().global::<WizardVm>();
    vm.set_pairing(true);
    vm.set_banner_title(ss(""));
    push_all(app);
    let (epoch, addr, code) = {
        let c = app.wiz.borrow();
        (
            c.epoch,
            ServerAddr { host: c.w.address.clone(), port: c.w.agent_port.trim().parse().unwrap_or(443) },
            c.w.code.clone(),
        )
    };
    let setup = app.be.setup.clone();
    let key = app.key.clone();
    let a2 = addr.clone();
    spawn_ui(
        app,
        async move { setup.pair(&a2, key, &Secret::new(code)).await },
        move |a, r| {
            if a.wiz.borrow().epoch != epoch {
                return;
            }
            let vm = a.ui().global::<WizardVm>();
            vm.set_pairing(false);
            match r {
                Ok(p) => {
                    let name = if p.server_name.is_empty() { addr.host.clone() } else { crate::session::connect::sanitize(&p.server_name) };
                    let s = Server {
                        id: new_id(),
                        name,
                        host: addr.host,
                        port: addr.port,
                        server_key: p.server_key_hex,
                        lifecycle: Lifecycle::Ready,
                        last_seen_unix: 0,
                        revoked_unix: 0,
                    };
                    let _ = a.store.borrow_mut().upsert(s);
                    a.wiz.borrow_mut().w.wipe_secrets();
                    a.show_home();
                }
                Err(e) => {
                    let (t, x) = match e {
                        SetupError::Unreachable => (
                            format!("Cannot reach {}", crate::servers::format_address(&addr.host, addr.port)),
                            "No answer. Check the address and port, and that the agent is running.".to_owned(),
                        ),
                        SetupError::PairingClosed | SetupError::PairingFailed => (
                            "That code did not work".to_owned(),
                            "It may have expired (15 minutes), been used, or typed wrong. After 3 wrong tries a code stops working. Run hx-agent pairing code on the server for a new one.".to_owned(),
                        ),
                        SetupError::Other(m) => ("Pairing failed".to_owned(), m),
                    };
                    vm.set_banner_title(ss(t));
                    vm.set_banner_text(ss(x));
                    push_all(a);
                }
            }
        },
    );
}

// ------------------------------------------------------------------------------- ssh install

fn start_install(app: &Rc<App>) {
    let (target, options, auth, host_key, password, pin) = {
        let c = app.wiz.borrow();
        let Some((algorithm, fingerprint)) = c.w.trusted.clone() else { return };
        let keys: Vec<_> = super::to_vec(app.ui().global::<WizardVm>().get_keys());
        (
            target_of(&c.w),
            c.w.options(),
            auth_of(&c.w, &keys),
            HostKey { algorithm, fingerprint },
            Secret::new(c.w.password.clone()),
            Secret::new(c.w.pin.clone()),
        )
    };
    let token = hx_crypto::PairingToken::generate().map(|t| t.to_text().to_string()).unwrap_or_default();
    let req = InstallRequest {
        target: target.clone(),
        auth,
        host_key,
        options,
        password,
        pin,
        pairing_token: Secret::new(token),
    };
    let reuse = app
        .wiz
        .borrow()
        .server_id
        .clone()
        .filter(|i| app.server(i).is_some_and(|s| s.lifecycle == Lifecycle::Installing));
    let id = reuse.unwrap_or_else(new_id);
    let server = Server {
        id: id.clone(),
        name: target.host.clone(),
        host: target.host.clone(),
        port: req.options.port,
        server_key: String::new(),
        lifecycle: Lifecycle::Installing,
        last_seen_unix: 0,
        revoked_unix: 0,
    };
    let _ = app.store.borrow_mut().upsert(server);
    {
        let mut c = app.wiz.borrow_mut();
        c.server_id = Some(id.clone());
        // Keep the non-secret choices for a "Reconnect and resume" later; the secrets go now.
        c.w.wipe_secrets();
    }
    super::progress_ctl::start_ssh(app, id, req);
}

// ------------------------------------------------------------------------------- one-liner

fn start_one_liner(app: &Rc<App>) {
    let token = hx_crypto::PairingToken::generate().map(|t| t.to_text().to_string()).unwrap_or_default();
    {
        let mut c = app.wiz.borrow_mut();
        c.token = Some(token);
        c.epoch += 1;
        c.unreachable_since = None;
    }
    let vm = app.ui().global::<WizardVm>();
    vm.set_run_phase(0);
    vm.set_run_status(ss("Waiting for the server… Looking for the agent. This starts as soon as the installer opens the port."));
    push_all(app);
    poll_agent(app);
}

fn poll_agent(app: &Rc<App>) {
    let (epoch, addr, token) = {
        let c = app.wiz.borrow();
        if c.w.step != Step::RunOnServer {
            return;
        }
        (
            c.epoch,
            ServerAddr { host: c.w.address.clone(), port: c.w.agent_port.trim().parse().unwrap_or(443) },
            c.token.clone().unwrap_or_default(),
        )
    };
    let setup = app.be.setup.clone();
    let key = app.key.clone();
    let a2 = addr.clone();
    spawn_ui(app, async move { setup.pair(&a2, key, &Secret::new(token)).await }, move |a, r| {
        if a.wiz.borrow().epoch != epoch {
            return;
        }
        let vm = a.ui().global::<WizardVm>();
        match r {
            Ok(p) => paired(a, addr, p),
            Err(SetupError::PairingFailed) => {
                vm.set_run_phase(1);
            }
            Err(e) => {
                // Not listening yet, or listening without a token yet: keep waiting. After two
                // minutes with no answer at all, say what a firewall might be doing.
                let since = {
                    let mut c = a.wiz.borrow_mut();
                    if matches!(e, SetupError::Unreachable) {
                        *c.unreachable_since.get_or_insert_with(std::time::Instant::now)
                    } else {
                        c.unreachable_since = None;
                        std::time::Instant::now()
                    }
                };
                if since.elapsed() > Duration::from_secs(120) {
                    vm.set_run_phase(2);
                    return;
                }
                let a3 = a.clone();
                slint::Timer::single_shot(Duration::from_secs(3), move || {
                    if a3.wiz.borrow().epoch == epoch {
                        poll_agent(&a3);
                    }
                });
            }
        }
    });
}

fn paired(app: &Rc<App>, addr: ServerAddr, p: crate::backend::PairedInfo) {
    let id = new_id();
    let server = Server {
        id: id.clone(),
        name: addr.host.clone(),
        host: addr.host.clone(),
        port: addr.port,
        server_key: p.server_key_hex.clone(),
        lifecycle: Lifecycle::SetupPending,
        last_seen_unix: 0,
        revoked_unix: 0,
    };
    let _ = app.store.borrow_mut().upsert(server);
    app.wiz.borrow_mut().server_id = Some(id.clone());
    begin_setup(app, id, addr, p);
}

/// "Finish setup" on an already paired server.
fn finish_existing(app: &Rc<App>, id: &str) {
    let Some(s) = app.server(id) else { return };
    let key = s.server_key.clone();
    let addr = ServerAddr { host: s.host.clone(), port: s.port };
    begin_setup(
        app,
        id.to_owned(),
        addr,
        crate::backend::PairedInfo { server_key_hex: key, server_name: s.name },
    );
}

fn begin_setup(app: &Rc<App>, id: String, addr: ServerAddr, p: crate::backend::PairedInfo) {
    let (req, epoch) = {
        let mut c = app.wiz.borrow_mut();
        let o = c.w.options();
        let r = crate::backend::SetupRequest {
            options: o,
            password: Secret::new(c.w.password.clone()),
            pin: Secret::new(c.w.pin.clone()),
        };
        c.w.wipe_secrets();
        (r, c.epoch)
    };
    let vm = app.ui().global::<WizardVm>();
    vm.set_run_phase(4);
    vm.set_run_status(ss(format!(
        "Connected to the agent at {}. Server identity pinned: {}. Sending the account password and PIN over the encrypted connection…",
        crate::servers::format_address(&addr.host, addr.port),
        crate::servers::short_key(&p.server_key_hex)
    )));
    {
        let mut pc = app.prog.borrow_mut();
        pc.username = req.options.username.clone();
        pc.preset = if req.options.apps == "developer" { "developer".into() } else { "basic".into() };
        pc.distro = crate::wizard::DISTROS
            .iter()
            .find(|d| d.0 == req.options.distro)
            .map_or(String::new(), |d| d.1.to_owned());
    }
    super::progress_ctl::remember_setup(app, addr.clone(), p.clone(), req.duplicate());
    let setup = app.be.setup.clone();
    let key = app.key.clone();
    let a2 = addr.clone();
    let p2 = p.clone();
    spawn_ui(app, async move { setup.start_setup(&a2, key, &p2, req).await }, move |a, r| {
        if a.wiz.borrow().epoch != epoch {
            return;
        }
        match r {
            Ok(run) => super::progress_ctl::attach(a, id, run, super::progress_ctl::Kind::Setup),
            Err(e) => {
                let vm = a.ui().global::<WizardVm>();
                vm.set_run_phase(3);
                vm.set_run_status(ss(format!("Setup could not start: {e}. The server stays on Home as Setup not finished.")));
            }
        }
    });
}

fn back(app: &Rc<App>) {
    pull(app);
    let left = {
        let mut c = app.wiz.borrow_mut();
        if c.existing.is_some() && c.w.step == Step::Desktop {
            drop(c);
            cancel(app);
            return;
        }
        if c.w.step == Step::Connection && !matches!(c.w.conn, ConnPhase::Form | ConnPhase::Error(_)) {
            // Leaving the checks: the form again, and nothing in flight counts any more.
            c.w.conn = ConnPhase::Form;
            c.epoch += 1;
        }
        if c.w.step == Step::RunOnServer {
            c.epoch += 1;
        }
        !c.w.back()
    };
    if left {
        cancel(app);
        return;
    }
    push_all(app);
}

fn cancel(app: &Rc<App>) {
    {
        let mut c = app.wiz.borrow_mut();
        c.epoch += 1;
        c.w.wipe_secrets();
        c.token = None;
    }
    app.show_home();
}

pub fn wire(app: &Rc<App>) {
    let ui = app.ui();
    let vm = ui.global::<WizardVm>();
    let a = app.clone();
    vm.on_set_method(move |m| {
        let method = match m {
            1 => Method::OneLiner,
            2 => Method::Code,
            _ => Method::Ssh,
        };
        a.wiz.borrow_mut().w.set_method(method);
        push_all(&a);
    });
    let a = app.clone();
    vm.on_changed(move || {
        pull(&a);
        push_all(&a);
    });
    let a = app.clone();
    vm.on_next(move || next(&a));
    let a = app.clone();
    vm.on_back(move || back(&a));
    let a = app.clone();
    vm.on_cancel(move || cancel(&a));
    let a = app.clone();
    vm.on_edit(move |s| {
        let step = match s.as_str() {
            "connection" => Step::Connection,
            "server" => Step::Server,
            "desktop" => Step::Desktop,
            "account" => Step::Account,
            "backups" => Step::Backups,
            "resources" => Step::Resources,
            _ => return,
        };
        a.wiz.borrow_mut().w.edit(step);
        push_all(&a);
    });
    let a = app.clone();
    vm.on_trust_host_key(move || trust_host_key(&a));
    let a = app.clone();
    vm.on_cancel_host_key(move || {
        a.wiz.borrow_mut().w.conn = ConnPhase::Form;
        a.wiz.borrow_mut().epoch += 1;
        push_all(&a);
    });
    let a = app.clone();
    vm.on_check_again(move || start_checks(&a));
    let a = app.clone();
    vm.on_copy_command(move || {
        let c = a.wiz.borrow().w.one_liner();
        a.set_clipboard(&c);
        a.ui().global::<WizardVm>().set_copied_note(ss("Copied"));
    });
    let a = app.clone();
    vm.on_copy_token(move || {
        let t = a.wiz.borrow().token.clone().unwrap_or_default();
        a.set_clipboard(&t);
        a.ui().global::<WizardVm>().set_copied_note(ss("Copied"));
    });
    let a = app.clone();
    vm.on_new_token(move || start_one_liner(&a));
    let a = app.clone();
    vm.on_try_again(move || {
        a.wiz.borrow_mut().unreachable_since = None;
        let vm = a.ui().global::<WizardVm>();
        vm.set_run_phase(0);
        poll_agent(&a);
    });
    let a = app.clone();
    vm.on_continue_to_progress(move || {
        let id = a.wiz.borrow().server_id.clone();
        if let Some(id) = id {
            super::progress_ctl::open_for_server(&a, &id);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_follow_the_step_and_the_check_state() {
        let mut w = Wizard::new();
        w.step = Step::Connection;
        assert_eq!(next_label(&w, false), "Check server");
        w.conn = ConnPhase::ChecksBad;
        assert_eq!(next_label(&w, false), "Check again");
        w.conn = ConnPhase::ChecksOk;
        assert_eq!(next_label(&w, false), "Next");
        w.step = Step::Review;
        assert_eq!(next_label(&w, false), "Install");
        w.set_method(Method::OneLiner);
        assert_eq!(next_label(&w, false), "Show command");
        assert_eq!(next_label(&w, true), "Finish setup");
    }

    #[test]
    fn engine_errors_have_plain_sentences() {
        assert!(engine_error_text(&EngineError::AuthFailed).contains("refused"));
        assert!(engine_error_text(&EngineError::HostKeyChanged { expected: "a".into(), actual: "b".into() }).contains("different"));
        assert!(engine_error_text(&EngineError::Unreachable("x".into())).contains("Cannot reach"));
    }
}
