//! Live install progress: runs an [`InstallRun`] and shows the grouped rows, the log and the
//! end states (failed with Retry, connection lost, success).

use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::time::Duration;

use slint::ComponentHandle;

use super::progress::{Model, Row, RowState, Run, duration_text, long_duration};
use super::{App, model, post, spawn_ui, ss};
use crate::backend::{
    InstallEvent, InstallOutcome, InstallRequest, InstallRun, PairedInfo, Secret, ServerAddr,
    SetupRequest, group_of,
};
use crate::servers::{Lifecycle, short_key};
use crate::{Kv, ProgressVm, Screen, StageRowData};

/// Which path produced the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Kind {
    /// The SSH install.
    #[default]
    Ssh,
    /// The post-pairing setup of the one-liner path.
    Setup,
}

/// What is needed to start the same run again (kept in memory while this screen is open).
pub enum Retry {
    /// An SSH install.
    Ssh(InstallRequest),
    /// A setup over the paired connection.
    Setup(ServerAddr, PairedInfo, SetupRequest),
}

/// Progress state.
#[derive(Default)]
pub struct Ctx {
    pub model: Model,
    pub server_id: Option<String>,
    pub kind: Kind,
    pub retry: Option<Retry>,
    pub epoch: u64,
    pub cancel: Option<Arc<AtomicBool>>,
    pub username: String,
    pub preset: String,
    pub distro: String,
}

fn kv(k: &str, v: String) -> Kv {
    Kv {
        key: ss(k),
        value: ss(v),
    }
}

fn row_state(r: &Row) -> i32 {
    match r.state {
        RowState::Pending => 0,
        RowState::Running => 1,
        RowState::Done => 2,
        RowState::Failed => 3,
        RowState::Deferred => 4,
    }
}

/// Pushes the model to the view model.
pub fn push(app: &Rc<App>) {
    let ui = app.ui();
    let vm = ui.global::<ProgressVm>();
    let c = app.prog.borrow();
    let server = c.server_id.as_deref().and_then(|id| app.server(id));
    let addr = server.as_ref().map(|s| s.address()).unwrap_or_default();
    vm.set_server_name(ss(server
        .as_ref()
        .map(|s| s.name.clone())
        .unwrap_or_default()));
    vm.set_address(ss(&addr));
    let m = &c.model;
    vm.set_rows(model(
        m.rows
            .iter()
            .map(|r| StageRowData {
                title: ss(r.title),
                ids: ss(if r.state == RowState::Deferred {
                    format!("{} · set up later", r.ids)
                } else {
                    r.ids.clone()
                }),
                state: row_state(r),
                duration: ss(if r.state == RowState::Done && r.ms > 0 {
                    duration_text(r.ms)
                } else {
                    String::new()
                }),
                detail: ss(&r.detail),
                percent: r.percent,
            })
            .collect(),
    ));
    vm.set_log(ss(m.log_text()));
    match &m.image {
        Some((true, _)) => {
            vm.set_image_title(ss("Using prebuilt image (about 4 min)"));
            vm.set_image_text(ss(
                "The desktop image was downloaded and is only configured on the server.",
            ));
        }
        Some((false, reason)) => {
            vm.set_image_title(ss("Building on the server (about 12 minutes)"));
            vm.set_image_text(ss(if reason.is_empty() {
                "The server builds the desktop itself, which takes longer.".to_owned()
            } else {
                format!("The prebuilt image could not be used: {reason}. The server builds the desktop itself, which takes longer.")
            }));
        }
        None => {
            vm.set_image_title(ss(""));
            vm.set_image_text(ss(""));
        }
    }
    let stage_n = m.stage_text();
    match &m.run {
        Run::Running => {
            vm.set_state(0);
            vm.set_headline(ss(format!(
                "Installing on {}",
                server.as_ref().map(|s| s.host.clone()).unwrap_or_default()
            )));
            vm.set_badge(ss("Installing"));
            vm.set_badge_tone(4);
            vm.set_subline(ss(format!(
                "{stage_n}. If you close this window the install stops safely and resumes from where it stopped when you reconnect (Retry, or Add server again)."
            )));
        }
        Run::Failed(f) => {
            vm.set_state(1);
            vm.set_headline(ss("Install stopped"));
            vm.set_badge(ss("Failed"));
            vm.set_badge_tone(3);
            let title =
                group_of(&f.stage).map_or("The install", |g| crate::backend::GROUPS[g].title);
            vm.set_subline(ss(format!(
                "{stage_n} failed. Nothing is lost: Retry continues from this stage and skips the finished ones."
            )));
            vm.set_fail_title(ss(format!("{title} failed")));
            vm.set_fail_text(ss(format!(
                "{} (code {}, stage {}). {}",
                f.message,
                f.code,
                f.stage,
                if f.retryable {
                    "This is usually temporary."
                } else {
                    "This is not something a retry fixes. Copy the log and contact support."
                }
            )));
            vm.set_retryable(f.retryable && c.retry.is_some());
        }
        Run::Lost { stage } => {
            vm.set_state(2);
            vm.set_headline(ss("Connection to the server was lost"));
            vm.set_badge(ss("Disconnected"));
            vm.set_badge_tone(2);
            vm.set_subline(ss("Finished stages are kept on the server. Reconnect to carry on from where it stopped."));
            vm.set_fail_title(ss(format!(
                "The connection closed at {}",
                stage_n.to_lowercase()
            )));
            vm.set_fail_text(ss(format!(
                "The app cannot show progress until it reconnects (last stage: {stage}). Secrets are never saved, so Retry asks for the SSH password (or key passphrase) and the account password and PIN again."
            )));
        }
        Run::Done(o) => {
            vm.set_state(3);
            vm.set_headline(ss("Your desktop is ready"));
            vm.set_badge(ss("Done"));
            vm.set_badge_tone(1);
            vm.set_subline(ss(format!(
                "Installed in {} on {} (XFCE, {} preset).",
                long_duration(o.elapsed_secs.max(m.elapsed_secs())),
                if c.distro.is_empty() {
                    "your server".to_owned()
                } else {
                    c.distro.clone()
                },
                c.preset
            )));
            vm.set_summary(model(vec![
                kv("Server", addr.clone()),
                kv("Account", c.username.clone()),
                kv(
                    "Image path",
                    if o.image_path.is_empty() {
                        "Not reported".into()
                    } else {
                        o.image_path.clone()
                    },
                ),
                kv("Server identity", short_key(&o.server_key_hex)),
                kv("Backups", "Off (turn on later)".into()),
            ]));
            vm.set_good_to_know(ss(
                "If you lose this device, install the app on a new one and pair again with the account password. Keep the password somewhere safe.",
            ));
        }
    }
}

// ------------------------------------------------------------------------------- starting runs

/// Starts an SSH install for `server_id` and shows the progress screen.
pub fn start_ssh(app: &Rc<App>, server_id: String, req: InstallRequest) {
    {
        let mut c = app.prog.borrow_mut();
        c.model = Model::new();
        c.server_id = Some(server_id);
        c.kind = Kind::Ssh;
        c.username = req.options.username.clone();
        c.preset = if req.options.apps == "developer" {
            "developer".into()
        } else {
            "basic".into()
        };
        c.distro = distro_label(&req.options.distro);
        c.epoch += 1;
    }
    launch_ssh(app, req);
    app.go(Screen::Progress);
}

fn distro_label(id: &str) -> String {
    crate::wizard::DISTROS
        .iter()
        .find(|d| d.0 == id)
        .map_or(id.to_owned(), |d| d.1.to_owned())
}

fn launch_ssh(app: &Rc<App>, req: InstallRequest) {
    let (epoch, id) = {
        let mut c = app.prog.borrow_mut();
        c.model.restart();
        c.retry = Some(Retry::Ssh(req.duplicate()));
        (c.epoch, c.server_id.clone().unwrap_or_default())
    };
    push(app);
    let engine = app.be.install.clone();
    spawn_ui(
        app,
        async move { engine.install(req).await },
        move |a, r| {
            if a.prog.borrow().epoch != epoch {
                return;
            }
            match r {
                Ok(run) => attach(a, id, run, Kind::Ssh),
                Err(e) => {
                    a.prog.borrow_mut().model.apply(InstallEvent::Failed(
                        crate::backend::InstallFailure {
                            stage: "preflight".into(),
                            code: "CONNECT".into(),
                            message: e.to_string(),
                            retryable: true,
                        },
                    ));
                    push(a);
                }
            }
        },
    );
}

/// Follows a run that is already started.
pub fn attach(app: &Rc<App>, server_id: String, mut run: Box<dyn InstallRun>, kind: Kind) {
    let cancel = Arc::new(AtomicBool::new(false));
    let epoch = {
        let mut c = app.prog.borrow_mut();
        if c.server_id.as_deref() != Some(&server_id) || c.kind != kind {
            c.model = Model::new();
        }
        c.server_id = Some(server_id.clone());
        c.kind = kind;
        c.epoch += 1;
        c.cancel = Some(cancel.clone());
        c.epoch
    };
    push(app);
    app.go(Screen::Progress);
    app.rt.spawn(async move {
        while let Some(ev) = run.next_event().await {
            if cancel.load(SeqCst) {
                run.cancel();
                return;
            }
            let id = server_id.clone();
            post(move |a| on_event(a, &id, epoch, ev));
        }
    });
}

fn on_event(app: &Rc<App>, id: &str, epoch: u64, ev: InstallEvent) {
    {
        let c = app.prog.borrow();
        if c.epoch != epoch || c.server_id.as_deref() != Some(id) {
            return;
        }
    }
    let finished = match &ev {
        InstallEvent::Finished(o) => Some(o.clone()),
        _ => None,
    };
    let lost = matches!(ev, InstallEvent::ConnectionLost { .. });
    app.prog.borrow_mut().model.apply(ev);
    if lost {
        // Secrets are never kept across a lost connection.
        app.prog.borrow_mut().retry = None;
    }
    if let Some(o) = finished {
        finish(app, id, o);
        return;
    }
    push(app);
}

/// After the install ended: pair with the app's token (SSH path), pin the key, mark Ready.
fn finish(app: &Rc<App>, id: &str, o: InstallOutcome) {
    let kind = app.prog.borrow().kind;
    if kind == Kind::Setup {
        complete(app, id, &o);
        return;
    }
    let (token, epoch) = {
        let c = app.prog.borrow();
        let t = match &c.retry {
            Some(Retry::Ssh(r)) => r.pairing_token.expose().to_owned(),
            _ => String::new(),
        };
        (t, c.epoch)
    };
    let Some(server) = app.server(id) else { return };
    // The run is over; hold the model in "running" visuals until the pairing answers.
    app.prog.borrow_mut().model.run = Run::Running;
    push(app);
    pair_after_install(
        app,
        id.to_owned(),
        ServerAddr {
            host: server.host,
            port: o.port,
        },
        token,
        o,
        epoch,
        0,
    );
}

fn pair_after_install(
    app: &Rc<App>,
    id: String,
    addr: ServerAddr,
    token: String,
    o: InstallOutcome,
    epoch: u64,
    tries: u32,
) {
    let setup = app.be.setup.clone();
    let key = app.key.clone();
    let a2 = addr.clone();
    let t2 = token.clone();
    spawn_ui(
        app,
        async move { setup.pair(&a2, key, &Secret::new(t2)).await },
        move |a, r| {
            if a.prog.borrow().epoch != epoch {
                return;
            }
            match r {
                Ok(p)
                    if p.server_key_hex.eq_ignore_ascii_case(&o.server_key_hex)
                        || o.server_key_hex.is_empty() =>
                {
                    let mut oo = o.clone();
                    if oo.server_key_hex.is_empty() {
                        oo.server_key_hex = p.server_key_hex;
                    }
                    complete(a, &id, &oo);
                }
                Ok(_) => fail_pairing(
                    a,
                    "The server's identity does not match what the installer reported. The desktop was installed, but this app did not pair with it, because someone may be intercepting the connection.",
                    false,
                ),
                Err(crate::backend::SetupError::Unreachable)
                | Err(crate::backend::SetupError::PairingClosed)
                    if tries < 20 =>
                {
                    let (a3, id2) = (a.clone(), id.clone());
                    slint::Timer::single_shot(Duration::from_secs(2), move || {
                        pair_after_install(&a3, id2, addr, token, o, epoch, tries + 1);
                    });
                }
                Err(e) => fail_pairing(
                    a,
                    &format!(
                        "The install finished, but pairing this device failed: {e}. Add the server again with a pairing code from `hx-agent pairing code`."
                    ),
                    false,
                ),
            }
        },
    );
}

fn fail_pairing(app: &Rc<App>, msg: &str, retryable: bool) {
    app.prog
        .borrow_mut()
        .model
        .apply(InstallEvent::Failed(crate::backend::InstallFailure {
            stage: "pairing".into(),
            code: "PAIRING".into(),
            message: msg.into(),
            retryable,
        }));
    push(app);
}

fn complete(app: &Rc<App>, id: &str, o: &InstallOutcome) {
    {
        let mut st = app.store.borrow_mut();
        if let Some(s) = st.get(id).cloned() {
            let mut s = s;
            s.server_key = o.server_key_hex.to_ascii_lowercase();
            s.lifecycle = Lifecycle::Ready;
            if o.port != 0 {
                s.port = o.port;
            }
            let _ = st.upsert(s);
        }
    }
    {
        let mut c = app.prog.borrow_mut();
        c.retry = None;
        c.model.apply(InstallEvent::Finished(o.clone()));
    }
    push(app);
}

/// Retry from the failed stage, with the secrets still in memory.
fn retry(app: &Rc<App>) {
    let r = app.prog.borrow_mut().retry.take();
    match r {
        Some(Retry::Ssh(req)) => launch_ssh(app, req),
        Some(Retry::Setup(addr, paired, req)) => {
            let setup = app.be.setup.clone();
            let key = app.key.clone();
            let (epoch, id) = {
                let mut c = app.prog.borrow_mut();
                c.model.restart();
                c.retry = Some(Retry::Setup(addr.clone(), paired.clone(), req.duplicate()));
                (c.epoch, c.server_id.clone().unwrap_or_default())
            };
            push(app);
            spawn_ui(
                app,
                async move { setup.start_setup(&addr, key, &paired, req).await },
                move |a, r| {
                    if a.prog.borrow().epoch != epoch {
                        return;
                    }
                    if let Ok(run) = r {
                        attach(a, id, run, Kind::Setup);
                    }
                },
            );
        }
        None => reconnect(app),
    }
}

/// Keeps the run's secrets for "Retry" while this screen is open (setup path).
pub fn remember_setup(app: &Rc<App>, addr: ServerAddr, paired: PairedInfo, req: SetupRequest) {
    app.prog.borrow_mut().retry = Some(Retry::Setup(addr, paired, req));
}

/// "Reconnect and resume": back to the wizard with the choices kept and the secrets empty.
fn reconnect(app: &Rc<App>) {
    let id = app.prog.borrow().server_id.clone();
    if let Some(s) = id.and_then(|i| app.server(&i)) {
        super::wizard_ctl::open_resume(app, &s);
    } else {
        app.show_home();
    }
}

/// Home's "View progress" and "Finish setup".
pub fn open_for_server(app: &Rc<App>, id: &str) {
    let Some(s) = app.server(id) else { return };
    let have = app.prog.borrow().server_id.as_deref() == Some(id);
    if have {
        push(app);
        app.go(Screen::Progress);
        return;
    }
    match s.lifecycle {
        Lifecycle::SetupPending => super::wizard_ctl::open_finish_setup(app, &s),
        _ => {
            // The app was closed during the install: the connection is gone.
            {
                let mut c = app.prog.borrow_mut();
                c.model = Model::new();
                c.server_id = Some(id.to_owned());
                c.model.apply(InstallEvent::ConnectionLost {
                    stage: "unknown".into(),
                });
                c.retry = None;
            }
            push(app);
            app.go(Screen::Progress);
        }
    }
}

pub fn wire(app: &Rc<App>) {
    let ui = app.ui();
    let vm = ui.global::<ProgressVm>();
    let a = app.clone();
    vm.on_back(move || {
        if let Some(c) = &a.prog.borrow().cancel {
            let still_running = matches!(a.prog.borrow().model.run, Run::Running);
            if still_running {
                c.store(true, SeqCst);
            }
        }
        a.prog.borrow_mut().retry = None;
        a.show_home();
    });
    let a = app.clone();
    vm.on_retry(move || retry(&a));
    let a = app.clone();
    vm.on_reconnect(move || reconnect(&a));
    let a = app.clone();
    vm.on_copy_log(move || {
        let t = a.prog.borrow().model.log_text();
        a.set_clipboard(&t);
    });
    let a = app.clone();
    vm.on_open_desktop(move || {
        let id = a.prog.borrow().server_id.clone();
        if let Some(id) = id {
            a.prog.borrow_mut().retry = None;
            super::connect_ctl::open(&a, &id);
        }
    });
    let a = app.clone();
    vm.on_details(move || {
        let id = a.prog.borrow().server_id.clone();
        if let Some(id) = id {
            super::details_ctl::open(&a, &id);
        }
    });
}
