//! Connect: the PIN screen around [`crate::session::ConnectMachine`].

use std::rc::Rc;
use std::time::Duration;

use slint::ComponentHandle;
use zeroize::Zeroizing;

use super::{App, desktop_ctl, spawn_ui, ss};
use crate::backend::{AdminContext, AdminError, Secret};
use crate::servers::Lifecycle;
use crate::session::connect::{Notice, wrong_pin_text};
use crate::session::{ConnectMachine, ConnectState, Link, Outcome};
use crate::{ConnectVm, Screen};

/// Connect state.
#[derive(Default)]
pub struct Ctx {
    pub server_id: Option<String>,
    pub machine: ConnectMachine,
    /// Bumped to drop the answers of cancelled attempts.
    pub epoch: u64,
    pub timer: Option<slint::Timer>,
    /// Name of the device that will be displaced (a takeover).
    pub takeover_of: Option<String>,
}

/// The link to a saved server, or `None` if it was never paired.
pub fn link_of(app: &App, id: &str) -> Option<Link> {
    let s = app.server(id)?;
    let key = crate::session::net::parse_key(&s.server_key)?;
    Some(Link {
        host: s.host,
        port: s.port,
        server_key: key,
        device: app.key.clone(),
        device_name: app.device_name(),
    })
}

/// Opens the PIN screen for a server (or the revoked state for a revoked one).
pub fn open(app: &Rc<App>, id: &str) {
    let Some(s) = app.server(id) else { return };
    {
        let mut c = app.conn.borrow_mut();
        c.epoch += 1;
        c.server_id = Some(id.to_owned());
        c.machine = ConnectMachine::new();
        c.timer = None;
        c.takeover_of = None;
    }
    let vm = app.ui().global::<ConnectVm>();
    vm.set_pin(ss(""));
    vm.set_password(ss(""));
    vm.set_show_pin(false);
    if s.lifecycle == Lifecycle::Revoked {
        app.conn.borrow_mut().machine.outcome(Outcome::Revoked);
    }
    show(app);
    app.go(Screen::Connect);
}

/// The Home card "Pair again": straight to the password form.
pub fn open_pair_again(app: &Rc<App>, id: &str) {
    open(app, id);
    app.conn.borrow_mut().machine.pair_again();
    show(app);
}

/// Opens the PIN screen to take a desktop back (the other device is told).
pub fn open_take_back(app: &Rc<App>, id: &str, other: &str) {
    open(app, id);
    app.conn.borrow_mut().takeover_of = Some(other.to_owned());
    show(app);
}

/// Pushes the machine state to the view model.
pub fn show(app: &Rc<App>) {
    let ui = app.ui();
    let vm = ui.global::<ConnectVm>();
    let c = app.conn.borrow();
    let server = c.server_id.as_deref().and_then(|i| app.server(i));
    vm.set_server_name(ss(server
        .as_ref()
        .map(|s| s.name.clone())
        .unwrap_or_default()));
    vm.set_address(ss(server.as_ref().map(|s| s.address()).unwrap_or_default()));
    vm.set_pinned_fp(ss(server
        .as_ref()
        .map(|s| s.short_fingerprint())
        .unwrap_or_default()));
    vm.set_presented_fp(ss(
        "not available: the connection was refused before the key could be read",
    ));
    vm.set_notice_title(ss(""));
    vm.set_notice_text(ss(""));
    vm.set_notice_tone(3);
    vm.set_wait_secs(0);
    vm.set_takeover_hint(ss(match &c.takeover_of {
        Some(n) if !n.is_empty() => {
            format!("Connecting takes the desktop over from {n}, which is disconnected.")
        }
        Some(_) => {
            "Connecting takes the desktop over from the other device, which is disconnected."
                .to_owned()
        }
        None => String::new(),
    }));
    let phase = match c.machine.state() {
        ConnectState::Entering(n) => {
            if let Some(Notice::Wrong { attempts_left }) = n {
                let (t, x) = wrong_pin_text(*attempts_left);
                vm.set_notice_title(ss(t));
                vm.set_notice_text(ss(x));
            }
            0
        }
        ConnectState::Connecting => 1,
        ConnectState::CheckingPin => 2,
        ConnectState::Waiting {
            secs,
            attempts_left,
        } => {
            vm.set_wait_secs(*secs as i32);
            vm.set_notice_title(ss(format!(
                "Wait {secs} second{} before trying again",
                if *secs == 1 { "" } else { "s" }
            )));
            vm.set_notice_text(ss(match attempts_left {
                Some(1) => "1 attempt left. Waiting does not use up an attempt.".to_owned(),
                Some(n) => format!("{n} attempts left. Waiting does not use up an attempt."),
                None => "Waiting does not use up an attempt.".to_owned(),
            }));
            vm.set_notice_tone(2);
            3
        }
        ConnectState::Revoked => 4,
        ConnectState::PairAgain => 5,
        ConnectState::NotAvailable { secs } => {
            vm.set_wait_secs(*secs as i32);
            6
        }
        ConnectState::Unreachable(_) => 7,
        ConnectState::IdentityChanged => 8,
        ConnectState::Connected => 0,
    };
    vm.set_phase(phase);
}

/// Starts or stops the one-second countdown depending on the state.
fn sync_timer(app: &Rc<App>) {
    let needs = matches!(
        app.conn.borrow().machine.state(),
        ConnectState::Waiting { .. } | ConnectState::NotAvailable { secs: 1.. }
    );
    let mut c = app.conn.borrow_mut();
    if !needs {
        c.timer = None;
        return;
    }
    if c.timer.is_some() {
        return;
    }
    let t = slint::Timer::default();
    let a = app.clone();
    t.start(
        slint::TimerMode::Repeated,
        Duration::from_secs(1),
        move || {
            let back = a.conn.borrow_mut().machine.tick_second();
            show(&a);
            if back {
                focus_pin(&a);
            }
            sync_timer(&a);
        },
    );
    c.timer = Some(t);
}

fn submit(app: &Rc<App>) {
    let vm = app.ui().global::<ConnectVm>();
    let pin = Zeroizing::new(vm.get_pin().to_string());
    if pin.is_empty() {
        return;
    }
    let (id, epoch) = {
        let mut c = app.conn.borrow_mut();
        if !c.machine.submit() {
            return;
        }
        c.epoch += 1;
        (c.server_id.clone().unwrap_or_default(), c.epoch)
    };
    vm.set_pin(ss(""));
    show(app);
    let Some(link) = link_of(app, &id) else {
        app.conn.borrow_mut().machine.outcome(Outcome::Failed(
            "This server was never paired with this device.".into(),
        ));
        show(app);
        return;
    };
    let prepared = desktop_ctl::prepare(app);
    let wiring = prepared.wiring(app);
    let connector = app.be.connector.clone();
    let l2 = link.clone();
    let p2 = pin.clone();
    let on_secure: Box<dyn FnOnce() + Send> = Box::new(move || {
        super::post(move |a| {
            if a.conn.borrow().epoch == epoch {
                a.conn.borrow_mut().machine.secure();
                show(a);
            }
        });
    });
    spawn_ui(
        app,
        async move { connector.connect(&l2, &p2, on_secure, wiring).await },
        move |a, r| {
            if a.conn.borrow().epoch != epoch {
                return;
            }
            match r {
                Ok(est) => {
                    a.conn.borrow_mut().machine.outcome(Outcome::Accepted);
                    let _ = a.store.borrow_mut().touch(&id, super::now_unix());
                    if let Some(v) = est.server_version {
                        let _ = a.store.borrow_mut().set_version(&id, v);
                    }
                    a.unavailable.borrow_mut().remove(&id);
                    desktop_ctl::enter(a, &id, link, est, prepared, pin);
                }
                Err(o) => {
                    drop(prepared);
                    if o == Outcome::Revoked {
                        let _ = a.store.borrow_mut().set_lifecycle(
                            &id,
                            Lifecycle::Revoked,
                            super::now_unix(),
                        );
                    }
                    if let Outcome::Unreachable(_) = o {
                        a.reachable.borrow_mut().insert(id.clone(), false);
                    }
                    a.conn.borrow_mut().machine.outcome(o);
                    show(a);
                    sync_timer(a);
                    focus_pin(a);
                }
            }
        },
    );
}

fn submit_password(app: &Rc<App>) {
    let vm = app.ui().global::<ConnectVm>();
    let pw = vm.get_password().to_string();
    if pw.is_empty() || vm.get_pairing() {
        return;
    }
    let Some(id) = app.conn.borrow().server_id.clone() else {
        return;
    };
    let Some(s) = app.server(&id) else { return };
    vm.set_pairing(true);
    vm.set_err_password(ss(""));
    let ctx = AdminContext {
        host: s.host.clone(),
        port: s.port,
        server_key_hex: s.server_key.clone(),
        device: app.key.clone(),
        server_version: s.version(),
        session: None,
    };
    let admin = app.be.admin.clone();
    spawn_ui(
        app,
        async move { admin.reinstate(&ctx, &Secret::new(pw)).await },
        move |a, r| {
            let vm = a.ui().global::<ConnectVm>();
            vm.set_pairing(false);
            match r {
                Ok(()) => {
                    let _ = a.store.borrow_mut().set_lifecycle(&id, Lifecycle::Ready, 0);
                    vm.set_password(ss(""));
                    a.conn.borrow_mut().machine = ConnectMachine::new();
                    show(&a.clone());
                }
                Err(AdminError::Incorrect { .. }) => {
                    vm.set_err_password(ss("That password did not work. Check it and try again."))
                }
                Err(AdminError::RateLimited) => {
                    vm.set_err_password(ss("Too many tries. Wait a few minutes and try again."))
                }
                Err(AdminError::Unreachable) => vm.set_err_password(ss("Cannot reach the server.")),
                Err(AdminError::UpdateRequired) => super::update_ctl::show(a, &id),
                Err(AdminError::Failed(m)) => vm.set_err_password(ss(m)),
            }
        },
    );
}

pub fn wire(app: &Rc<App>) {
    let ui = app.ui();
    let vm = ui.global::<ConnectVm>();
    let a = app.clone();
    vm.on_submit(move || {
        submit(&a);
        sync_timer(&a);
    });
    let a = app.clone();
    vm.on_cancel(move || {
        a.conn.borrow_mut().epoch += 1;
        a.conn.borrow_mut().machine.cancel();
        a.conn.borrow_mut().timer = None;
        a.show_home();
    });
    let a = app.clone();
    vm.on_back(move || {
        a.conn.borrow_mut().epoch += 1;
        a.conn.borrow_mut().timer = None;
        a.show_home();
    });
    let a = app.clone();
    vm.on_pair_again(move || {
        a.conn.borrow_mut().machine.pair_again();
        show(&a);
    });
    let a = app.clone();
    vm.on_submit_password(move || submit_password(&a));
    let a = app.clone();
    vm.on_retry(move || {
        if a.conn.borrow_mut().machine.retry() {
            show(&a);
            sync_timer(&a);
        }
    });
    let a = app.clone();
    vm.on_open_details(move || {
        let id = a.conn.borrow().server_id.clone();
        if let Some(id) = id {
            super::details_ctl::open(&a, &id);
        }
    });
    let a = app.clone();
    vm.on_remove_server(move || {
        let id = a.conn.borrow().server_id.clone();
        if let Some(id) = id {
            let _ = a.store.borrow_mut().remove(&id);
        }
        a.show_home();
    });
}

fn focus_pin(app: &Rc<App>) {
    let vm = app.ui().global::<ConnectVm>();
    vm.set_focus_tick(vm.get_focus_tick() + 1);
}
