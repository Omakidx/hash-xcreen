//! Server details: Overview, Security (devices, revoke, pair a new device, change PIN and
//! password), Desktop and the Danger zone. Backups, web access and passkeys (Phase 2 and 3) are
//! not shown.

use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use slint::ComponentHandle;

use super::known_hosts::Known;
use super::{App, model, spawn_ui, ss};
use crate::backend::{
    AdminContext, AdminError, DesktopStatus, EngineError, HostKey, Limits, Overview, Secret,
    SshAuth, SshTarget, UninstallRequest,
};
use crate::details::{self, DangerFlow, DeviceRow, RevokePlan};
use crate::servers::{Lifecycle, parse_version};
use crate::session::{Desk, Wiring};
use crate::video::Stats;
use crate::{DetailsVm, DeviceRowData, Kv, Screen};

/// Details state.
#[derive(Default)]
pub struct Ctx {
    pub server_id: Option<String>,
    pub epoch: u64,
    pub session: Option<Arc<dyn Desk>>,
    pub rows: Vec<DeviceRow>,
    pub plan: Option<RevokePlan>,
    pub overview: Option<Overview>,
    pub danger: DangerFlow,
    pub pending_host: Option<HostKey>,
    pub pair_started: Option<(Instant, u64, u32)>,
    pub pair_timer: Option<slint::Timer>,
}

fn kv(k: &str, v: impl Into<String>) -> Kv {
    Kv {
        key: ss(k),
        value: ss(v.into()),
    }
}

fn admin_ctx(app: &App) -> Option<AdminContext> {
    let id = app.det.borrow().server_id.clone()?;
    let s = app.server(&id)?;
    Some(AdminContext {
        host: s.host,
        port: s.port,
        server_key_hex: s.server_key,
        device: app.key.clone(),
        server_version: parse_version(&s.server_version),
        session: app.det.borrow().session.clone(),
    })
}

fn hex16(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut o = [0u8; 16];
    for (i, b) in o.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(o)
}

/// Opens Server details for a server.
pub fn open(app: &Rc<App>, id: &str) {
    let Some(s) = app.server(id) else { return };
    {
        let mut c = app.det.borrow_mut();
        let epoch = c.epoch + 1;
        *c = Ctx {
            epoch,
            server_id: Some(id.to_owned()),
            ..Ctx::default()
        };
    }
    let vm = app.ui().global::<DetailsVm>();
    vm.set_tab(0);
    vm.set_dialog(0);
    vm.set_danger(0);
    vm.set_notice(ss(""));
    vm.set_server_name(ss(&s.name));
    vm.set_address(ss(s.address()));
    let (status, tone, can_connect) = match s.lifecycle {
        Lifecycle::Revoked => ("Pair again", 3, true),
        Lifecycle::Installing => ("Installing", 4, false),
        Lifecycle::SetupPending => ("Setup not finished", 2, false),
        Lifecycle::Uninstalled => ("Uninstalled", 0, false),
        Lifecycle::Ready => match app.reachable.borrow().get(id) {
            Some(false) => ("Offline", 0, false),
            _ => ("Online", 1, true),
        },
    };
    vm.set_status(ss(status));
    vm.set_status_tone(tone);
    vm.set_can_connect(can_connect);
    clear_overview(app);
    app.go(Screen::Details);
    if s.lifecycle == Lifecycle::Ready {
        fetch_overview(app);
    } else if s.lifecycle == Lifecycle::Uninstalled {
        vm.set_tab(3);
        vm.set_danger(4);
        vm.set_done_text(ss(done_text(&s.host, true)));
    }
}

fn clear_overview(app: &Rc<App>) {
    let vm = app.ui().global::<DetailsVm>();
    vm.set_attention_title(ss(""));
    vm.set_attention_text(ss(""));
    vm.set_offline_text(ss(""));
    vm.set_can_restart(false);
    vm.set_update_text(ss(""));
    vm.set_can_update(false);
    vm.set_ov_limits(model(vec![]));
    vm.set_ov_desktop(model(vec![]));
    vm.set_ov_agent(model(vec![]));
    vm.set_ov_server(model(vec![]));
}

fn uptime_text(s: u64) -> String {
    let (d, h) = (s / 86_400, (s % 86_400) / 3600);
    match (d, h) {
        (0, 0) => format!("{} minutes", s / 60),
        (0, h) => format!("{h} hours"),
        (d, h) => format!("{d} days {h} hours"),
    }
}

fn fetch_overview(app: &Rc<App>) {
    let Some(ctx) = admin_ctx(app) else { return };
    let (epoch, id) = {
        let c = app.det.borrow();
        (c.epoch, c.server_id.clone().unwrap_or_default())
    };
    app.ui().global::<DetailsVm>().set_loading(true);
    let control = app.be.control.clone();
    spawn_ui(
        app,
        async move { control.overview(&ctx).await },
        move |a, r| {
            if a.det.borrow().epoch != epoch {
                return;
            }
            let vm = a.ui().global::<DetailsVm>();
            vm.set_loading(false);
            let Some(s) = a.server(&id) else { return };
            match r {
                Ok(o) => {
                    fill_overview(a, &s, &o);
                    a.det.borrow_mut().overview = Some(o);
                }
                Err(AdminError::SessionRequired) => {
                    if vm.get_dialog() == 0 {
                        open_dialog(a, 6);
                    }
                }
                Err(AdminError::UpdateRequired) => super::update_ctl::show(a, &id),
                Err(AdminError::Failed(m)) => {
                    vm.set_attention_title(ss("The server's details could not be loaded"));
                    vm.set_attention_text(ss(m));
                }
                Err(_) => {
                    a.reachable.borrow_mut().insert(id, false);
                    vm.set_status(ss("Offline"));
                    vm.set_status_tone(0);
                    vm.set_can_connect(false);
                    vm.set_offline_text(ss(if s.last_seen_unix == 0 {
                        "No answer from the server. Values are not available.".to_owned()
                    } else {
                        format!(
                            "Last seen {}. Values below are from then.",
                            details::relative_time(s.last_seen_unix, super::now_unix(), false)
                        )
                    }));
                    vm.set_ov_desktop(model(vec![
                        kv("Status", "Unknown"),
                        kv("Uptime", "unknown"),
                    ]));
                    vm.set_ov_agent(model(vec![kv("Version", "unknown")]));
                    vm.set_ov_server(model(vec![
                        kv("Address", s.address()),
                        kv("Identity", s.short_fingerprint()),
                    ]));
                }
            }
        },
    );
}

fn fill_overview(app: &Rc<App>, s: &crate::servers::Server, o: &Overview) {
    let vm = app.ui().global::<DetailsVm>();
    let status = match o.desktop {
        DesktopStatus::Running => "Running",
        DesktopStatus::NotAnswering => "Not answering",
        DesktopStatus::Creating => "Being created",
        DesktopStatus::NotCreated => "Not created yet",
        DesktopStatus::Unknown => "Unknown",
    };
    vm.set_ov_desktop(model(vec![
        kv("Status", status),
        kv(
            "Session",
            if o.session_active {
                "In use"
            } else {
                "Nobody connected"
            },
        ),
        kv("Setup", o.setup.clone()),
    ]));
    vm.set_ov_agent(model(vec![
        kv(
            "Version",
            format!("{} ({} channel)", o.agent_version, o.channel),
        ),
        kv("Running for", uptime_text(o.agent_uptime_secs)),
        kv(
            "Updates",
            match (&o.update_available, &o.rolled_back) {
                (Some(v), _) => format!("Version {v} is available"),
                (None, Some(v)) => format!("Rolled back from {v}"),
                (None, None) => "Up to date".to_owned(),
            },
        ),
        kv("Protocol", o.protocol.clone()),
    ]));
    vm.set_ov_server(model(vec![
        kv("Address", s.address()),
        kv("Host OS", o.host_os.clone()),
        kv("Identity", s.short_fingerprint()),
    ]));
    vm.set_ov_limits(model(match o.limits {
        Some(l) => vec![
            kv("CPU", format!("{} cores", l.cpu)),
            kv("Memory", format!("{} GB", l.memory_gb)),
            kv("Disk", format!("{} GB", l.disk_gb)),
        ],
        None => vec![],
    }));
    vm.set_update_text(ss(o
        .update_available
        .as_ref()
        .map_or(String::new(), |v| format!("Update available: {v}"))));
    vm.set_can_update(o.update_available.is_some());
    vm.set_agent_line(ss(format!(
        "Version {}, {}. Updates also apply by themselves on the {} channel.",
        o.agent_version,
        if o.update_available.is_some() {
            "an update is available"
        } else {
            "up to date"
        },
        o.channel
    )));
    let running = o.desktop == DesktopStatus::Running;
    if running && o.attention.is_empty() {
        vm.set_attention_title(ss(""));
        vm.set_attention_text(ss(""));
        vm.set_can_restart(false);
    } else {
        vm.set_attention_title(ss(if running {
            "Needs attention"
        } else {
            "The desktop is not answering"
        }));
        vm.set_attention_text(ss(if o.attention.is_empty() {
            "The agent is up but cannot reach the desktop session. It retries every 10 minutes and after a restart.".to_owned()
        } else {
            o.attention.join(" ")
        }));
        vm.set_can_restart(
            o.desktop != DesktopStatus::NotCreated && o.desktop != DesktopStatus::Creating,
        );
    }
    vm.set_docker(o.docker);
    vm.set_cpu_max(o.host_cpus.max(1) as i32);
    vm.set_memory_max(o.host_mem_gb.max(1) as i32);
    vm.set_disk_max(o.host_disk_gb.max(8) as i32);
    if let Some(l) = o.limits {
        vm.set_cpu(l.cpu as i32);
        vm.set_memory(l.memory_gb as i32);
        vm.set_disk(l.disk_gb as i32);
    }
    vm.set_limits_dirty(false);
}

// ------------------------------------------------------------------------------- security

fn show_rows(app: &Rc<App>) {
    let vm = app.ui().global::<DetailsVm>();
    let c = app.det.borrow();
    vm.set_devices(model(
        c.rows
            .iter()
            .map(|r| DeviceRowData {
                id: ss(hex16(&r.id)),
                name: ss(&r.name),
                last_seen: ss(&r.last_seen),
                state: ss(&r.state),
                tone: r.tone,
                current: r.current,
                can_revoke: r.can_revoke,
            })
            .collect(),
    ));
}

fn refresh_devices(app: &Rc<App>) {
    let Some(desk) = app.det.borrow().session.clone() else {
        return;
    };
    let epoch = app.det.borrow().epoch;
    app.ui().global::<DetailsVm>().set_loading(true);
    spawn_ui(
        app,
        async move { desk.list_devices().await },
        move |a, r| {
            if a.det.borrow().epoch != epoch {
                return;
            }
            let vm = a.ui().global::<DetailsVm>();
            vm.set_loading(false);
            match r {
                Ok(list) => {
                    a.det.borrow_mut().rows = details::rows(&list, super::now_unix());
                    vm.set_devices_note(ss("Devices paired with this server. Revoked ones stay listed so you can see what happened."));
                    show_rows(a);
                }
                Err(e) => vm.set_devices_note(ss(e.to_string())),
            }
        },
    );
}

fn select_tab(app: &Rc<App>, t: i32) {
    let vm = app.ui().global::<DetailsVm>();
    vm.set_tab(t);
    if t == 1 {
        if app.det.borrow().session.is_some() {
            refresh_devices(app);
        } else {
            open_dialog(app, 6);
        }
    }
}

fn open_dialog(app: &Rc<App>, d: i32) {
    let vm = app.ui().global::<DetailsVm>();
    vm.set_f1(ss(""));
    vm.set_f2(ss(""));
    vm.set_f3(ss(""));
    vm.set_e1(ss(""));
    vm.set_e2(ss(""));
    vm.set_e3(ss(""));
    vm.set_dialog_error(ss(""));
    vm.set_dialog_busy(false);
    vm.set_dialog(d);
}

fn close_dialog(app: &Rc<App>) {
    let vm = app.ui().global::<DetailsVm>();
    // Wipe typed secrets with the dialog.
    vm.set_f1(ss(""));
    vm.set_f2(ss(""));
    vm.set_f3(ss(""));
    vm.set_dialog(0);
    app.det.borrow_mut().pair_timer = None;
    // Without a session the Security tab has nothing to show: go back to Overview.
    if app.det.borrow().session.is_none() && vm.get_tab() == 1 {
        vm.set_tab(0);
    }
}

fn admin_error_text(e: &AdminError) -> String {
    match e {
        AdminError::Incorrect {
            attempts_left: Some(1),
        } => "Incorrect, 1 attempt left".into(),
        AdminError::Incorrect {
            attempts_left: Some(n),
        } => format!("Incorrect, {n} attempts left"),
        AdminError::Incorrect {
            attempts_left: None,
        } => "Incorrect. Check it and try again.".into(),
        AdminError::RateLimited => "Too many tries. Wait a few minutes and try again.".into(),
        AdminError::Failed(m) => m.clone(),
        AdminError::Unreachable => "Cannot reach the server.".into(),
        AdminError::UpdateRequired => "This server must be updated first.".into(),
        AdminError::SessionRequired => "Sign in with your PIN first.".into(),
        AdminError::Revoked => "This device was removed from the server. Use Pair again.".into(),
    }
}

fn submit_dialog(app: &Rc<App>) {
    let vm = app.ui().global::<DetailsVm>();
    if vm.get_dialog_busy() {
        return;
    }
    let (f1, f2, f3) = (
        vm.get_f1().to_string(),
        vm.get_f2().to_string(),
        vm.get_f3().to_string(),
    );
    match vm.get_dialog() {
        6 => unlock(app, f1),
        4 | 5 => {
            let pin = vm.get_dialog() == 4;
            let p = if pin {
                details::pin_dialog_problems(&f1, &f2, &f3)
            } else {
                details::password_dialog_problems(&f1, &f2, &f3)
            };
            vm.set_e1(ss(p[0].clone().unwrap_or_default()));
            vm.set_e2(ss(p[1].clone().unwrap_or_default()));
            vm.set_e3(ss(p[2].clone().unwrap_or_default()));
            if p.iter().any(Option::is_some) {
                return;
            }
            let Some(ctx) = admin_ctx(app) else { return };
            vm.set_dialog_busy(true);
            vm.set_dialog_error(ss(""));
            let control = app.be.control.clone();
            spawn_ui(
                app,
                async move {
                    let (cur, new) = (Secret::new(f1), Secret::new(f2));
                    if pin {
                        control.change_pin(&ctx, &cur, &new).await
                    } else {
                        control.change_password(&ctx, &cur, &new).await
                    }
                },
                move |a, r| {
                    let vm = a.ui().global::<DetailsVm>();
                    vm.set_dialog_busy(false);
                    match r {
                        Ok(()) => {
                            close_dialog(a);
                            vm.set_notice(ss(if pin {
                                "PIN changed"
                            } else {
                                "Password changed"
                            }));
                        }
                        Err(AdminError::Revoked)
                        | Err(AdminError::Incorrect {
                            attempts_left: Some(0),
                        }) => {
                            // The fifth wrong PIN or password: the server ended the session and
                            // revoked this device.
                            close_dialog(a);
                            if let Some(sid) = a.det.borrow().server_id.clone() {
                                let _ = a.store.borrow_mut().set_lifecycle(
                                    &sid,
                                    Lifecycle::Revoked,
                                    super::now_unix(),
                                );
                            }
                            teardown(a);
                            a.show_home();
                        }
                        Err(e) => vm.set_dialog_error(ss(admin_error_text(&e))),
                    }
                },
            );
        }
        _ => {}
    }
}

fn unlock(app: &Rc<App>, pin: String) {
    if pin.is_empty() {
        app.ui().global::<DetailsVm>().set_e1(ss("Enter your PIN."));
        return;
    }
    let Some(id) = app.det.borrow().server_id.clone() else {
        return;
    };
    let Some(link) = super::connect_ctl::link_of(app, &id) else {
        return;
    };
    let vm = app.ui().global::<DetailsVm>();
    vm.set_dialog_busy(true);
    vm.set_dialog_error(ss(""));
    let connector = app.be.connector.clone();
    let wiring = Wiring {
        frames: None,
        presenter: None,
        stats: Arc::new(Stats::default()),
        downloads: app.downloads.clone(),
    };
    let epoch = app.det.borrow().epoch;
    let pin = zeroize::Zeroizing::new(pin);
    spawn_ui(
        app,
        async move {
            connector
                .connect(&link, &pin, Box::new(|| {}), wiring)
                .await
        },
        move |a, r| {
            if a.det.borrow().epoch != epoch {
                if let Ok(est) = r {
                    a.rt.spawn(async move { est.desk.close().await });
                }
                return;
            }
            let vm = a.ui().global::<DetailsVm>();
            vm.set_dialog_busy(false);
            match r {
                Ok(est) => {
                    a.det.borrow_mut().session = Some(est.desk);
                    vm.set_f1(ss(""));
                    vm.set_dialog(0);
                    refresh_devices(a);
                    fetch_overview(a);
                }
                Err(o) => {
                    let text = match o {
                        crate::session::Outcome::Wrong { attempts_left, .. } => {
                            crate::session::connect::wrong_pin_text(attempts_left).0
                        }
                        crate::session::Outcome::Backoff { retry_after } => format!(
                            "Wait {} seconds before trying again",
                            retry_after.as_secs().max(1)
                        ),
                        crate::session::Outcome::Revoked => {
                            "This device was removed from the server.".into()
                        }
                        crate::session::Outcome::NotAvailable { .. } => {
                            "The server cannot check PINs right now. Try again in about a minute."
                                .into()
                        }
                        crate::session::Outcome::IdentityChanged => {
                            "This server's identity changed. Nothing was sent.".into()
                        }
                        crate::session::Outcome::Unreachable(m)
                        | crate::session::Outcome::Failed(m) => m,
                        crate::session::Outcome::Accepted => String::new(),
                    };
                    vm.set_dialog_error(ss(text));
                    vm.set_f1(ss(""));
                }
            }
        },
    );
}

fn start_revoke(app: &Rc<App>, id_hex: &str) {
    let Some(id) = parse16(id_hex) else { return };
    let row = app.det.borrow().rows.iter().find(|r| r.id == id).cloned();
    let Some(plan) = row.as_ref().and_then(details::plan_revoke) else {
        return;
    };
    let vm = app.ui().global::<DetailsVm>();
    vm.set_dialog_text(ss(&plan.name));
    let is_self = plan.is_self;
    app.det.borrow_mut().plan = Some(plan);
    open_dialog(app, if is_self { 2 } else { 1 });
}

fn confirm_revoke(app: &Rc<App>) {
    let (plan, desk) = {
        let c = app.det.borrow();
        (c.plan.clone(), c.session.clone())
    };
    let (Some(plan), Some(desk)) = (plan, desk) else {
        return;
    };
    let vm = app.ui().global::<DetailsVm>();
    vm.set_dialog_busy(true);
    let epoch = app.det.borrow().epoch;
    let id = plan.id;
    spawn_ui(app, async move { desk.revoke(id).await }, move |a, r| {
        if a.det.borrow().epoch != epoch {
            return;
        }
        let vm = a.ui().global::<DetailsVm>();
        vm.set_dialog_busy(false);
        let status = match r {
            Ok(s) => s,
            Err(e) => {
                vm.set_dialog_error(ss(e.to_string()));
                return;
            }
        };
        match details::revoke_message(status) {
            Some(m) if status != hx_proto::pb::RevokeStatus::AlreadyRevoked => {
                vm.set_dialog_error(ss(m))
            }
            _ => {
                vm.set_dialog(0);
                if plan.is_self && status == hx_proto::pb::RevokeStatus::Ok {
                    // This device signed itself out: it is revoked here too.
                    if let Some(sid) = a.det.borrow().server_id.clone() {
                        let _ = a.store.borrow_mut().set_lifecycle(
                            &sid,
                            Lifecycle::Revoked,
                            super::now_unix(),
                        );
                    }
                    teardown(a);
                    a.show_home();
                } else {
                    vm.set_notice(ss(format!("{} was revoked", plan.name)));
                    refresh_devices(a);
                }
            }
        }
    });
}

fn pair_device(app: &Rc<App>) {
    let Some(ctx) = admin_ctx(app) else { return };
    open_dialog(app, 3);
    let vm = app.ui().global::<DetailsVm>();
    vm.set_pair_code(ss(""));
    vm.set_pair_address(ss(format!("{}:{}", ctx.host, ctx.port)));
    let epoch = app.det.borrow().epoch;
    let admin = app.be.admin.clone();
    spawn_ui(
        app,
        async move { admin.create_pairing_code(&ctx).await },
        move |a, r| {
            if a.det.borrow().epoch != epoch {
                return;
            }
            let vm = a.ui().global::<DetailsVm>();
            match r {
                Ok(code) => {
                    vm.set_pair_code(ss(&code.code));
                    vm.set_pair_expiry(ss(details::expiry_text(code.expires_in_secs, code.tries)));
                    a.det.borrow_mut().pair_started =
                        Some((Instant::now(), code.expires_in_secs, code.tries));
                    let t = slint::Timer::default();
                    let a2 = a.clone();
                    t.start(
                        slint::TimerMode::Repeated,
                        Duration::from_secs(1),
                        move || {
                            let Some((at, total, tries)) = a2.det.borrow().pair_started else {
                                return;
                            };
                            let left = total.saturating_sub(at.elapsed().as_secs());
                            a2.ui()
                                .global::<DetailsVm>()
                                .set_pair_expiry(ss(details::expiry_text(left, tries)));
                        },
                    );
                    a.det.borrow_mut().pair_timer = Some(t);
                }
                Err(AdminError::UpdateRequired) => {
                    close_dialog(a);
                    let id = a.det.borrow().server_id.clone().unwrap_or_default();
                    super::update_ctl::show(a, &id);
                }
                Err(e) => vm.set_dialog_error(ss(match e {
                    AdminError::RateLimited => {
                        "The server limits how often a code can be created. Wait a few minutes."
                            .to_owned()
                    }
                    other => admin_error_text(&other),
                })),
            }
        },
    );
}

// ------------------------------------------------------------------------------- desktop

fn run_control(
    app: &Rc<App>,
    label: &'static str,
    f: impl FnOnce(
        Arc<dyn crate::backend::ServerControl>,
        AdminContext,
    ) -> crate::backend::BoxFuture<'static, Result<(), AdminError>>
    + 'static,
) {
    let Some(ctx) = admin_ctx(app) else { return };
    let vm = app.ui().global::<DetailsVm>();
    vm.set_loading(true);
    let fut = f(app.be.control.clone(), ctx);
    spawn_ui(app, fut, move |a, r| {
        let vm = a.ui().global::<DetailsVm>();
        vm.set_loading(false);
        vm.set_notice(ss(match r {
            Ok(()) => label.to_owned(),
            Err(e) => format!("Could not do that: {}", admin_error_text(&e)),
        }));
        fetch_overview(a);
    });
}

// ------------------------------------------------------------------------------- danger zone

fn done_text(host: &str, keep: bool) -> String {
    format!(
        "hash-xcreen was uninstalled from {host}. {} Incus and its package source remain installed. To remove them, run on the server: {}",
        if keep {
            "The desktop was kept on the server."
        } else {
            "The desktop was deleted."
        },
        details::REMOVE_INCUS
    )
}

fn danger_continue(app: &Rc<App>) {
    let vm = app.ui().global::<DetailsVm>();
    let Some(id) = app.det.borrow().server_id.clone() else {
        return;
    };
    let Some(s) = app.server(&id) else { return };
    let port: u16 = match vm.get_ssh_port().trim().parse() {
        Ok(p) if p > 0 => p,
        _ => {
            vm.set_danger_error(ss("Enter a port from 1 to 65535."));
            return;
        }
    };
    vm.set_danger_error(ss(""));
    let target = SshTarget {
        host: s.host.clone(),
        port,
    };
    let pending = app.det.borrow().pending_host.clone();
    if let Some(hk) = pending {
        // Second press: the user saw the fingerprint and trusts it.
        app.hosts
            .borrow_mut()
            .trust(&target.host, target.port, &hk.fingerprint);
        app.det.borrow_mut().pending_host = None;
        app.det.borrow_mut().danger.ssh_given();
        vm.set_danger(2);
        return;
    }
    let engine = app.be.install.clone();
    let epoch = app.det.borrow().epoch;
    let t2 = target.clone();
    spawn_ui(
        app,
        async move { engine.probe_host_key(&t2).await },
        move |a, r| {
            if a.det.borrow().epoch != epoch {
                return;
            }
            let vm = a.ui().global::<DetailsVm>();
            match r {
            Err(e) => vm.set_danger_error(ss(e.to_string())),
            Ok(hk) => match a.hosts.borrow().check(&target.host, target.port, &hk.fingerprint) {
                Known::Same => {
                    a.det.borrow_mut().danger.ssh_given();
                    vm.set_danger(2);
                }
                Known::Changed { .. } => vm.set_danger_error(ss(
                    "This server's SSH host key is different from the one you trusted before. Nothing was sent. If you reinstalled the server, remove its entry from known_hosts.json in the app's config folder.",
                )),
                Known::New => {
                    vm.set_danger_error(ss(format!(
                        "Host key ({}): {}. If this matches the one your provider shows, press Continue again to trust it.",
                        hk.algorithm, hk.fingerprint
                    )));
                    a.det.borrow_mut().pending_host = Some(hk);
                }
            },
        }
        },
    );
}

fn danger_confirm(app: &Rc<App>) {
    let vm = app.ui().global::<DetailsVm>();
    let Some(id) = app.det.borrow().server_id.clone() else {
        return;
    };
    let Some(s) = app.server(&id) else { return };
    let typed = vm.get_confirm_name().to_string();
    let keep = vm.get_keep_desktop();
    {
        let mut c = app.det.borrow_mut();
        c.danger.keep = keep;
        if !c.danger.confirm(&typed, &s.name) {
            return;
        }
    }
    vm.set_danger(3);
    let port: u16 = vm.get_ssh_port().trim().parse().unwrap_or(22);
    let user = vm.get_ssh_user().trim().to_owned();
    let pw = vm.get_ssh_password().to_string();
    vm.set_ssh_password(ss(""));
    let auth = if pw.is_empty() {
        SshAuth::DefaultKeys { user }
    } else {
        SshAuth::Password {
            user,
            password: Secret::new(pw),
        }
    };
    let target = SshTarget {
        host: s.host.clone(),
        port,
    };
    let engine = app.be.install.clone();
    let epoch = app.det.borrow().epoch;
    let host = s.host.clone();
    spawn_ui(
        app,
        async move {
            // The trusted key was checked when the SSH details were given; the engine verifies it
            // again against what the server presents now.
            let hk = engine.probe_host_key(&target).await?;
            engine
                .uninstall(UninstallRequest {
                    target,
                    auth,
                    host_key: hk,
                    keep_desktop: keep,
                })
                .await
        },
        move |a, r: Result<(), EngineError>| {
            if a.det.borrow().epoch != epoch {
                return;
            }
            let vm = a.ui().global::<DetailsVm>();
            let ok = r.is_ok();
            a.det.borrow_mut().danger.finished(ok);
            match r {
                Ok(()) => {
                    if let Some(sid) = a.det.borrow().server_id.clone() {
                        let _ = a.store.borrow_mut().set_lifecycle(
                            &sid,
                            Lifecycle::Uninstalled,
                            super::now_unix(),
                        );
                    }
                    vm.set_done_text(ss(done_text(&host, keep)));
                    vm.set_danger(4);
                    vm.set_status(ss("Uninstalled"));
                    vm.set_status_tone(0);
                    vm.set_can_connect(false);
                }
                Err(e) => {
                    vm.set_danger_error(ss(e.to_string()));
                    vm.set_danger(2);
                }
            }
        },
    );
}

fn teardown(app: &Rc<App>) {
    let s = app.det.borrow_mut().session.take();
    if let Some(s) = s {
        app.rt.spawn(async move { s.close().await });
    }
    let mut c = app.det.borrow_mut();
    c.epoch += 1;
    c.pair_timer = None;
}

pub fn wire(app: &Rc<App>) {
    let ui = app.ui();
    let vm = ui.global::<DetailsVm>();
    let a = app.clone();
    vm.on_back(move || {
        teardown(&a);
        a.show_home();
    });
    let a = app.clone();
    vm.on_connect(move || {
        let id = a.det.borrow().server_id.clone();
        if let Some(id) = id {
            let lifecycle = a.server(&id).map(|s| s.lifecycle);
            teardown(&a);
            if lifecycle == Some(Lifecycle::Revoked) {
                super::connect_ctl::open_pair_again(&a, &id);
            } else {
                super::connect_ctl::open(&a, &id);
            }
        }
    });
    let a = app.clone();
    vm.on_select_tab(move |t| select_tab(&a, t));
    let a = app.clone();
    vm.on_restart_desktop(move || {
        a.ui().global::<DetailsVm>().set_restart_dialog(true);
    });
    let a = app.clone();
    vm.on_cancel_restart(move || a.ui().global::<DetailsVm>().set_restart_dialog(false));
    let a = app.clone();
    vm.on_confirm_restart(move || {
        a.ui().global::<DetailsVm>().set_restart_dialog(false);
        run_control(&a, "The desktop is restarting", |c, ctx| {
            Box::pin(async move { c.restart_desktop(&ctx).await })
        });
    });
    let a = app.clone();
    vm.on_update_agent(move || {
        let Some(ctx) = admin_ctx(&a) else { return };
        let control = a.be.control.clone();
        a.ui().global::<DetailsVm>().set_loading(true);
        spawn_ui(
            &a,
            async move { control.update_agent(&ctx).await },
            move |a, r| {
                let vm = a.ui().global::<DetailsVm>();
                vm.set_loading(false);
                vm.set_notice(ss(match r {
                    Ok(v) => format!("The agent was updated to {v}"),
                    Err(e) => format!("Could not update: {}", admin_error_text(&e)),
                }));
                fetch_overview(a);
            },
        );
    });
    let a = app.clone();
    vm.on_revoke(move |id| start_revoke(&a, id.as_str()));
    let a = app.clone();
    vm.on_confirm_revoke(move || confirm_revoke(&a));
    let a = app.clone();
    vm.on_pair_device(move || pair_device(&a));
    let a = app.clone();
    vm.on_copy_pair_code(move || {
        let c = a.ui().global::<DetailsVm>().get_pair_code();
        a.set_clipboard(c.as_str());
    });
    let a = app.clone();
    vm.on_change_pin(move || open_dialog(&a, 4));
    let a = app.clone();
    vm.on_change_password(move || open_dialog(&a, 5));
    let a = app.clone();
    vm.on_submit_dialog(move || submit_dialog(&a));
    let a = app.clone();
    vm.on_close_dialog(move || close_dialog(&a));
    let a = app.clone();
    vm.on_dialog_changed(move || {
        let vm = a.ui().global::<DetailsVm>();
        let (s, _) = (crate::wizard::password_strength(&vm.get_f2()), ());
        vm.set_strength(i32::from(s.0));
        vm.set_strength_word(ss(s.1));
    });
    let a = app.clone();
    vm.on_docker_toggled(move |on| {
        let vm = a.ui().global::<DetailsVm>();
        if on {
            // Not on until the warning is accepted.
            vm.set_docker(false);
            vm.set_docker_ack(false);
            vm.set_docker_dialog(true);
        } else {
            vm.set_docker(false);
            run_control(&a, "Docker is off; the desktop restarts", |c, ctx| {
                Box::pin(async move { c.set_docker(&ctx, false).await })
            });
        }
    });
    let a = app.clone();
    vm.on_cancel_docker(move || a.ui().global::<DetailsVm>().set_docker_dialog(false));
    let a = app.clone();
    vm.on_confirm_docker(move || {
        let vm = a.ui().global::<DetailsVm>();
        vm.set_docker_dialog(false);
        vm.set_docker(true);
        run_control(&a, "Docker is on; the desktop restarts", |c, ctx| {
            Box::pin(async move { c.set_docker(&ctx, true).await })
        });
    });
    let a = app.clone();
    vm.on_limits_changed(move || {
        let vm = a.ui().global::<DetailsVm>();
        let dirty = a.det.borrow().overview.as_ref().is_none_or(|o| {
            o.limits.is_none_or(|l| {
                vm.get_cpu() as u32 != l.cpu
                    || vm.get_memory() as u32 != l.memory_gb
                    || vm.get_disk() as u32 != l.disk_gb
            })
        });
        vm.set_limits_dirty(dirty);
    });
    let a = app.clone();
    vm.on_apply_limits(move || {
        let vm = a.ui().global::<DetailsVm>();
        let l = Limits {
            cpu: vm.get_cpu().max(1) as u32,
            memory_gb: vm.get_memory().max(1) as u32,
            disk_gb: vm.get_disk().max(8) as u32,
        };
        run_control(&a, "Limits applied", move |c, ctx| {
            Box::pin(async move { c.set_limits(&ctx, l).await })
        });
    });
    let a = app.clone();
    vm.on_uninstall(move || {
        a.det.borrow_mut().danger.start();
        a.det.borrow_mut().pending_host = None;
        let vm = a.ui().global::<DetailsVm>();
        vm.set_danger_error(ss(""));
        vm.set_danger(1);
    });
    let a = app.clone();
    vm.on_danger_continue(move || danger_continue(&a));
    let a = app.clone();
    vm.on_danger_cancel(move || {
        a.det.borrow_mut().danger.cancel();
        a.det.borrow_mut().pending_host = None;
        let vm = a.ui().global::<DetailsVm>();
        vm.set_danger(0);
        vm.set_confirm_name(ss(""));
        vm.set_ssh_password(ss(""));
    });
    let a = app.clone();
    vm.on_danger_confirm(move || danger_confirm(&a));
    let a = app.clone();
    vm.on_copy_commands(move || a.set_clipboard(details::REMOVE_INCUS));
    let a = app.clone();
    vm.on_remove_from_app(move || {
        let id = a.det.borrow().server_id.clone();
        if let Some(id) = id {
            let _ = a.store.borrow_mut().remove(&id);
        }
        teardown(&a);
        a.show_home();
    });
}
