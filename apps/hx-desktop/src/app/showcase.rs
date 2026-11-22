//! Every state of the design mockups, reachable directly (demo mode only): `--demo --screen NAME`.
//! The screenshots, the render tests and the README use these names.

use std::rc::Rc;
use std::time::Duration;

use slint::ComponentHandle;

use super::progress::Model;
use super::{App, model, ss};
use crate::backend::{CheckRow, CheckStatus, InstallEvent, InstallFailure, InstallOutcome, Preflight, StageState};
use crate::servers::{Lifecycle, Server};
use crate::session::connect::Outcome;
use crate::wizard::{ConnPhase, Method, Step};
use crate::{ActivityData, DesktopVm, DetailsVm, DeviceRowData, Kv, Screen, ThemeMode, Tokens, WizardVm};

/// Every name `apply` knows.
pub const NAMES: &[&str] = &[
    "home", "home-empty", "home-loading",
    "wizard-method", "wizard-connection", "wizard-hostkey", "wizard-checks-ok", "wizard-checks-bad",
    "wizard-desktop", "wizard-docker", "wizard-account", "wizard-account-errors", "wizard-backups",
    "wizard-resources", "wizard-review", "wizard-oneliner-server", "wizard-run-waiting",
    "wizard-run-expired", "wizard-run-unreachable", "wizard-run-paired", "wizard-code", "wizard-code-failed",
    "progress-running", "progress-unknown", "progress-failed", "progress-lost", "progress-success",
    "connect-pin", "connect-checking", "connect-wrong", "connect-wait", "connect-last", "connect-revoked",
    "connect-pair-again", "connect-unavailable", "connect-unreachable", "connect-identity",
    "desktop", "desktop-toolbar", "desktop-display", "desktop-quality", "desktop-keys", "desktop-transfers",
    "desktop-stats", "desktop-files", "desktop-reconnect", "desktop-gave-up", "desktop-takeover",
    "desktop-open-link", "desktop-unavailable",
    "details-overview", "details-problems", "details-offline", "details-security", "details-revoke",
    "details-revoke-self", "details-pair", "details-pin", "details-password", "details-desktop",
    "details-docker", "details-restart", "details-danger", "details-danger-ssh", "details-danger-confirm",
    "details-danger-done", "settings",
];

const KEY_A: &str = "3f9ac1d477be0a52b81e05f7d3906c2a3f9ac1d477be0a52b81e05f7d3906c2a";

fn srv(id: &str, name: &str, host: &str, port: u16, l: Lifecycle) -> Server {
    Server {
        id: id.into(),
        name: name.into(),
        host: host.into(),
        port,
        server_key: KEY_A.into(),
        lifecycle: l,
        last_seen_unix: if l == Lifecycle::Ready { super::now_unix().saturating_sub(3 * 86_400 + 4 * 3600) } else { 0 },
        revoked_unix: if l == Lifecycle::Revoked { 1_699_920_000 } else { 0 },
    }
}

/// The servers of the demo.
pub fn demo_servers() -> Vec<Server> {
    vec![
        srv("ws", "Workstation", "203.0.113.10", 443, Lifecycle::Ready),
        srv("dev", "Dev box", "203.0.113.24", 443, Lifecycle::Ready),
        srv("vm", "Test VM", "203.0.113.88", 443, Lifecycle::Installing),
        srv("lab", "Home lab", "203.0.113.131", 8443, Lifecycle::Ready),
        srv("build", "Build server", "203.0.113.142", 443, Lifecycle::SetupPending),
        srv("old", "Old laptop box", "203.0.113.19", 443, Lifecycle::Revoked),
    ]
}

/// Forces a theme from the command line.
pub fn force_theme(ui: &crate::AppWindow, t: &str) {
    ui.global::<Tokens>().set_mode(match t {
        "dark" => ThemeMode::Dark,
        "light" => ThemeMode::Light,
        _ => ThemeMode::System,
    });
}

fn wiz(app: &Rc<App>, f: impl FnOnce(&mut super::wizard_ctl::Ctx)) {
    f(&mut app.wiz.borrow_mut());
}

fn preflight(bad: bool) -> Preflight {
    let row = |k: &str, t: &str, d: &str, s| CheckRow { key: k.into(), title: t.into(), detail: d.into(), status: s };
    use CheckStatus::{Fail, Pass};
    if bad {
        Preflight {
            connected_as: "Connected over SSH as root".into(),
            rows: vec![
                row("os", "Debian 12 (x86_64) is supported", "", Pass),
                row("cpus", "2 vCPU", "At least 2 needed", Pass),
                row("memory", "1.9 GB memory", "Missing: this server has 1.9 GB, the minimum is 4 GB", Fail),
                row("disk", "18 GB free disk", "Missing: 12 GB more free space; the minimum is 30 GB", Fail),
                row("port", "Port 443 is free for TCP and UDP", "", Pass),
            ],
            cpus: 2,
            memory_mib: 1946,
            disk_free_gib: 18,
        }
    } else {
        Preflight {
            connected_as: "Connected over SSH as root".into(),
            rows: vec![
                row("os", "Ubuntu 24.04.2 LTS (x86_64) is supported", "", Pass),
                row("cpus", "4 vCPU", "At least 2 needed", Pass),
                row("memory", "7.8 GB memory", "At least 4 GB needed", Pass),
                row("disk", "152 GB free disk", "At least 30 GB needed", Pass),
                row("port", "Port 443 is free for TCP and UDP", "Change it later under Resources, Advanced", Pass),
            ],
            cpus: 4,
            memory_mib: 7987,
            disk_free_gib: 152,
        }
    }
}

fn fill_account(app: &Rc<App>) {
    let vm = app.ui().global::<WizardVm>();
    vm.set_username(ss("alex"));
    vm.set_password(ss("correct horse battery"));
    vm.set_password2(ss("correct horse battery"));
    vm.set_pin(ss("482913"));
    vm.set_pin2(ss("482913"));
    wiz(app, |c| {
        c.w.username = "alex".into();
        c.w.password = "correct horse battery".into();
        c.w.password2 = c.w.password.clone();
        c.w.pin = "482913".into();
        c.w.pin2 = "482913".into();
    });
}

fn wizard_at(app: &Rc<App>, step: Step, method: Method) {
    super::wizard_ctl::open(app, false);
    wiz(app, |c| {
        c.w.set_method(method);
        c.w.address = "203.0.113.10".into();
        c.w.step = step;
        c.w.trusted = Some(("ED25519".into(), "SHA256:5Gk2xQ0m8vT1uZpJc3W9nLr7aYbHd4eFsIo6KtN2VhE".into()));
        c.w.preflight = Some(preflight(false));
        c.w.conn = ConnPhase::ChecksOk;
        c.w.docker = false;
    });
    let vm = app.ui().global::<WizardVm>();
    vm.set_address(ss("203.0.113.10"));
    if step == Step::Review {
        fill_account(app);
        wiz(app, |c| {
            c.w.cpu = 3;
            c.w.memory_gb = 5;
            c.w.disk_gb = 60;
            c.w.docker = true;
            c.w.docker_ack = true;
        });
        vm.set_cpu(3);
        vm.set_memory(5);
        vm.set_disk(60);
    }
    super::wizard_ctl::push_all(app);
}

fn progress_events(upto: &str) -> Vec<InstallEvent> {
    use crate::backend::demo::{Scenario, install_script};
    let all = install_script(Scenario::Success, 443);
    let mut out = Vec::new();
    for e in all {
        out.push(e.clone());
        if let InstallEvent::Step { index, .. } = &e
            && upto == "step5"
            && *index == 5
        {
            break;
        }
    }
    out
}

fn progress(app: &Rc<App>, kind: &str) {
    let id = "vm".to_owned();
    {
        let mut c = app.prog.borrow_mut();
        c.model = Model::with_clock(|| "14:02:11".into());
        c.server_id = Some(id);
        c.username = "alex".into();
        c.preset = "developer".into();
        c.distro = "Ubuntu 24.04".into();
    }
    let mut m = Model::with_clock(|| "14:08:02".into());
    let st = |id: &str, s: StageState, ms: Option<u64>| InstallEvent::Stage { id: id.into(), state: s, ms };
    match kind {
        "running" => {
            for e in progress_events("step5") {
                m.apply(e);
            }
        }
        "unknown" | "failed" => {
            m.apply(st("preflight", StageState::Done, Some(1200)));
            m.apply(st("packages", StageState::Done, Some(38_000)));
            m.apply(st("incus", StageState::Start, None));
            if kind == "failed" {
                m.apply(InstallEvent::Warn("retrying package index (1 of 3)".into()));
                m.apply(InstallEvent::Failed(InstallFailure {
                    stage: "incus".into(),
                    code: "UNAVAILABLE".into(),
                    message: "The package source could not be reached".into(),
                    retryable: true,
                }));
            }
        }
        "lost" => {
            for e in progress_events("step5").into_iter().take(40) {
                m.apply(e);
            }
            m.apply(InstallEvent::ConnectionLost { stage: "desktop".into() });
        }
        _ => {
            for e in crate::backend::demo::install_script(crate::backend::demo::Scenario::Success, 443) {
                m.apply(e);
            }
            m.apply(InstallEvent::Finished(InstallOutcome {
                server_key_hex: KEY_A.into(),
                addresses: vec![],
                port: 443,
                agent_version: "0.1.0".into(),
                image_path: "Built on the server".into(),
                elapsed_secs: 374,
            }));
        }
    }
    {
        let mut c = app.prog.borrow_mut();
        c.model = m;
        c.retry = if kind == "failed" { Some(super::progress_ctl::Retry::Ssh(crate::backend::InstallRequest {
            target: crate::backend::SshTarget { host: "203.0.113.88".into(), port: 22 },
            auth: crate::backend::SshAuth::DefaultKeys { user: "root".into() },
            host_key: crate::backend::HostKey { algorithm: "ED25519".into(), fingerprint: "x".into() },
            options: crate::wizard::Wizard::new().options(),
            password: crate::backend::Secret::new(""),
            pin: crate::backend::Secret::new(""),
            pairing_token: crate::backend::Secret::new(""),
        })) } else { None };
    }
    super::progress_ctl::push(app);
    app.go(Screen::Progress);
}

fn connect(app: &Rc<App>, outcome: Option<Outcome>, setup: impl FnOnce(&Rc<App>)) {
    super::connect_ctl::open(app, "ws");
    setup(app);
    if let Some(o) = outcome {
        let mut c = app.conn.borrow_mut();
        if matches!(o, Outcome::Revoked) && c.machine.state() != &crate::session::ConnectState::Revoked {
            c.machine.submit();
        } else {
            c.machine.submit();
        }
        c.machine.outcome(o);
    }
    super::connect_ctl::show(app);
}

fn desk_view(app: &Rc<App>) {
    let vm = app.ui().global::<DesktopVm>();
    vm.set_server_name(ss("Workstation"));
    vm.set_has_frame(true);
    vm.set_remote_w(1920);
    vm.set_remote_h(1080);
    vm.set_hint(false);
    vm.set_st_fps(ss("60 fps"));
    vm.set_st_latency(ss("14 ms"));
    vm.set_st_bitrate(ss("8.4 Mbps"));
    vm.set_st_encoding(ss("Software (x264)"));
    vm.set_st_screen(ss("1920 x 1080"));
    vm.set_overlay(0);
    vm.set_menu(0);
    vm.set_toolbar(false);
    vm.set_link_open(false);
    vm.set_drop_hover(false);
    vm.set_stats_on(false);
    vm.set_frame(demo_picture());
    app.go(Screen::Desktop);
}

/// A drawn desktop for the screenshots (remote content looks the same in both themes).
pub fn demo_picture() -> slint::Image {
    let (w, h) = (960u32, 540u32);
    let mut buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(w, h);
    let px = buf.make_mut_slice();
    for y in 0..h {
        for x in 0..w {
            let mut c = [30 + (y * 40 / h) as u8, 60 + (y * 50 / h) as u8, 110 + (x * 50 / w) as u8];
            if y < 28 {
                c = [58, 62, 68];
            } else if (60..560).contains(&x) && (70..400).contains(&y) {
                c = if y < 96 { [88, 94, 106] } else { [28, 30, 34] };
                if y >= 96 && (y - 96) % 20 < 2 && x > 80 && x < 420 {
                    c = [90, 200, 120];
                }
            } else if (600..900).contains(&x) && (120..360).contains(&y) {
                c = if y < 146 { [88, 94, 106] } else { [245, 246, 248] };
            }
            px[(y * w + x) as usize] = slint::Rgba8Pixel { r: c[0], g: c[1], b: c[2], a: 255 };
        }
    }
    slint::Image::from_rgba8(buf)
}

fn details(app: &Rc<App>, id: &str, tab: i32) {
    super::details_ctl::open(app, id);
    let vm = app.ui().global::<DetailsVm>();
    vm.set_tab(tab);
}

fn security_rows(app: &Rc<App>) {
    let vm = app.ui().global::<DetailsVm>();
    let row = |id: &str, name: &str, seen: &str, state: &str, tone, current, can| DeviceRowData {
        id: ss(id),
        name: ss(name),
        last_seen: ss(seen),
        state: ss(state),
        tone,
        current,
        can_revoke: can,
    };
    vm.set_devices(model(vec![
        row("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", "Alex's desktop (a1a1a1a1)", "now", "Active", 1, true, true),
        row("b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2", "Maya's laptop (b2b2b2b2)", "Today 13:58", "Active", 1, false, true),
        row("d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4", "Old tablet (d4d4d4d4)", "14 Nov", "Revoked", 3, false, false),
        row("c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3", "Work PC (c3c3c3c3)", "2 days ago", "Active", 1, false, true),
    ]));
    vm.set_devices_note(ss("Devices paired with this server. Revoked ones stay listed so you can see what happened."));
    vm.set_tab(1);
}

/// Opens the named state. Returns false for an unknown name.
pub fn apply(app: &Rc<App>, name: &str) -> bool {
    let ui = app.ui();
    match name {
        "home" => app.show_home(),
        "home-empty" => {
            let ids: Vec<String> = app.store.borrow().list().iter().map(|s| s.id.clone()).collect();
            for i in ids {
                let _ = app.store.borrow_mut().remove(&i);
            }
            app.show_home();
        }
        "home-loading" => {
            super::home::refresh(app, true);
            app.go(Screen::Home);
        }
        "wizard-method" => wizard_at(app, Step::Method, Method::Ssh),
        "wizard-connection" => {
            wizard_at(app, Step::Connection, Method::Ssh);
            wiz(app, |c| c.w.conn = ConnPhase::Form);
            super::wizard_ctl::push_all(app);
        }
        "wizard-hostkey" => {
            wizard_at(app, Step::Connection, Method::Ssh);
            wiz(app, |c| {
                c.w.conn = ConnPhase::HostKey {
                    algorithm: "ED25519".into(),
                    fingerprint: "SHA256:5Gk2xQ0m8vT1uZpJc3W9nLr7aYbHd4eFsIo6KtN2VhE".into(),
                }
            });
            super::wizard_ctl::push_all(app);
        }
        "wizard-checks-ok" => wizard_at(app, Step::Connection, Method::Ssh),
        "wizard-checks-bad" => {
            wizard_at(app, Step::Connection, Method::Ssh);
            wiz(app, |c| {
                c.w.preflight = Some(preflight(true));
                c.w.conn = ConnPhase::ChecksBad;
            });
            super::wizard_ctl::push_all(app);
        }
        "wizard-desktop" => wizard_at(app, Step::Desktop, Method::Ssh),
        "wizard-docker" => {
            wizard_at(app, Step::Desktop, Method::Ssh);
            wiz(app, |c| c.w.docker = true);
            let vm = ui.global::<WizardVm>();
            vm.set_docker(true);
            super::wizard_ctl::push_all(app);
        }
        "wizard-account" => {
            wizard_at(app, Step::Account, Method::Ssh);
            fill_account(app);
            super::wizard_ctl::push_all(app);
        }
        "wizard-account-errors" => {
            wizard_at(app, Step::Account, Method::Ssh);
            wiz(app, |c| {
                c.w.username = "Alex".into();
                c.w.password = "aaaa".into();
                c.w.password2 = "aaab".into();
                c.w.pin = "123".into();
                c.w.show_errors = true;
            });
            let vm = ui.global::<WizardVm>();
            vm.set_username(ss("Alex"));
            vm.set_password(ss("aaaa"));
            vm.set_password2(ss("aaab"));
            vm.set_pin(ss("123"));
            super::wizard_ctl::push_all(app);
        }
        "wizard-backups" => wizard_at(app, Step::Backups, Method::Ssh),
        "wizard-resources" => {
            wizard_at(app, Step::Resources, Method::Ssh);
            let vm = ui.global::<WizardVm>();
            vm.set_cpu(3);
            vm.set_memory(5);
            vm.set_disk(60);
        }
        "wizard-review" => wizard_at(app, Step::Review, Method::Ssh),
        "wizard-oneliner-server" => wizard_at(app, Step::Server, Method::OneLiner),
        "wizard-run-waiting" | "wizard-run-expired" | "wizard-run-unreachable" | "wizard-run-paired" => {
            wizard_at(app, Step::RunOnServer, Method::OneLiner);
            wiz(app, |c| {
                c.w.address = "203.0.113.142".into();
                c.w.username = "alex".into();
                c.w.docker = true;
                c.w.docker_ack = true;
                c.w.cpu = 3;
                c.w.memory_gb = 5;
                c.w.disk_gb = 60;
                c.token = Some("hxt1-aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypsaijcemsckjrh".into());
            });
            let vm = ui.global::<WizardVm>();
            vm.set_address(ss("203.0.113.142"));
            let (phase, status) = match name {
                "wizard-run-expired" => (1, ""),
                "wizard-run-unreachable" => (2, ""),
                "wizard-run-paired" => (3, "Server identity pinned: 3f9a c1d4 77be 0a52."),
                _ => (0, "Waiting for the server… Looking for the agent at 203.0.113.142:443. This starts as soon as the installer opens the port."),
            };
            vm.set_run_phase(phase);
            vm.set_run_status(ss(status));
            super::wizard_ctl::push_all(app);
        }
        "wizard-code" | "wizard-code-failed" => {
            super::wizard_ctl::open(app, true);
            let vm = ui.global::<WizardVm>();
            vm.set_address(ss("203.0.113.10"));
            vm.set_code(ss("K7QM-4XD2"));
            wiz(app, |c| {
                c.w.address = "203.0.113.10".into();
                c.w.code = "K7QM-4XD2".into();
            });
            super::wizard_ctl::push_all(app);
            if name == "wizard-code-failed" {
                vm.set_banner_title(ss("That code did not work"));
                vm.set_banner_text(ss("It may have expired (15 minutes), been used, or typed wrong. After 3 wrong tries a code stops working. Run hx-agent pairing code on the server for a new one."));
            }
        }
        "progress-running" => progress(app, "running"),
        "progress-unknown" => progress(app, "unknown"),
        "progress-failed" => progress(app, "failed"),
        "progress-lost" => progress(app, "lost"),
        "progress-success" => progress(app, "success"),
        "connect-pin" => connect(app, None, |_| {}),
        "connect-checking" => {
            connect(app, None, |_| {});
            app.conn.borrow_mut().machine.submit();
            app.conn.borrow_mut().machine.secure();
            super::connect_ctl::show(app);
        }
        "connect-wrong" => connect(app, Some(Outcome::Wrong { attempts_left: 4, retry_after: Duration::ZERO }), |_| {}),
        "connect-wait" => connect(app, Some(Outcome::Wrong { attempts_left: 2, retry_after: Duration::from_secs(8) }), |_| {}),
        "connect-last" => connect(app, Some(Outcome::Wrong { attempts_left: 1, retry_after: Duration::ZERO }), |_| {}),
        "connect-revoked" => connect(app, Some(Outcome::Revoked), |_| {}),
        "connect-pair-again" => {
            connect(app, Some(Outcome::Revoked), |_| {});
            app.conn.borrow_mut().machine.pair_again();
            super::connect_ctl::show(app);
        }
        "connect-unavailable" => connect(app, Some(Outcome::NotAvailable { retry_after: Duration::from_secs(58) }), |_| {}),
        "connect-unreachable" => connect(app, Some(Outcome::Unreachable("no answer".into())), |_| {}),
        "connect-identity" => connect(app, Some(Outcome::IdentityChanged), |_| {}),
        "desktop" => {
            desk_view(app);
            ui.global::<DesktopVm>().set_hint(true);
        }
        "desktop-toolbar" | "desktop-display" | "desktop-quality" | "desktop-keys" | "desktop-transfers" => {
            desk_view(app);
            let vm = ui.global::<DesktopVm>();
            vm.set_toolbar(true);
            vm.set_menu(match name {
                "desktop-display" => 1,
                "desktop-quality" => 2,
                "desktop-keys" => 3,
                "desktop-transfers" => 4,
                _ => 0,
            });
            if name == "desktop-transfers" {
                vm.set_activities(model(vec![
                    ActivityData { name: ss("report-q3.pdf"), direction: ss("up"), percent: 62, state: ss("62%"), failed: false },
                    ActivityData { name: ss("screenshot.png"), direction: ss("down"), percent: 100, state: ss("done"), failed: false },
                ]));
            }
        }
        "desktop-stats" => {
            desk_view(app);
            ui.global::<DesktopVm>().set_stats_on(true);
        }
        "desktop-files" => {
            desk_view(app);
            let vm = ui.global::<DesktopVm>();
            vm.set_drop_hover(true);
        }
        "desktop-reconnect" | "desktop-gave-up" | "desktop-takeover" | "desktop-unavailable" => {
            desk_view(app);
            let vm = ui.global::<DesktopVm>();
            match name {
                "desktop-reconnect" => {
                    vm.set_overlay(1);
                    vm.set_attempt(3);
                    vm.set_next_secs(4);
                }
                "desktop-gave-up" => vm.set_overlay(2),
                "desktop-takeover" => {
                    vm.set_takeover_title(ss("This desktop was opened on another device"));
                    vm.set_takeover_text(ss("Maya's laptop (b2b2b2b2) connected to Workstation and took over, so this session ended. Nothing on the desktop was closed."));
                    vm.set_can_revoke(true);
                    vm.set_overlay(3);
                }
                _ => vm.set_overlay(4),
            }
        }
        "desktop-open-link" => {
            desk_view(app);
            let vm = ui.global::<DesktopVm>();
            vm.set_link_prefix(ss("https://"));
            vm.set_link_host(ss("docs.example.test"));
            vm.set_link_rest(ss("/guide/getting-started?ref=desktop"));
            vm.set_link_open(true);
        }
        "details-overview" | "details-problems" | "details-offline" => {
            let id = match name {
                "details-problems" => "dev",
                "details-offline" => "lab",
                _ => "ws",
            };
            details(app, id, 0);
        }
        "details-security" | "details-revoke" | "details-revoke-self" | "details-pair" | "details-pin" | "details-password" => {
            details(app, "ws", 1);
            security_rows(app);
            let vm = ui.global::<DetailsVm>();
            vm.set_dialog_error(ss(""));
            match name {
                "details-revoke" => {
                    vm.set_dialog_text(ss("Maya's laptop"));
                    vm.set_dialog(1);
                }
                "details-revoke-self" => {
                    vm.set_dialog_text(ss("Alex's desktop"));
                    vm.set_dialog(2);
                }
                "details-pair" => {
                    vm.set_pair_code(ss("K7QM-4XD2"));
                    vm.set_pair_address(ss("203.0.113.10:443"));
                    vm.set_pair_expiry(ss(crate::details::expiry_text(892, 3)));
                    vm.set_dialog(3);
                }
                "details-pin" => vm.set_dialog(4),
                "details-password" => {
                    vm.set_f2(ss("correct horse battery"));
                    vm.set_strength_word(ss("good"));
                    vm.set_dialog(5);
                }
                _ => {}
            }
        }
        "details-desktop" | "details-docker" | "details-restart" => {
            details(app, "ws", 2);
            let vm = ui.global::<DetailsVm>();
            vm.set_docker(true);
            vm.set_cpu_max(4);
            vm.set_memory_max(5);
            vm.set_disk_max(152);
            vm.set_cpu(3);
            vm.set_memory(5);
            vm.set_disk(60);
            vm.set_agent_line(ss("Version 0.1.0, up to date. Updates also apply by themselves on the stable channel."));
            vm.set_docker_dialog(name == "details-docker");
            vm.set_restart_dialog(name == "details-restart");
        }
        "details-danger" | "details-danger-ssh" | "details-danger-confirm" | "details-danger-done" => {
            details(app, "ws", 3);
            let vm = ui.global::<DetailsVm>();
            match name {
                "details-danger-ssh" => vm.set_danger(1),
                "details-danger-confirm" => {
                    vm.set_keep_desktop(false);
                    vm.set_danger(2);
                }
                "details-danger-done" => {
                    vm.set_done_text(ss(format!(
                        "hash-xcreen was uninstalled from 203.0.113.10. The desktop was kept on the server. Incus and its package source remain installed. To remove them, run on the server: {}",
                        crate::details::REMOVE_INCUS
                    )));
                    vm.set_danger(4);
                }
                _ => {}
            }
        }
        "settings" => app.go(Screen::Settings),
        _ => return false,
    }
    let _ = Kv { key: ss(""), value: ss("") };
    true
}
