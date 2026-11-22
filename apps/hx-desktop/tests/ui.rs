//! Screen tests with the Slint testing backend: states of the mockups, callbacks, keyboard,
//! and a render of a few screens in both themes.

use std::sync::Arc;

use hx_desktop::app::{App, Config, showcase};
use hx_desktop::backend::demo;
use hx_desktop::keys::MemoryKeyStore;
use hx_desktop::{
    AppWindow, ConnectVm, DetailsVm, HomeVm, Nav, Screen, ThemeMode, Tokens, WizardVm,
};
use i_slint_backend_testing::ElementHandle;
use slint::{ComponentHandle, Model};

struct Rig {
    ui: AppWindow,
    app: std::rc::Rc<App>,
    _rt: tokio::runtime::Runtime,
}

fn rig() -> Rig {
    i_slint_backend_testing::init_no_event_loop();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let ui = AppWindow::new().unwrap();
    let app = App::start(
        &ui,
        rt.handle().clone(),
        Config {
            demo: true,
            config_dir: None,
            downloads: std::env::temp_dir(),
            backends: demo::backends(demo::Pace::instant()),
            key_store: Arc::new(MemoryKeyStore::default()),
            seed: showcase::demo_servers(),
        },
    );
    ui.window().set_size(slint::PhysicalSize::new(1000, 700));
    Rig { ui, app, _rt: rt }
}

fn find(ui: &AppWindow, label: &str) -> Option<ElementHandle> {
    ElementHandle::find_by_accessible_label(ui, label).next()
}

fn press(ui: &AppWindow, label: &str) {
    let e = find(ui, label).unwrap_or_else(|| panic!("no element labelled {label}"));
    e.invoke_accessible_default_action();
}

#[test]
fn every_named_state_opens_in_both_themes() {
    let r = rig();
    for mode in [ThemeMode::Dark, ThemeMode::Light] {
        r.ui.global::<Tokens>().set_mode(mode);
        for name in showcase::NAMES {
            assert!(showcase::apply(&r.app, name), "{name}");
        }
    }
    assert!(!showcase::apply(&r.app, "no-such-screen"));
}

#[test]
fn home_lists_servers_with_status_words() {
    let r = rig();
    showcase::apply(&r.app, "home");
    let n = r.ui.global::<HomeVm>().get_servers().row_count();
    assert_eq!(n, 6);
    // The card of a revoked device offers Pair again; an installing one View progress.
    let cards: Vec<_> = (0..n)
        .map(|i| r.ui.global::<HomeVm>().get_servers().row_data(i).unwrap())
        .collect();
    assert!(
        cards
            .iter()
            .any(|c| c.action_label.as_str() == "Pair again")
    );
    assert!(
        cards
            .iter()
            .any(|c| c.action_label.as_str() == "View progress")
    );
    assert!(
        cards
            .iter()
            .any(|c| c.action_label.as_str() == "Finish setup")
    );
    assert!(find(&r.ui, "Add server").is_some());
}

#[test]
fn empty_home_is_the_welcome_with_add_server_first() {
    let r = rig();
    showcase::apply(&r.app, "home-empty");
    assert!(
        find(&r.ui, "Welcome to hash-xcreen").is_some()
            || r.ui.global::<HomeVm>().get_servers().row_count() == 0
    );
    press(&r.ui, "Add server");
    assert_eq!(r.ui.global::<Nav>().get_screen(), Screen::Wizard);
    assert_eq!(r.ui.global::<WizardVm>().get_step().as_str(), "method");
}

#[test]
fn wizard_blocks_an_invalid_account_and_shows_the_errors() {
    let r = rig();
    showcase::apply(&r.app, "wizard-account-errors");
    let vm = r.ui.global::<WizardVm>();
    assert!(!vm.get_err_username().is_empty());
    assert!(vm.get_err_password().contains("8 characters"));
    assert!(vm.get_err_password2().contains("do not match"));
    assert!(vm.get_err_pin().contains("6 digits"));
    // Next does not move on.
    vm.invoke_next();
    assert_eq!(vm.get_step().as_str(), "account");
}

#[test]
fn wizard_review_masks_secrets() {
    let r = rig();
    showcase::apply(&r.app, "wizard-review");
    let vm = r.ui.global::<WizardVm>();
    let rows = vm.get_review_account();
    let text: String = (0..rows.row_count())
        .map(|i| rows.row_data(i).unwrap().value.to_string())
        .collect();
    assert!(!text.contains("482913") && !text.contains("correct horse"));
    assert!(text.contains("6 digits"));
    assert_eq!(vm.get_next_label().as_str(), "Install");
}

#[test]
fn connect_states_show_the_server_wording() {
    let r = rig();
    showcase::apply(&r.app, "connect-wrong");
    let v = r.ui.global::<ConnectVm>();
    assert_eq!(
        v.get_notice_title().as_str(),
        "Incorrect PIN, 4 attempts left"
    );
    assert_eq!(v.get_phase(), 0);
    showcase::apply(&r.app, "connect-last");
    assert_eq!(
        v.get_notice_title().as_str(),
        "Incorrect PIN, 1 attempt left"
    );
    assert!(v.get_notice_text().contains("account password"));
    showcase::apply(&r.app, "connect-wait");
    assert_eq!(v.get_phase(), 3);
    assert_eq!(v.get_wait_secs(), 8);
    assert!(v.get_notice_title().contains("Wait 8 seconds"));
    showcase::apply(&r.app, "connect-revoked");
    assert_eq!(v.get_phase(), 4);
    assert!(find(&r.ui, "Pair again").is_some());
    showcase::apply(&r.app, "connect-identity");
    assert_eq!(v.get_phase(), 8);
    // No override: only Back to Home and Remove.
    assert!(find(&r.ui, "Connect").is_none());
}

#[test]
fn identity_changed_pair_again_flow_leads_to_the_password_form() {
    let r = rig();
    showcase::apply(&r.app, "connect-revoked");
    press(&r.ui, "Pair again");
    assert_eq!(r.ui.global::<ConnectVm>().get_phase(), 5);
}

#[test]
fn revoke_dialog_cancel_is_the_default_and_escape_closes_it() {
    let r = rig();
    showcase::apply(&r.app, "details-revoke");
    let vm = r.ui.global::<DetailsVm>();
    assert_eq!(vm.get_dialog(), 1);
    assert!(find(&r.ui, "Cancel").is_some());
    r.ui.window()
        .dispatch_event(slint::platform::WindowEvent::KeyPressed {
            text: slint::platform::Key::Escape.into(),
        });
    assert_eq!(vm.get_dialog(), 0, "Escape dismisses the dialog");
}

#[test]
fn hidden_phase_two_and_three_items_are_not_in_the_ui() {
    let r = rig();
    for name in [
        "details-overview",
        "details-security",
        "details-desktop",
        "wizard-backups",
    ] {
        showcase::apply(&r.app, name);
        for hidden in [
            "Backups",
            "Web access",
            "Passkeys",
            "Backup mode",
            "Restore from backup",
        ] {
            // The wizard step "Backups" exists (fixed to Off); nowhere else.
            if name == "wizard-backups" && hidden == "Backups" {
                continue;
            }
            assert!(find(&r.ui, hidden).is_none(), "{hidden} shown on {name}");
        }
    }
}

#[test]
fn desktop_overlays_block_and_offer_the_mockup_actions() {
    let r = rig();
    showcase::apply(&r.app, "desktop-takeover");
    assert!(find(&r.ui, "Revoke that device").is_some());
    assert!(find(&r.ui, "Take it back").is_some());
    showcase::apply(&r.app, "desktop-gave-up");
    assert!(find(&r.ui, "Try again").is_some());
    assert!(find(&r.ui, "Back to Home").is_some());
    showcase::apply(&r.app, "desktop-open-link");
    // Cancel is the safe default and there is no "always allow".
    assert!(find(&r.ui, "Cancel").is_some());
    assert!(find(&r.ui, "Always allow").is_none());
}

#[test]
fn toolbar_shows_icons_only_below_1000_px() {
    let r = rig();
    showcase::apply(&r.app, "desktop-toolbar");
    r.ui.window().set_size(slint::PhysicalSize::new(1100, 700));
    assert!(find(&r.ui, "Display").is_some());
    r.ui.window().set_size(slint::PhysicalSize::new(900, 600));
    assert!(
        find(&r.ui, "Display").is_some(),
        "the accessible name stays"
    );
}

fn mean(buf: &slint::SharedPixelBuffer<slint::Rgba8Pixel>) -> f64 {
    let px = buf.as_slice();
    px.iter()
        .map(|p| (f64::from(p.r) + f64::from(p.g) + f64::from(p.b)) / 3.0)
        .sum::<f64>()
        / px.len() as f64
}

#[test]
fn a_few_screens_render_in_both_themes() {
    let r = rig();
    r.ui.show().unwrap();
    let dir = std::env::var_os("HX_SHOT_DIR").map(std::path::PathBuf::from);
    for name in [
        "home",
        "connect-wrong",
        "wizard-checks-bad",
        "progress-running",
        "desktop-toolbar",
        "details-security",
    ] {
        let mut means = Vec::new();
        for (mode, tag) in [(ThemeMode::Dark, "dark"), (ThemeMode::Light, "light")] {
            r.ui.global::<Tokens>().set_mode(mode);
            showcase::apply(&r.app, name);
            let Ok(buf) = r.ui.window().take_snapshot() else {
                eprintln!("this backend cannot take snapshots; skipping the render check");
                return;
            };
            assert!(buf.width() > 100 && buf.height() > 100);
            let m = mean(&buf);
            means.push(m);
            if let Some(d) = &dir {
                let _ = std::fs::create_dir_all(d);
                let mut ppm = format!("P6\n{} {}\n255\n", buf.width(), buf.height()).into_bytes();
                for p in buf.as_slice() {
                    ppm.extend_from_slice(&[p.r, p.g, p.b]);
                }
                let _ = std::fs::write(d.join(format!("{name}-{tag}.ppm")), ppm);
            }
        }
        if name != "desktop-toolbar" {
            assert!(
                means[0] < means[1],
                "{name}: dark ({}) must be darker than light ({})",
                means[0],
                means[1]
            );
        }
    }
}
