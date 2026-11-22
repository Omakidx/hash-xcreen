//! The controller: state and navigation. Screens live in the Slint files; their view models are
//! the globals of `ui/state.slint`; this module fills them and handles their callbacks.
//!
//! Everything here runs on the UI thread. Network work runs on the tokio runtime and comes back
//! through [`spawn_ui`], which posts a closure to the event loop.

pub mod connect_ctl;
pub mod desktop_ctl;
pub mod details_ctl;
pub mod home;
pub mod known_hosts;
pub mod prefs;
pub mod progress;
pub mod progress_ctl;
pub mod showcase;
pub mod update_ctl;
pub mod wizard_ctl;

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::rc::{Rc, Weak};
use std::sync::Arc;

use hx_crypto::IdentityKey;
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use crate::backend::Backends;
use crate::servers::{Server, ServerStore};
use crate::{AppWindow, DesktopVm, HomeVm, Nav, Screen, SettingsVm, ThemeMode, Tokens};

pub use prefs::Prefs;

/// Everything the app needs to start.
pub struct Config {
    /// Demo mode: fakes for every backend, nothing real is touched.
    pub demo: bool,
    /// Where servers, settings and known hosts live; `None` keeps everything in memory.
    pub config_dir: Option<PathBuf>,
    /// Where received files are saved.
    pub downloads: PathBuf,
    /// The backends.
    pub backends: Backends,
    /// Where the device key lives.
    pub key_store: Arc<dyn crate::keys::SecretStore>,
    /// Demo servers to start with (demo mode only).
    pub seed: Vec<Server>,
}

thread_local! {
    static CURRENT: RefCell<Option<Weak<App>>> = const { RefCell::new(None) };
}

/// The application state. One instance, on the UI thread.
pub struct App {
    pub(crate) ui: AppWindow,
    pub(crate) rt: tokio::runtime::Handle,
    pub(crate) be: Backends,
    pub(crate) key: Arc<IdentityKey>,
    pub(crate) store: RefCell<ServerStore>,
    pub(crate) prefs: RefCell<Prefs>,
    pub(crate) prefs_path: Option<PathBuf>,
    pub(crate) hosts: RefCell<known_hosts::KnownHosts>,
    pub(crate) downloads: PathBuf,
    pub(crate) reachable: RefCell<HashMap<String, bool>>,
    pub(crate) unavailable: RefCell<HashSet<String>>,
    pub(crate) wiz: RefCell<wizard_ctl::Ctx>,
    pub(crate) prog: RefCell<progress_ctl::Ctx>,
    pub(crate) conn: RefCell<connect_ctl::Ctx>,
    pub(crate) desk: RefCell<desktop_ctl::Ctx>,
    pub(crate) det: RefCell<details_ctl::Ctx>,
}

/// Runs `fut` on the runtime and then `then` on the UI thread with its result.
pub fn spawn_ui<T: Send + 'static>(
    app: &Rc<App>,
    fut: impl Future<Output = T> + Send + 'static,
    then: impl FnOnce(&Rc<App>, T) + Send + 'static,
) {
    app.rt.spawn(async move {
        let v = fut.await;
        post(move |a| then(a, v));
    });
}

/// Runs `f` on the UI thread with the app (does nothing if the app is gone).
pub fn post(f: impl FnOnce(&Rc<App>) + Send + 'static) {
    let _ = slint::invoke_from_event_loop(move || {
        let app = CURRENT.with(|c| c.borrow().as_ref().and_then(Weak::upgrade));
        if let Some(app) = app {
            f(&app);
        }
    });
}

/// Unix seconds now.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub(crate) fn ss(s: impl AsRef<str>) -> SharedString {
    SharedString::from(s.as_ref())
}

pub(crate) fn model<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(v))
}

impl App {
    /// Builds the app on `ui`, wires every callback and shows Home (or the blocking error).
    pub fn start(ui: &AppWindow, rt: tokio::runtime::Handle, cfg: Config) -> Rc<App> {
        let prefs_path = cfg.config_dir.as_ref().map(|d| d.join("prefs.json"));
        let prefs = Prefs::load(prefs_path.as_ref());
        let key = crate::keys::load_or_create(&*cfg.key_store);
        let store = match &cfg.config_dir {
            Some(d) => ServerStore::open(d.join("servers.json")),
            None => Ok(ServerStore::in_memory(cfg.seed.clone())),
        };
        let hosts = known_hosts::KnownHosts::open(
            cfg.config_dir.as_ref().map(|d| d.join("known_hosts.json")),
        );
        let (key, store, fatal) = match (key, store) {
            (Ok(k), Ok(s)) => (Some(k), Some(s), None),
            (Err(e), _) => (
                None,
                None,
                Some((
                    "The system keyring is not available".to_owned(),
                    format!(
                        "hash-xcreen keeps this device's key in the system keyring (Secret Service) and will not store it in a file. {e}. Start a keyring (GNOME Keyring or KWallet), sign in again, and open the app again."
                    ),
                )),
            ),
            (_, Err(e)) => (
                None,
                None,
                Some((
                    "The server list could not be read".to_owned(),
                    format!(
                        "{e}. The file was left as it is. Fix or move it, then open the app again."
                    ),
                )),
            ),
        };
        let app = Rc::new(App {
            ui: ui.clone_strong(),
            rt,
            be: cfg.backends,
            key: key.unwrap_or_else(|| Arc::new(IdentityKey::generate().expect("random source"))),
            store: RefCell::new(store.unwrap_or_else(|| ServerStore::in_memory(Vec::new()))),
            prefs: RefCell::new(prefs),
            prefs_path,
            hosts: RefCell::new(hosts),
            downloads: cfg.downloads,
            reachable: RefCell::default(),
            unavailable: RefCell::default(),
            wiz: RefCell::default(),
            prog: RefCell::default(),
            conn: RefCell::default(),
            desk: RefCell::default(),
            det: RefCell::default(),
        });
        CURRENT.with(|c| *c.borrow_mut() = Some(Rc::downgrade(&app)));
        ui.global::<Nav>().set_demo(cfg.demo);
        ui.global::<Nav>().on_quit(|| {
            let _ = slint::quit_event_loop();
        });
        app.apply_prefs();
        home::wire(&app);
        wizard_ctl::wire(&app);
        progress_ctl::wire(&app);
        connect_ctl::wire(&app);
        desktop_ctl::wire(&app);
        details_ctl::wire(&app);
        wire_settings(&app);
        update_ctl::wire(&app);
        if let Some((title, text)) = fatal {
            let nav = ui.global::<Nav>();
            nav.set_fatal_title(ss(title));
            nav.set_fatal_text(ss(text));
            nav.set_screen(Screen::Fatal);
        } else {
            app.show_home();
        }
        app
    }

    /// The window.
    pub fn ui(&self) -> &AppWindow {
        &self.ui
    }

    /// Switches screen.
    pub fn go(&self, s: Screen) {
        let ui = self.ui();
        let nav = ui.global::<Nav>();
        nav.set_title(ss(match s {
            Screen::Desktop => format!(
                "{} - hx-desktop",
                ui.global::<DesktopVm>().get_server_name()
            ),
            _ => "hx-desktop".to_owned(),
        }));
        nav.set_screen(s);
    }

    /// A saved server by id.
    pub fn server(&self, id: &str) -> Option<Server> {
        self.store.borrow().get(id).cloned()
    }

    /// Applies the theme and reduced-motion setting.
    pub fn apply_prefs(&self) {
        let ui = self.ui();
        let p = self.prefs.borrow();
        let t = ui.global::<Tokens>();
        t.set_mode(match p.theme {
            1 => ThemeMode::Dark,
            2 => ThemeMode::Light,
            _ => ThemeMode::System,
        });
        t.set_reduced_motion(std::env::var_os("HX_REDUCED_MOTION").is_some());
        let s = ui.global::<SettingsVm>();
        s.set_theme(i32::from(p.theme));
        s.set_quality(i32::from(p.quality));
        s.set_bandwidth(i32::from(p.bandwidth));
        s.set_capture_keys(p.capture_keys);
        s.set_clip_send(p.clip_send);
        s.set_clip_receive(p.clip_receive);
        s.set_clip_files(p.clip_files);
        s.set_start_at_login(p.start_at_login);
        s.set_device_name(ss(&p.device_name));
        s.set_version(ss(env!("CARGO_PKG_VERSION")));
        let d = ui.global::<DesktopVm>();
        d.set_quality(i32::from(p.quality));
        d.set_capture_keys(p.capture_keys);
        d.set_hint(!p.hint_seen);
    }

    /// The device name for pairing and sessions.
    pub fn device_name(&self) -> String {
        self.prefs.borrow().device_name.clone()
    }

    /// The clipboard policy from the settings.
    pub fn clip_policy(&self) -> crate::clipboard::Policy {
        let p = self.prefs.borrow();
        crate::clipboard::Policy {
            send: p.clip_send,
            receive: p.clip_receive,
            files: p.clip_files,
        }
    }

    /// Sets the local clipboard text (through the window's hidden text input).
    pub fn set_clipboard(&self, text: &str) {
        self.ui().invoke_clipboard_write(ss(text));
    }

    /// Reads the local clipboard text.
    pub fn get_clipboard(&self) -> String {
        self.ui().invoke_clipboard_read().to_string()
    }

    /// Shows Home with the current list and starts the reachability checks.
    pub fn show_home(self: &Rc<Self>) {
        home::refresh(self, true);
        self.go(Screen::Home);
        home::probe_all(self);
    }
}

fn wire_settings(app: &Rc<App>) {
    let ui = app.ui();
    let s = ui.global::<SettingsVm>();
    let a = app.clone();
    s.on_changed(move || {
        let ui = a.ui();
        let v = ui.global::<SettingsVm>();
        {
            let mut p = a.prefs.borrow_mut();
            p.theme = v.get_theme() as u8;
            p.quality = v.get_quality() as u8;
            p.bandwidth = v.get_bandwidth() as u8;
            p.capture_keys = v.get_capture_keys();
            p.clip_send = v.get_clip_send();
            p.clip_receive = v.get_clip_receive();
            p.clip_files = v.get_clip_files();
            p.start_at_login = v.get_start_at_login();
            p.device_name = prefs::clean_device_name(&v.get_device_name());
            p.save(a.prefs_path.as_ref());
        }
        // Theme applies at once; the others are read when a desktop opens.
        let t = ui.global::<Tokens>();
        t.set_mode(match v.get_theme() {
            1 => ThemeMode::Dark,
            2 => ThemeMode::Light,
            _ => ThemeMode::System,
        });
    });
    let a = app.clone();
    s.on_done(move || a.show_home());
    let a = app.clone();
    ui.global::<HomeVm>()
        .on_open_settings(move || a.go(Screen::Settings));
}

/// Collects a model into a vec.
pub(crate) fn to_vec<T: Clone + 'static>(m: ModelRc<T>) -> Vec<T> {
    m.iter().collect()
}
