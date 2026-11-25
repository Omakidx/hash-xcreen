//! hash-xcreen desktop client.
//!
//! `hx-desktop` runs against real servers. `hx-desktop --demo` runs the whole app against
//! fakes (see README.md); `--screen <name>` opens a demo state directly (for screenshots).

use std::sync::Arc;

use hx_desktop::AppWindow;
use hx_desktop::app::{App, Config, Prefs, showcase};
use hx_desktop::backend::{demo, real};
use hx_desktop::keys::{KeyringStore, MemoryKeyStore};
use hx_desktop::servers;
use slint::ComponentHandle;

fn usage() -> &'static str {
    "hx-desktop [--demo] [--screen NAME] [--theme system|dark|light]\n\
     \n\
     --demo         run against fakes: no server, no keyring, nothing is saved\n\
     --screen NAME  with --demo: open a state of the design mockups (see README.md)\n\
     --theme T      force the theme (default: follow the system)\n\
     --version      print the version"
}

fn main() -> Result<(), slint::PlatformError> {
    let mut demo_mode = false;
    let mut screen: Option<String> = None;
    let mut theme: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--demo" => demo_mode = true,
            "--screen" => screen = args.next(),
            "--theme" => theme = args.next(),
            "--version" | "-V" => {
                println!("hx-desktop {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--help" | "-h" => {
                println!("{}", usage());
                return Ok(());
            }
            other => {
                eprintln!("unknown argument {other}\n{}", usage());
                std::process::exit(2);
            }
        }
    }
    if screen.is_some() && !demo_mode {
        eprintln!("--screen needs --demo\n{}", usage());
        std::process::exit(2);
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("HX_LOG"))
        .with_writer(std::io::stderr)
        .try_init();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");

    // The id of the packaged desktop file (X11 WM_CLASS, Wayland app id).
    // The app id needs an existing platform: select the backend (SLINT_BACKEND is honoured) first.
    // Without a GPU, OpenGL runs on the CPU and costs ten times the software renderer
    // (architecture 6.5); SLINT_BACKEND still overrides this.
    let mut backend = slint::BackendSelector::new();
    if cfg!(target_os = "linux")
        && std::env::var_os("SLINT_BACKEND").is_none()
        && hx_desktop::video::opengl_runs_on_cpu(
            std::env::var_os("LIBGL_ALWAYS_SOFTWARE").as_deref(),
            std::path::Path::new("/dev/dri"),
        )
    {
        tracing::info!("no GPU render node: Slint's software renderer");
        backend = backend.renderer_name("software".into());
    }
    backend.select()?;
    slint::set_xdg_app_id("io.github.omakidx.hashxcreen")?;
    let ui = AppWindow::new()?;
    let cfg = if demo_mode {
        Config {
            demo: true,
            config_dir: None,
            backends: demo::backends(demo::Pace::slow()),
            key_store: Arc::new(MemoryKeyStore::default()),
            seed: showcase::demo_servers(),
        }
    } else {
        let dir = servers::config_dir();
        let name = Prefs::load(dir.as_ref().map(|d| d.join("prefs.json")).as_ref()).device_name;
        Config {
            demo: false,
            config_dir: dir,
            backends: real::backends(rt.handle().clone(), name),
            key_store: Arc::new(KeyringStore),
            seed: Vec::new(),
        }
    };
    let app = App::start(&ui, rt.handle().clone(), cfg);
    if let Some(t) = theme {
        showcase::force_theme(&ui, &t);
    }
    if let Some(s) = screen
        && !showcase::apply(&app, &s)
    {
        eprintln!("unknown screen {s}; known: {}", showcase::NAMES.join(", "));
        std::process::exit(2);
    }
    ui.run()?;
    drop(app);
    drop(rt);
    Ok(())
}
