//! hx-gatewayd: the internet-facing, unprivileged gateway.
//!
//! `hx-gatewayd [--config <path>]` reads `/etc/hx/gatewayd.toml` by default
//! ([`hx_agent::gateway::config`] documents the keys). Start-up order, which the seccomp
//! allowlist depends on:
//!
//! 1. parse the configuration, load the identity key from the systemd credential, open the
//!    state directory (device registry, verifiers) and bind the QUIC and WebSocket sockets and
//!    the admin socket (systemd hands the admin socket over by socket activation);
//! 2. register the signal handlers;
//! 3. `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `mlockall`;
//! 4. install the seccomp allowlist on every thread;
//! 5. only now start accepting connections, and tell systemd (`READY=1`).
//!
//! On `SIGTERM` or `SIGINT` it stops accepting, closes live sessions with `SHUTDOWN` and exits.
//! Logs go to stderr (the journal) through `tracing`; they never contain a secret.

use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use hx_agent::gateway::admin::{self, AdminPolicy};
use hx_agent::gateway::config::GatewayConfig;
use hx_agent::gateway::desktop::UnavailableLink;
use hx_agent::gateway::harden;
use hx_agent::gateway::server::{Gateway, StartOptions, load_identity};
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};
use tracing_subscriber::filter::LevelFilter;

const DEFAULT_CONFIG: &str = "/etc/hx/gatewayd.toml";

struct Args {
    config: PathBuf,
    /// Debug builds only: lets one unprivileged uid use the admin socket, for tests that cannot
    /// run as root. Release builds refuse the flag.
    admin_allow_uid: Option<u32>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        config: DEFAULT_CONFIG.into(),
        admin_allow_uid: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" => {
                args.config = it.next().ok_or("--config needs a path")?.into();
            }
            "--admin-allow-uid" if cfg!(debug_assertions) => {
                let v = it.next().ok_or("--admin-allow-uid needs a uid")?;
                args.admin_allow_uid = Some(v.parse().map_err(|_| "bad uid")?);
            }
            "--version" => {
                println!("{} {}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(args)
}

fn init_logging() {
    let level = match std::env::var("HX_LOG").as_deref() {
        Ok("error") => LevelFilter::ERROR,
        Ok("warn") => LevelFilter::WARN,
        Ok("debug") => LevelFilter::DEBUG,
        Ok("trace") => LevelFilter::TRACE,
        _ => LevelFilter::INFO,
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .init();
}

/// The admin socket systemd passed (socket activation), or one bound at `config.admin_socket`.
fn admin_listener(config: &GatewayConfig) -> Result<UnixListener, String> {
    let mut fds = listenfd::ListenFd::from_env();
    if let Ok(Some(std_listener)) = fds.take_unix_listener(0) {
        std_listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        return UnixListener::from_std(std_listener).map_err(|e| e.to_string());
    }
    admin::bind(&config.admin_socket).map_err(|e| format!("cannot create the admin socket: {e}"))
}

/// `READY=1` to the service manager, if it asked (`Type=notify`).
fn notify_ready() {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let bytes = std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str());
    let addr = match bytes.strip_prefix(b"@") {
        Some(name) => SocketAddr::from_abstract_name(name),
        None => SocketAddr::from_pathname(&path),
    };
    if let Ok(addr) = addr
        && let Ok(sock) = UnixDatagram::unbound()
    {
        let _ = sock.send_to_addr(b"READY=1", &addr);
    }
}

async fn run(args: Args) -> Result<(), String> {
    let config = GatewayConfig::load(&args.config).map_err(|e| e.to_string())?;
    let creds = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
    let identity = load_identity(&config.identity_path(creds.as_deref()).map_err(|e| e.to_string())?)?;

    // The state directory is the unit's `StateDirectory` (0700); create it for a manual run.
    if !config.state_dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&config.state_dir)
            .map_err(|e| format!("cannot create the state directory: {}", e.kind()))?;
    }

    let mut opts = StartOptions::new(config.clone(), Arc::new(identity), Arc::new(UnavailableLink));
    opts.admin_listener = Some(admin_listener(&config)?);
    if let Some(uid) = args.admin_allow_uid {
        tracing::warn!(uid, "DEBUG BUILD: the admin socket also accepts this uid");
        opts.admin_policy = AdminPolicy::OnlyUid(uid);
    }
    let mut gateway = Gateway::bind(opts).await.map_err(|e| e.to_string())?;

    // Signal handlers are created before the filter: registering one needs `socketpair`.
    let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut int = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;

    harden::process_limits(config.mlock).map_err(|e| e.to_string())?;
    harden::install_seccomp(config.seccomp).map_err(|e| e.to_string())?;

    gateway.begin();
    if let (Some(q), Some(w)) = (gateway.quic_addr(), gateway.websocket_addr()) {
        // One plain line on stdout: scripts and tests read the bound ports (never a secret).
        println!("hx-gatewayd listening quic={q} websocket={w}");
    }
    tracing::info!(takeover = ?config.takeover, "gateway started");
    notify_ready();

    tokio::select! {
        _ = term.recv() => tracing::info!("SIGTERM: shutting down"),
        _ = int.recv() => tracing::info!("SIGINT: shutting down"),
    }
    gateway.shutdown().await;
    Ok(())
}

fn main() -> ExitCode {
    init_logging();
    harden::install_panic_hook();
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("hx-gatewayd: {e}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("hx-gatewayd")
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("hx-gatewayd: cannot start the runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "hx-gatewayd failed");
            ExitCode::FAILURE
        }
    }
}
