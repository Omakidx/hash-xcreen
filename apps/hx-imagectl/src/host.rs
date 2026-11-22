//! The Incus side shared by the commands that build or run desktops: connecting, the object
//! names, `ensure_host`, and the `incus` CLI.

use std::net::IpAddr;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use hx_provision::host::{HostSpec, Naming, PoolSource, ensure_host};
use hx_provision::incus::{Client, ImageSource, UnixTransport};
use hx_provision::orchestrate::Limits;
use hx_provision::{Plan, Progress};

use crate::devproxy;
use crate::util::{CliError, failed};

/// The default prefix of the object names (`hxci-pool`, `hxci-br0`, ...).
pub const DEFAULT_PREFIX: &str = "hxci";

/// The prefix with its trailing `-` (`hxci` is `hxci-`), so the names read `hxci-pool` and not
/// `hxcipool`.
pub fn norm_prefix(prefix: &str) -> String {
    if prefix.ends_with('-') {
        prefix.to_string()
    } else {
        format!("{prefix}-")
    }
}

/// Object names for `--prefix`.
pub fn naming(prefix: &str) -> Result<Naming, CliError> {
    Naming::with_prefix(&norm_prefix(prefix)).map_err(|e| CliError::Usage(e.to_string()))
}

/// The instance that builds the image.
pub fn builder_name(prefix: &str) -> String {
    format!("{}img", norm_prefix(prefix))
}

/// The desktop of path A (`build`, on the server) or B (`prebuilt`) of the equivalence check.
pub fn desktop_name(prefix: &str, path: &str) -> String {
    let suffix = if path == "build" { "desk-a" } else { "desk-b" };
    format!("{}{suffix}", norm_prefix(prefix))
}

/// The local alias of the published image (removed again after the export).
pub fn publish_alias(prefix: &str) -> String {
    format!("{}pub", norm_prefix(prefix))
}

/// The alias an imported image carries (`hx-img-` is what `Client::delete_image` insists on).
pub fn import_alias(prefix: &str) -> String {
    format!("hx-img-{}ci", norm_prefix(prefix))
}

/// Incus socket: `HX_INCUS_SOCKET`, else the default.
pub fn socket() -> String {
    std::env::var("HX_INCUS_SOCKET").unwrap_or_else(|_| UnixTransport::DEFAULT_SOCKET.to_string())
}

/// What the commands share once the host objects exist.
pub struct HostCtx {
    /// Incus client.
    pub client: Client<UnixTransport>,
    /// Object names.
    pub naming: Naming,
    /// An image to start from instead of the recipe's base (local development behind a Docker
    /// host only, see [`devproxy`]); `None` in CI.
    pub base_override: Option<ImageSource>,
    _proxy: Option<tokio::task::JoinHandle<()>>,
}

/// Addresses of this machine, so the desktops' isolation ACL can refuse them. `hostname -I`;
/// an empty answer falls back to a documentation address, which blocks nothing real.
fn host_addresses() -> Vec<IpAddr> {
    let out = Command::new("hostname").arg("-I").output();
    let mut v: Vec<IpAddr> = out
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .filter_map(|w| w.parse::<IpAddr>().ok())
                .collect()
        })
        .unwrap_or_default();
    if v.is_empty() {
        v.push(IpAddr::from([203, 0, 113, 7]));
    }
    v
}

/// Connect to Incus and make sure the pool, bridge, ACL and profiles exist (idempotent).
/// `plan` names the base image for the local-development proxy.
pub async fn connect(
    prefix: &str,
    pool_gib: u64,
    plan: Option<&Plan>,
) -> Result<HostCtx, CliError> {
    let naming = naming(prefix)?;
    let client = Client::unix(socket());
    let info = client.server_info().await.map_err(|e| {
        failed(format!(
            "cannot use Incus at {}: {e} (is the socket readable by this user?)",
            socket()
        ))
    })?;
    eprintln!("incus {} at {}", info.server_version, socket());
    let report = ensure_host(
        &client,
        &HostSpec {
            naming: naming.clone(),
            pool: PoolSource::LoopFile { size_gib: pool_gib },
            ipv4: "auto".into(),
            host_addresses: host_addresses(),
            allow_private_networks: false,
        },
    )
    .await
    .map_err(|e| failed(format!("ensure_host: {e}")))?;
    eprintln!(
        "host objects: pool {:?}, network {:?}, acl {:?}",
        report.pool, report.network, report.acl
    );
    let (base_override, proxy) = if devproxy::enabled() {
        let gateway = report
            .gateway
            .ok_or_else(|| failed("the bridge has no IPv4 gateway"))?;
        let plan = plan.ok_or_else(|| failed("the dev proxy needs a recipe"))?;
        let (img, handle) = devproxy::prepare(&client, &naming, gateway, plan).await?;
        (Some(img), Some(handle))
    } else {
        (None, None)
    };
    Ok(HostCtx {
        client,
        naming,
        base_override,
        _proxy: proxy,
    })
}

/// Resource limits of the desktops and the builder.
pub fn limits(cpu: Option<u64>, memory_mib: Option<u64>) -> Limits {
    Limits {
        cpu: Some(cpu.and_then(|c| u32::try_from(c).ok()).unwrap_or(4)),
        memory_mib: Some(memory_mib.unwrap_or(4096)),
        disk_gib: None,
        processes: None,
    }
}

/// A progress callback that prints one line per finished step to stderr (a warning marks an
/// optional step that failed).
pub fn progress(label: &'static str) -> impl FnMut(&Progress) + Send {
    move |p| {
        if let Progress::Finished {
            step, elapsed, ok, ..
        } = p
        {
            eprintln!(
                "  {label:<7} {:>6.0?}  {}  {}",
                elapsed,
                if *ok { "ok  " } else { "WARN" },
                step.chars().take(90).collect::<String>()
            );
        }
    }
}

/// Run the `incus` CLI (blocking work off the async threads); returns stdout. The CLI talks to
/// the same socket as the API client (`INCUS_SOCKET`).
pub async fn incus(args: &[&str]) -> Result<String, CliError> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let sock = socket();
    tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new("incus");
        cmd.args(&args);
        if sock != UnixTransport::DEFAULT_SOCKET {
            cmd.env("INCUS_SOCKET", &sock);
        }
        let out = cmd
            .output()
            .map_err(|e| failed(format!("cannot run `incus`: {e}")))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(failed(format!(
                "`incus {}` failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    })
    .await
    .map_err(|e| failed(format!("incus task: {e}")))?
}

/// The fingerprint of the image that carries `alias`.
pub async fn fingerprint_of_alias(
    client: &Client<UnixTransport>,
    alias: &str,
) -> Result<Option<String>, CliError> {
    let images = client
        .list_images()
        .await
        .map_err(|e| failed(format!("list images: {e}")))?;
    Ok(images
        .into_iter()
        .find(|i| i.aliases.iter().any(|a| a == alias))
        .map(|i| i.fingerprint))
}

/// A generous bound for the longest Incus operation we start from here.
pub const LONG: Duration = Duration::from_secs(20 * 60);

/// Whether `p` is a plain existing file path (used for friendlier messages).
pub fn require_file(p: &Path) -> Result<(), CliError> {
    if p.is_file() {
        Ok(())
    } else {
        Err(failed(format!("{} is not a file", p.display())))
    }
}
