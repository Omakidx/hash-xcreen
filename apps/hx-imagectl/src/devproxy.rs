//! Local development only: let the desktops reach the package mirrors on a host that runs Docker.
//!
//! Enabled by `HX_IMAGECTL_DEV_PROXY=1`; CI never sets it. On a host that runs Docker, traffic
//! forwarded from an Incus bridge is dropped, and a development run must not change the host's
//! firewall. So, as `crates/hx-provision/tests/incus_real_image.rs` does, this
//!
//! 1. clears the bridge's ACL (the isolation ACL would also block the proxy at the gateway),
//! 2. runs a small forward proxy (ports 80 and 443 only) bound to the bridge gateway, port 3128,
//! 3. bakes an apt and curl proxy configuration into a copy of the distro's base image, and
//!    returns that copy for the builder and both desktops to start from.
//!
//! The proxy lives as long as the process; the baked copy stays in the image store until
//! `hx-imagectl cleanup` removes it.
//!
//! ## One baked copy per base image
//!
//! The copy is cached under the alias `<prefix>base-<name>-<hash>`, where `<name>` is the remote
//! base reference of the recipe (`ubuntu/24.04`) reduced to `a-z0-9.` and `-`, and `<hash>` is
//! the first 8 hex digits of the SHA-256 of the exact reference, so two references never share an
//! alias even if their readable parts match. The published image also records the reference in
//! the property [`SOURCE_PROPERTY`]. A cached copy is reused only when its alias matches and its
//! property equals the recipe's reference; a copy that carries the alias but another (or no)
//! source is deleted and rebuilt, never used. The older single alias `<prefix>base` (one copy for
//! every recipe, which let a Debian copy serve an Ubuntu build) is ignored by `prepare` and
//! removed by `cleanup`, like every alias that starts with `<prefix>base`.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hx_provision::Plan;
use hx_provision::host::Naming;
use hx_provision::incus::{Client, ImageInfo, ImageSource, UnixTransport};
use hx_provision::orchestrate::{DesktopSpec, destroy_instance};
use hx_provision::plan::ImageRef;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::host::{fingerprint_of_alias, incus, limits};
use crate::util::{CliError, failed};

/// The fixed proxy port (the baked configuration of the base copy names it).
pub const PORT: u16 = 3128;

/// Whether the development proxy is requested.
pub fn enabled() -> bool {
    std::env::var("HX_IMAGECTL_DEV_PROXY").as_deref() == Ok("1")
}

fn prefix_of(n: &Naming) -> &str {
    n.pool.strip_suffix("pool").unwrap_or("hxci-")
}

/// The image property that records which remote base a baked copy was made from.
pub const SOURCE_PROPERTY: &str = "user.hx.base_source";

/// Start of every alias of a baked base copy, including the legacy `<prefix>base`.
pub fn base_alias_prefix(n: &Naming) -> String {
    format!("{}base", prefix_of(n))
}

/// Alias of the baked copy of the remote base `remote` (for example `ubuntu/24.04`).
pub fn base_alias(n: &Naming, remote: &str) -> String {
    let readable: String = remote
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' | '.' => c,
            'A'..='Z' => c.to_ascii_lowercase(),
            _ => '-',
        })
        .take(24)
        .collect();
    let digest = Sha256::digest(remote.as_bytes());
    let short: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("{}-{readable}-{short}", base_alias_prefix(n))
}

/// What the image store holds under the alias of a base copy.
#[derive(Debug, PartialEq, Eq)]
pub enum CachedBase {
    /// A copy made from the expected base: reuse it.
    Hit(String),
    /// Something carries the alias but was not made from the expected base: delete, rebuild.
    Stale,
    /// Nothing carries the alias.
    Missing,
}

/// Look up `alias` in `images` and check that it was made from `remote`.
pub fn lookup_base(images: &[ImageInfo], alias: &str, remote: &str) -> CachedBase {
    match images.iter().find(|i| i.aliases.iter().any(|a| a == alias)) {
        None => CachedBase::Missing,
        Some(i) if i.properties.get(SOURCE_PROPERTY).map(String::as_str) == Some(remote) => {
            CachedBase::Hit(i.fingerprint.clone())
        }
        Some(_) => CachedBase::Stale,
    }
}

/// Every alias in `images` that belongs to a baked base copy of this prefix (any scheme).
pub fn base_aliases_in(images: &[ImageInfo], n: &Naming) -> Vec<String> {
    let start = base_alias_prefix(n);
    let mut v: Vec<String> = images
        .iter()
        .flat_map(|i| i.aliases.iter())
        .filter(|a| a.starts_with(&start))
        .cloned()
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Name of the temporary instance the base copy is made from.
pub fn base_instance(n: &Naming) -> String {
    format!("{}base0", prefix_of(n))
}

/// Set up the proxy and the base copy. Returns the image to start from and the proxy task.
pub async fn prepare(
    c: &Client<UnixTransport>,
    n: &Naming,
    gateway: IpAddr,
    plan: &Plan,
) -> Result<(ImageSource, tokio::task::JoinHandle<()>), CliError> {
    c.patch_network_config(
        &n.bridge,
        &[("security.acls".to_string(), String::new())].into(),
    )
    .await
    .map_err(|e| failed(format!("clear the bridge ACL: {e}")))?;
    let listener = TcpListener::bind(SocketAddr::new(gateway, PORT))
        .await
        .map_err(|e| failed(format!("bind the dev proxy on {gateway}:{PORT}: {e}")))?;
    let handle = tokio::spawn(async move {
        loop {
            let Ok((s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let _ = proxy_conn(s).await;
            });
        }
    });
    eprintln!("dev proxy: listening on {gateway}:{PORT} (bridge gateway only), bridge ACL cleared");

    let ImageRef::Remote { alias: remote } = &plan.base_image else {
        return Err(failed("the dev proxy expects a remote base image"));
    };
    let alias = base_alias(n, remote);
    let images = c
        .list_images()
        .await
        .map_err(|e| failed(format!("list images: {e}")))?;
    match lookup_base(&images, &alias, remote) {
        CachedBase::Hit(fp) => {
            eprintln!("dev proxy: reusing the proxied base copy {fp} of {remote}");
            return Ok((ImageSource::LocalFingerprint(fp), handle));
        }
        CachedBase::Stale => {
            eprintln!("dev proxy: {alias} was not made from {remote}; deleting it");
            incus(&["image", "delete", &alias]).await?;
        }
        CachedBase::Missing => {}
    }
    let from = match cached_base(c, remote).await {
        Some(fp) => ImageSource::LocalFingerprint(fp),
        None => ImageSource::official(remote.clone()),
    };
    let name = base_instance(n);
    let spec = DesktopSpec::for_plan(&name, n.clone(), plan, limits(None, None)).with_image(from);
    let _ = destroy_instance(c, &name).await;
    c.create_instance(
        &spec
            .to_create()
            .map_err(|e| failed(format!("base instance: {e}")))?,
        Duration::from_secs(900),
    )
    .await
    .map_err(|e| failed(format!("create the base instance: {e}")))?;
    let p = format!("http://{gateway}:{PORT}");
    let r: Result<(), CliError> = async {
        let e = |what: &str, e: hx_provision::incus::IncusError| failed(format!("{what}: {e}"));
        c.push_file(
            &name,
            "/etc/apt/apt.conf.d/99hx-dev-proxy",
            format!("Acquire::http::Proxy \"{p}\";\nAcquire::https::Proxy \"{p}\";\n").as_bytes(),
            0o644,
        )
        .await
        .map_err(|x| e("push the apt proxy", x))?;
        c.push_dir(&name, "/root", 0o700)
            .await
            .map_err(|x| e("create /root", x))?;
        c.push_file(
            &name,
            "/root/.curlrc",
            format!("proxy = \"{p}\"\n").as_bytes(),
            0o600,
        )
        .await
        .map_err(|x| e("push .curlrc", x))?;
        let source = format!("{SOURCE_PROPERTY}={remote}");
        incus(&["publish", &name, "--alias", &alias, &source]).await?;
        Ok(())
    }
    .await;
    let _ = destroy_instance(c, &name).await;
    r?;
    let fp = fingerprint_of_alias(c, &alias)
        .await?
        .ok_or_else(|| failed("the proxied base copy is missing after publish"))?;
    eprintln!("dev proxy: proxied base copy {fp}");
    Ok((ImageSource::LocalFingerprint(fp), handle))
}

/// A cached copy of the distro's base image (by `os` and `release` properties), if any.
async fn cached_base(c: &Client<UnixTransport>, remote_alias: &str) -> Option<String> {
    let (os, rel) = remote_alias.split_once('/')?;
    let rels: &[&str] = match (os, rel) {
        ("ubuntu", "24.04") => &["noble", "24.04"],
        ("ubuntu", "26.04") => &["resolute", "26.04"],
        ("debian", "12") => &["bookworm", "12"],
        ("debian", "13") => &["trixie", "13"],
        _ => return None,
    };
    c.list_images().await.ok()?.into_iter().find_map(|i| {
        let ok = i
            .properties
            .get("os")
            .is_some_and(|s| s.eq_ignore_ascii_case(os))
            && i.properties
                .get("release")
                .is_some_and(|r| rels.contains(&r.as_str()));
        ok.then_some(i.fingerprint)
    })
}

async fn proxy_conn(mut client: TcpStream) -> std::io::Result<()> {
    let mut head = Vec::new();
    let mut buf = [0u8; 2048];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = client.read(&mut buf).await?;
        if n == 0 || head.len() > 16 * 1024 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..n]);
    }
    let end = head.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
    let text = String::from_utf8_lossy(&head[..end]).to_string();
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or_default().to_string();
    let parts: Vec<&str> = first.split(' ').collect();
    let refuse = async |mut c: TcpStream| {
        let _ = c
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await;
        Ok::<(), std::io::Error>(())
    };
    if parts.len() < 3 {
        return refuse(client).await;
    }
    let (host, port, request): (String, u16, Option<Vec<u8>>) = if parts[0] == "CONNECT" {
        let Some((h, p)) = parts[1].rsplit_once(':') else {
            return refuse(client).await;
        };
        (h.to_string(), p.parse().unwrap_or(0), None)
    } else {
        let Some(rest) = parts[1].strip_prefix("http://") else {
            return refuse(client).await;
        };
        let (authority, path) = rest
            .split_once('/')
            .map_or((rest, "/".to_string()), |(a, p)| (a, format!("/{p}")));
        let (h, p) = authority
            .rsplit_once(':')
            .map_or((authority, 80u16), |(h, p)| (h, p.parse().unwrap_or(0)));
        let mut req = format!("{} {} HTTP/1.1\r\n", parts[0], path).into_bytes();
        for l in lines.filter(|l| !l.is_empty()) {
            let low = l.to_ascii_lowercase();
            if low.starts_with("proxy-") || low.starts_with("connection:") {
                continue;
            }
            req.extend_from_slice(l.as_bytes());
            req.extend_from_slice(b"\r\n");
        }
        req.extend_from_slice(b"Connection: close\r\n\r\n");
        (h.to_string(), p, Some(req))
    };
    if port != 80 && port != 443 {
        return refuse(client).await;
    }
    let mut up = TcpStream::connect((host.as_str(), port)).await?;
    match request {
        None => {
            client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
            client.write_all(&head[end..]).await?;
        }
        Some(req) => up.write_all(&req).await?,
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naming() -> Naming {
        Naming::with_prefix("hxci-").unwrap()
    }

    fn image(fp: &str, alias: &str, source: Option<&str>) -> ImageInfo {
        let mut i = ImageInfo {
            fingerprint: fp.into(),
            aliases: vec![alias.into()],
            ..ImageInfo::default()
        };
        if let Some(s) = source {
            i.properties.insert(SOURCE_PROPERTY.into(), s.into());
        }
        i
    }

    #[test]
    fn different_bases_get_different_aliases() {
        let n = naming();
        let deb = base_alias(&n, "debian/13");
        let ubu = base_alias(&n, "ubuntu/24.04");
        assert_ne!(deb, ubu);
        assert_ne!(deb, base_alias_prefix(&n), "never the legacy shared alias");
        // Same readable form, different reference: the hash keeps them apart.
        assert_ne!(
            base_alias(&n, "ubuntu/24.04"),
            base_alias(&n, "ubuntu-24.04")
        );
        assert_eq!(ubu, base_alias(&n, "ubuntu/24.04"), "stable for one base");
    }

    #[test]
    fn alias_uses_plain_characters_and_is_bounded() {
        let n = naming();
        let a = base_alias(&n, &format!("Ubuntu/24.04 ;rm {}", "x".repeat(300)));
        assert!(a.len() <= 64, "{a}");
        assert!(
            a.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.'),
            "{a}"
        );
    }

    #[test]
    fn same_base_is_reused() {
        let n = naming();
        let alias = base_alias(&n, "ubuntu/24.04");
        let imgs = [image("f1", &alias, Some("ubuntu/24.04"))];
        assert_eq!(
            lookup_base(&imgs, &alias, "ubuntu/24.04"),
            CachedBase::Hit("f1".into())
        );
    }

    #[test]
    fn another_bases_copy_is_never_returned() {
        let n = naming();
        let deb = base_alias(&n, "debian/13");
        let ubu = base_alias(&n, "ubuntu/24.04");
        let imgs = [image("fd", &deb, Some("debian/13"))];
        assert_eq!(
            lookup_base(&imgs, &ubu, "ubuntu/24.04"),
            CachedBase::Missing
        );
    }

    #[test]
    fn a_mismatched_or_unmarked_copy_is_stale() {
        let n = naming();
        let alias = base_alias(&n, "ubuntu/24.04");
        let wrong = [image("fd", &alias, Some("debian/13"))];
        assert_eq!(
            lookup_base(&wrong, &alias, "ubuntu/24.04"),
            CachedBase::Stale
        );
        let unmarked = [image("fd", &alias, None)];
        assert_eq!(
            lookup_base(&unmarked, &alias, "ubuntu/24.04"),
            CachedBase::Stale
        );
    }

    #[test]
    fn the_legacy_alias_is_ignored_by_lookup_but_found_by_cleanup() {
        let n = naming();
        let legacy = base_alias_prefix(&n);
        let alias = base_alias(&n, "ubuntu/24.04");
        let imgs = [
            image("old", &legacy, None),
            image("new", &alias, Some("ubuntu/24.04")),
            image("other", "hxci-pub", None),
            image("foreign", "someone-base", None),
        ];
        assert_eq!(
            lookup_base(&imgs[..1], &alias, "ubuntu/24.04"),
            CachedBase::Missing
        );
        let mut want = vec![legacy, alias];
        want.sort();
        assert_eq!(base_aliases_in(&imgs, &n), want);
    }
}
