//! Host-side Incus setup: storage pool, isolated bridge network with ACLs, and profiles.
//!
//! Everything that decides *what* to create is a pure function (unit-tested); [`ensure_host`]
//! applies it idempotently through the [`Client`].

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use crate::incus::{Acl, AclAction, AclRule, Client, IncusError, ProfileSpec, Transport};
use crate::plan::Plan;

const GIB: u64 = 1024 * 1024 * 1024;

/// Smallest and largest loop-file pool the installer creates (architecture 4.2).
pub const MIN_POOL_GIB: u64 = 12;
/// See [`MIN_POOL_GIB`].
pub const MAX_POOL_GIB: u64 = 200;

/// The cloud metadata endpoint every desktop must not reach.
pub const METADATA_V4: &str = "169.254.169.254/32";
/// The AWS IPv6 metadata endpoint.
pub const METADATA_V6: &str = "fd00:ec2::254/128";

/// Loop-file pool size: about 60% of the free disk, bounded to 12-200 GiB.
pub fn default_loop_size_gib(free_bytes: u64) -> u64 {
    (free_bytes / GIB * 6 / 10).clamp(MIN_POOL_GIB, MAX_POOL_GIB)
}

/// Names of every Incus object hash-xcreen creates. Tests use a distinct prefix so they can
/// never touch production objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Naming {
    /// Storage pool.
    pub pool: String,
    /// Bridge network (Linux interface name, at most 15 characters).
    pub bridge: String,
    /// Network ACL attached to the bridge.
    pub acl: String,
    /// Profile with root disk and NIC.
    pub desktop_profile: String,
    /// Profile with the Debian 13 AppArmor `signal` rule.
    pub compat_profile: String,
}

impl Naming {
    /// Production names: `hx-pool`, `hxbr0`, `hx-isolate`, `hx-desktop`, `hx-compat-debian13`.
    pub fn production() -> Self {
        Self {
            pool: "hx-pool".into(),
            bridge: "hxbr0".into(),
            acl: "hx-isolate".into(),
            desktop_profile: "hx-desktop".into(),
            compat_profile: "hx-compat-debian13".into(),
        }
    }

    /// Names built from a prefix such as `hx1d-test-` (so `hx1d-test-pool`, `hx1d-test-br0`, ...).
    pub fn with_prefix(prefix: &str) -> Result<Self, IncusError> {
        let ok = !prefix.is_empty()
            && prefix.len() <= 10
            && prefix
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !ok {
            return Err(IncusError::InvalidArgument(format!(
                "name prefix `{prefix}` must be 1-10 characters of a-z, 0-9 and `-` (the bridge name is a Linux interface name)"
            )));
        }
        Ok(Self {
            pool: format!("{prefix}pool"),
            bridge: format!("{prefix}br0"),
            acl: format!("{prefix}isolate"),
            desktop_profile: format!("{prefix}desktop"),
            compat_profile: format!("{prefix}compat-debian13"),
        })
    }
}

/// Where the storage pool lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolSource {
    /// A sparse loop file of this many GiB (Incus creates it under its own directory).
    LoopFile {
        /// Size in GiB.
        size_gib: u64,
    },
    /// A spare block device (`/dev/sdb`), used whole.
    Device(String),
}

/// What [`ensure_host`] sets up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSpec {
    /// Object names.
    pub naming: Naming,
    /// Pool backing store; the driver is always btrfs.
    pub pool: PoolSource,
    /// Bridge address as `a.b.c.d/nn`, or `auto` to let Incus pick a free subnet.
    pub ipv4: String,
    /// Every address of the host (public IPv4/IPv6, private addresses of other interfaces,
    /// Docker bridge gateways). Desktops cannot reach any of them.
    pub host_addresses: Vec<IpAddr>,
}

impl HostSpec {
    /// Check the pieces that would otherwise fail deep inside Incus.
    pub fn validate(&self) -> Result<(), IncusError> {
        let bad = |m: String| Err(IncusError::InvalidArgument(m));
        if !self.bridge_name_len_ok() {
            return bad(format!(
                "bridge name `{}` is longer than 15 characters",
                self.naming.bridge
            ));
        }
        match &self.pool {
            PoolSource::LoopFile { size_gib } if *size_gib == 0 => {
                return bad("pool size must be at least 1 GiB".into());
            }
            PoolSource::Device(d)
                if !d.starts_with("/dev/")
                    || d.contains("..")
                    || d.chars().any(char::is_whitespace) =>
            {
                return bad(format!("`{d}` is not a block device path"));
            }
            _ => {}
        }
        if self.ipv4 != "auto" {
            let (addr, bits) = self.ipv4.split_once('/').ok_or_else(|| {
                IncusError::InvalidArgument(format!("`{}` is not a.b.c.d/nn", self.ipv4))
            })?;
            let a: Ipv4Addr = addr.parse().map_err(|_| {
                IncusError::InvalidArgument(format!("`{addr}` is not an IPv4 address"))
            })?;
            let bits: u8 = bits.parse().map_err(|_| {
                IncusError::InvalidArgument(format!("`{bits}` is not a prefix length"))
            })?;
            if !(8..=29).contains(&bits) || !a.is_private() {
                return bad(format!(
                    "`{}` must be a private IPv4 range with a prefix of /8 to /29",
                    self.ipv4
                ));
            }
        }
        Ok(())
    }

    fn bridge_name_len_ok(&self) -> bool {
        self.naming.bridge.len() <= 15
    }
}

/// ACL rules that isolate desktops from the host and the cloud metadata service while leaving the
/// internet open. Order matters: drops first, then the final allow.
///
/// DNS and DHCP to the bridge gateway keep working because Incus permits them on its own
/// (verified in S3), even though the gateway address is dropped.
pub fn isolation_rules(gateway: Option<IpAddr>, host_addresses: &[IpAddr]) -> Vec<AclRule> {
    let mut rules = vec![
        AclRule::to(AclAction::Drop, METADATA_V4, "cloud metadata"),
        AclRule::to(AclAction::Drop, METADATA_V6, "cloud metadata (AWS IPv6)"),
    ];
    let mut seen = std::collections::BTreeSet::new();
    let mut hosts: Vec<(IpAddr, &str)> = Vec::new();
    if let Some(g) = gateway {
        hosts.push((g, "host via the bridge gateway"));
    }
    hosts.extend(
        host_addresses
            .iter()
            .map(|a| (*a, "host address (agent ports)")),
    );
    for (addr, why) in hosts {
        if addr.is_loopback() || addr.is_unspecified() || !seen.insert(addr) {
            continue;
        }
        let cidr = match addr {
            IpAddr::V4(a) => format!("{a}/32"),
            IpAddr::V6(a) => format!("{a}/128"),
        };
        rules.push(AclRule::to(AclAction::Drop, cidr, why));
    }
    rules.push(AclRule::any(AclAction::Allow, "everything else"));
    rules
}

/// The ACL for a bridge.
pub fn isolation_acl(name: &str, gateway: Option<IpAddr>, host_addresses: &[IpAddr]) -> Acl {
    Acl {
        name: name.to_string(),
        description: "hash-xcreen: desktops reach the internet, not the host or cloud metadata"
            .into(),
        egress: isolation_rules(gateway, host_addresses),
        ingress: Vec::new(),
    }
}

fn map<const N: usize>(pairs: [(&str, &str); N]) -> BTreeMap<String, String> {
    pairs
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Storage pool driver and config for a [`PoolSource`].
pub fn pool_config(source: &PoolSource) -> BTreeMap<String, String> {
    match source {
        PoolSource::LoopFile { size_gib } => map([("size", &format!("{size_gib}GiB"))]),
        PoolSource::Device(d) => map([("source", d)]),
    }
}

/// Configuration of the bridge network (without the ACL, which needs the gateway address).
pub fn network_config(ipv4: &str) -> BTreeMap<String, String> {
    map([
        ("ipv4.address", ipv4),
        ("ipv4.nat", "true"),
        ("ipv6.address", "none"),
    ])
}

/// Keys that attach the ACL and set the default actions.
///
/// Egress defaults to allow (the ACL's final rule is allow anyway); ingress defaults to allow so
/// the agent can reach the desktop. Desktops cannot reach the host, which is the direction that
/// matters.
pub fn acl_attachment(acl: &str) -> BTreeMap<String, String> {
    map([
        ("security.acls", acl),
        ("security.acls.default.egress.action", "allow"),
        ("security.acls.default.ingress.action", "allow"),
    ])
}

/// The profile every desktop uses: root disk on our pool, NIC on our bridge.
pub fn desktop_profile(naming: &Naming) -> ProfileSpec {
    let mut devices = BTreeMap::new();
    devices.insert(
        "root".to_string(),
        map([("type", "disk"), ("path", "/"), ("pool", &naming.pool)]),
    );
    devices.insert(
        "eth0".to_string(),
        map([
            ("type", "nic"),
            ("name", "eth0"),
            ("network", &naming.bridge),
        ]),
    );
    ProfileSpec {
        name: naming.desktop_profile.clone(),
        description: "hash-xcreen desktop: root disk and NIC".into(),
        config: BTreeMap::new(),
        devices,
    }
}

/// The compatibility profile: Debian 13 guests hang at boot on newer host kernels unless their
/// AppArmor profile allows `signal` (S3, kernel 7.0, Incus 6.0.5). It is a profile, not recipe
/// content, because prebuilt images carry no instance configuration.
pub fn compat_profile(naming: &Naming) -> ProfileSpec {
    ProfileSpec {
        name: naming.compat_profile.clone(),
        description: "hash-xcreen: AppArmor signal rule needed by Debian 13 guests".into(),
        config: map([("raw.apparmor", "signal,")]),
        devices: BTreeMap::new(),
    }
}

/// Whether guests of `plan` need the compatibility profile (Debian 13).
pub fn needs_compat_profile(plan: &Plan) -> bool {
    plan.vars.get("distro").map(String::as_str) == Some("debian")
        && plan.vars.get("distro_version").map(String::as_str) == Some("13")
}

/// Whether [`ensure_host`] created an object or found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ensured {
    /// Created now.
    Created,
    /// Already there; left unchanged.
    Existed,
    /// Already there; rules refreshed (the ACL, whose host addresses may have changed).
    Updated,
}

/// What [`ensure_host`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostReport {
    /// Storage pool.
    pub pool: Ensured,
    /// Bridge network.
    pub network: Ensured,
    /// Gateway address of the bridge, when it has an IPv4 address.
    pub gateway: Option<IpAddr>,
    /// ACL.
    pub acl: Ensured,
    /// Desktop profile.
    pub desktop_profile: Ensured,
    /// Compatibility profile.
    pub compat_profile: Ensured,
}

/// Create (or find) the pool, the isolated bridge with its ACL, and the profiles.
///
/// Idempotent: existing pool, network and profiles are left alone; the ACL's rules are refreshed.
/// Nothing is ever deleted.
pub async fn ensure_host<T: Transport>(
    client: &Client<T>,
    spec: &HostSpec,
) -> Result<HostReport, IncusError> {
    spec.validate()?;
    let n = &spec.naming;

    let pool = if client.get_storage_pool(&n.pool).await?.is_some() {
        Ensured::Existed
    } else {
        client
            .create_storage_pool(&n.pool, "btrfs", &pool_config(&spec.pool))
            .await?;
        Ensured::Created
    };

    let (network, existing) = match client.get_network(&n.bridge).await? {
        Some(net) => (Ensured::Existed, net),
        None => {
            client
                .create_network(&n.bridge, &network_config(&spec.ipv4))
                .await?;
            let net = client.get_network(&n.bridge).await?.ok_or_else(|| {
                IncusError::Protocol(format!(
                    "network `{}` is missing right after creation",
                    n.bridge
                ))
            })?;
            (Ensured::Created, net)
        }
    };
    let gateway = existing
        .config
        .get("ipv4.address")
        .and_then(|a| a.split('/').next())
        .and_then(|a| a.parse::<Ipv4Addr>().ok())
        .map(IpAddr::V4);

    let acl = isolation_acl(&n.acl, gateway, &spec.host_addresses);
    let acl_state = if client.acl_exists(&n.acl).await? {
        client.update_acl(&acl).await?;
        Ensured::Updated
    } else {
        client.create_acl(&acl).await?;
        Ensured::Created
    };
    let attach = acl_attachment(&n.acl);
    if attach
        .iter()
        .any(|(k, v)| existing.config.get(k) != Some(v))
    {
        client.patch_network_config(&n.bridge, &attach).await?;
    }

    let ensure_profile = async |p: ProfileSpec| -> Result<Ensured, IncusError> {
        if client.profile_exists(&p.name).await? {
            Ok(Ensured::Existed)
        } else {
            client.create_profile(&p).await?;
            Ok(Ensured::Created)
        }
    };
    let desktop = ensure_profile(desktop_profile(n)).await?;
    let compat = ensure_profile(compat_profile(n)).await?;

    Ok(HostReport {
        pool,
        network,
        gateway,
        acl: acl_state,
        desktop_profile: desktop,
        compat_profile: compat,
    })
}
