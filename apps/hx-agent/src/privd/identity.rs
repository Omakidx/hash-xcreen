//! Who the gateway is, and the account-policy self-checks of ipc.md 3.
//!
//! The gateway uid is resolved from the user name compiled into the binary
//! ([`GATEWAY_USER`]) by reading the passwd file itself (no NSS, so no plugin code runs in a root
//! process). It never comes from configuration, the environment, argv or the socket.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::config::PrivdConfig;

/// The unprivileged gateway's system user, fixed at compile time (ipc.md 3).
pub const GATEWAY_USER: &str = "hx-gatewayd";

/// Groups the gateway user must not be in (ipc.md 3, "Self-checks at start").
pub const FORBIDDEN_GROUPS: [&str; 11] = [
    "incus",
    "incus-admin",
    "docker",
    "disk",
    "sudo",
    "wheel",
    "adm",
    "systemd-journal",
    "lxd",
    "shadow",
    "kvm",
];

/// Uid and gid of the gateway user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayIdentity {
    /// Numeric uid (never 0).
    pub uid: u32,
    /// Numeric primary gid (never 0).
    pub gid: u32,
}

/// One line of `/etc/passwd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    /// Login name.
    pub name: String,
    /// Uid.
    pub uid: u32,
    /// Primary gid.
    pub gid: u32,
}

/// One line of `/etc/group`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    /// Group name.
    pub name: String,
    /// Gid.
    pub gid: u32,
    /// Supplementary members.
    pub members: Vec<String>,
}

/// Parses passwd text; malformed lines are skipped.
pub fn parse_passwd(text: &str) -> Vec<PasswdEntry> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 4 || l.starts_with('#') {
                return None;
            }
            Some(PasswdEntry {
                name: f[0].to_string(),
                uid: f[2].parse().ok()?,
                gid: f[3].parse().ok()?,
            })
        })
        .collect()
}

/// Parses group text; malformed lines are skipped.
pub fn parse_group(text: &str) -> Vec<GroupEntry> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 4 || l.starts_with('#') {
                return None;
            }
            Some(GroupEntry {
                name: f[0].to_string(),
                gid: f[2].parse().ok()?,
                members: f[3]
                    .split(',')
                    .filter(|m| !m.is_empty())
                    .map(str::to_string)
                    .collect(),
            })
        })
        .collect()
}

/// Why the gateway identity could not be resolved.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The passwd file could not be read.
    #[error("cannot read the passwd file: {0}")]
    Read(#[from] std::io::Error),
    /// The gateway user does not exist.
    #[error("the system user `{GATEWAY_USER}` does not exist")]
    Missing,
    /// The user maps to uid or gid 0, which would make the two roles ambiguous.
    #[error("the system user `{GATEWAY_USER}` has uid or gid 0")]
    Root,
}

/// The gateway identity from passwd text.
pub fn resolve_gateway(passwd_text: &str) -> Result<GatewayIdentity, IdentityError> {
    let e = parse_passwd(passwd_text)
        .into_iter()
        .find(|e| e.name == GATEWAY_USER)
        .ok_or(IdentityError::Missing)?;
    if e.uid == 0 || e.gid == 0 {
        return Err(IdentityError::Root);
    }
    Ok(GatewayIdentity {
        uid: e.uid,
        gid: e.gid,
    })
}

/// Reads `passwd_path` and resolves the gateway.
pub fn resolve_gateway_from(passwd_path: &Path) -> Result<GatewayIdentity, IdentityError> {
    resolve_gateway(&std::fs::read_to_string(passwd_path)?)
}

/// A failed self-check (text only; never a secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation(pub String);

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Owner, group and permission bits of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMeta {
    /// Permission bits (`mode & 0o7777`).
    pub mode: u32,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
}

impl FileMeta {
    /// Metadata of `path`, following symlinks.
    pub fn of(path: &Path) -> std::io::Result<Self> {
        let m = std::fs::metadata(path)?;
        Ok(Self {
            mode: m.mode() & 0o7777,
            uid: m.uid(),
            gid: m.gid(),
        })
    }
}

/// Whether a process with `uid` and groups `gids` has all of the permission `bits` (`0o4` read,
/// `0o2` write) on a file with `meta`, by the classic owner/group/other rule (root excepted).
pub fn may_access(uid: u32, gids: &[u32], meta: &FileMeta, bits: u32) -> bool {
    let class = if uid == meta.uid {
        (meta.mode >> 6) & 7
    } else if gids.contains(&meta.gid) {
        (meta.mode >> 3) & 7
    } else {
        meta.mode & 7
    };
    class & bits == bits
}

/// The account-policy checks of ipc.md 3 on parsed passwd and group data:
///
/// * the gateway user is in none of [`FORBIDDEN_GROUPS`] (as primary or supplementary group);
/// * it has no supplementary group other than its own;
/// * no other user is a member of the `hx-gatewayd` group (membership grants access to the privd
///   socket and the link directory), as supplementary or primary group.
pub fn check_accounts(passwd: &[PasswdEntry], groups: &[GroupEntry]) -> Vec<Violation> {
    let mut out = Vec::new();
    let Some(gw) = passwd.iter().find(|e| e.name == GATEWAY_USER) else {
        out.push(Violation(format!("user `{GATEWAY_USER}` does not exist")));
        return out;
    };
    for g in groups {
        if g.gid == gw.gid {
            continue;
        }
        let primary = g.gid == gw.gid;
        let member = g.members.iter().any(|m| m == GATEWAY_USER);
        if FORBIDDEN_GROUPS.contains(&g.name.as_str()) && (member || primary) {
            out.push(Violation(format!(
                "`{GATEWAY_USER}` is in the forbidden group `{}`",
                g.name
            )));
        } else if member {
            out.push(Violation(format!(
                "`{GATEWAY_USER}` has a supplementary group `{}` besides its own",
                g.name
            )));
        }
    }
    // The primary group may itself be one of the forbidden ones (a misconfigured useradd).
    if let Some(pg) = groups.iter().find(|g| g.gid == gw.gid)
        && FORBIDDEN_GROUPS.contains(&pg.name.as_str())
    {
        out.push(Violation(format!(
            "`{GATEWAY_USER}` has the forbidden primary group `{}`",
            pg.name
        )));
    }
    for g in groups.iter().filter(|g| g.gid == gw.gid) {
        for m in g.members.iter().filter(|m| m.as_str() != GATEWAY_USER) {
            out.push(Violation(format!(
                "`{m}` is a member of the group `{}` (access to the privd socket)",
                g.name
            )));
        }
    }
    for e in passwd.iter().filter(|e| e.gid == gw.gid && e.uid != gw.uid) {
        out.push(Violation(format!(
            "`{}` has the gateway group as its primary group",
            e.name
        )));
    }
    out
}

/// The Incus socket must not be usable by the gateway uid (read or write; connecting needs
/// write). A missing socket (Incus down) is not a violation of this policy.
pub fn check_incus_socket(
    meta: Option<FileMeta>,
    gateway: GatewayIdentity,
    gateway_gids: &[u32],
) -> Option<Violation> {
    let meta = meta?;
    if may_access(gateway.uid, gateway_gids, &meta, 0o2)
        || may_access(gateway.uid, gateway_gids, &meta, 0o4)
    {
        return Some(Violation(
            "the Incus socket is accessible to the gateway user".into(),
        ));
    }
    None
}

/// The privd socket must have exactly the mode and owner of `expected` (ipc.md 3: `0660`,
/// `root:hx-gatewayd`).
pub fn check_privd_socket(meta: &FileMeta, expected: &FileMeta) -> Option<Violation> {
    if meta != expected {
        return Some(Violation(format!(
            "the privd socket is {:o} {}:{}, expected {:o} {}:{}",
            meta.mode, meta.uid, meta.gid, expected.mode, expected.uid, expected.gid
        )));
    }
    None
}

/// Runs every self-check against the files named in `cfg`. An empty list means the host account
/// policy holds. The daemon refuses to start otherwise, and re-runs this daily and after updates
/// (a failure sets `needs_attention=HOST_ACCOUNT_POLICY`).
pub fn run_self_checks(cfg: &PrivdConfig) -> Vec<Violation> {
    let read = |p: &Path| std::fs::read_to_string(p);
    let (passwd_text, group_text) = match (read(&cfg.passwd_file), read(&cfg.group_file)) {
        (Ok(p), Ok(g)) => (p, g),
        (Err(e), _) | (_, Err(e)) => {
            return vec![Violation(format!("cannot read the account files: {e}"))];
        }
    };
    let passwd = parse_passwd(&passwd_text);
    let groups = parse_group(&group_text);
    let mut out = check_accounts(&passwd, &groups);
    // The gids the gateway process has: its primary group plus any supplementary ones (which the
    // account check above already reports).
    let mut gids = vec![cfg.gateway.gid];
    gids.extend(
        groups
            .iter()
            .filter(|g| g.members.iter().any(|m| m == GATEWAY_USER))
            .map(|g| g.gid),
    );
    out.extend(check_incus_socket(
        FileMeta::of(&cfg.incus_socket).ok(),
        cfg.gateway,
        &gids,
    ));
    match FileMeta::of(&cfg.socket_path) {
        Ok(m) => out.extend(check_privd_socket(&m, &cfg.expected_socket)),
        Err(e) => out.push(Violation(format!("cannot stat the privd socket: {e}"))),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\nhx-gatewayd:x:998:998::/nonexistent:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\n";

    fn group(extra: &str) -> Vec<GroupEntry> {
        parse_group(&format!(
            "root:x:0:\nhx-gatewayd:x:998:\nincus-admin:x:50:alice\nsudo:x:27:alice\n{extra}"
        ))
    }

    #[test]
    fn resolves_the_gateway_user() {
        assert_eq!(
            resolve_gateway(PASSWD).unwrap(),
            GatewayIdentity { uid: 998, gid: 998 }
        );
        assert!(matches!(
            resolve_gateway("root:x:0:0::/:/bin/sh\n"),
            Err(IdentityError::Missing)
        ));
        assert!(matches!(
            resolve_gateway("hx-gatewayd:x:0:0::/:/bin/sh\n"),
            Err(IdentityError::Root)
        ));
    }

    #[test]
    fn a_clean_host_passes() {
        assert_eq!(check_accounts(&parse_passwd(PASSWD), &group("")), vec![]);
    }

    #[test]
    fn forbidden_and_supplementary_groups_are_violations() {
        for g in FORBIDDEN_GROUPS {
            let groups = parse_group(&format!("hx-gatewayd:x:998:\n{g}:x:77:hx-gatewayd\n"));
            let v = check_accounts(&parse_passwd(PASSWD), &groups);
            assert_eq!(v.len(), 1, "{g}: {v:?}");
            assert!(v[0].0.contains(g));
        }
        let v = check_accounts(
            &parse_passwd(PASSWD),
            &parse_group("hx-gatewayd:x:998:\nplain:x:77:hx-gatewayd\n"),
        );
        assert_eq!(v.len(), 1);
        assert!(v[0].0.contains("supplementary"));
    }

    #[test]
    fn a_forbidden_primary_group_is_a_violation() {
        let passwd = parse_passwd("hx-gatewayd:x:998:50::/:/bin/false\n");
        let v = check_accounts(&passwd, &parse_group("incus-admin:x:50:\n"));
        assert!(v.iter().any(|x| x.0.contains("forbidden primary group")));
    }

    #[test]
    fn other_members_of_the_gateway_group_are_violations() {
        let v = check_accounts(
            &parse_passwd(PASSWD),
            &parse_group("hx-gatewayd:x:998:alice\n"),
        );
        assert_eq!(v.len(), 1);
        assert!(v[0].0.contains("alice"));
        let passwd = parse_passwd(&format!("{PASSWD}bob:x:1001:998::/:/bin/sh\n"));
        let v = check_accounts(&passwd, &group(""));
        assert_eq!(v.len(), 1);
        assert!(v[0].0.contains("bob"));
    }

    #[test]
    fn socket_permission_rule() {
        let gw = GatewayIdentity { uid: 998, gid: 998 };
        let ok = FileMeta {
            mode: 0o660,
            uid: 0,
            gid: 50,
        };
        assert!(check_incus_socket(Some(ok), gw, &[998]).is_none());
        assert!(check_incus_socket(None, gw, &[998]).is_none());
        let other_rw = FileMeta { mode: 0o666, ..ok };
        assert!(check_incus_socket(Some(other_rw), gw, &[998]).is_some());
        // Readable through a group the gateway is in.
        assert!(check_incus_socket(Some(ok), gw, &[998, 50]).is_some());
        // Owned by the gateway.
        let owned = FileMeta { uid: 998, ..ok };
        assert!(check_incus_socket(Some(owned), gw, &[998]).is_some());
    }

    #[test]
    fn privd_socket_must_match_exactly() {
        let expected = FileMeta {
            mode: 0o660,
            uid: 0,
            gid: 998,
        };
        assert!(check_privd_socket(&expected, &expected).is_none());
        for bad in [
            FileMeta {
                mode: 0o666,
                ..expected
            },
            FileMeta {
                uid: 998,
                ..expected
            },
            FileMeta { gid: 0, ..expected },
        ] {
            assert!(check_privd_socket(&bad, &expected).is_some());
        }
    }
}
