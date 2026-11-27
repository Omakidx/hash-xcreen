//! The files `hx-agent install` writes to the host, embedded in the binary: **one table**.
//!
//! The units ship inside `hx-agent` (design C7, `include_str!`), are installed by the installer and
//! are not touched by self-update. A test asserts that every file under `apps/hx-agent/systemd/`
//! is a row of [`FILES`] and the other way round, so a new unit file cannot be forgotten.

/// Where a file goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dest {
    /// `/usr/local/lib/systemd/system/`.
    Unit,
    /// `/usr/local/lib/sysusers.d/`.
    Sysusers,
    /// `/usr/local/lib/tmpfiles.d/`.
    Tmpfiles,
    /// `/etc/logrotate.d/`.
    Logrotate,
}

/// What the `units` stage does with a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enable {
    /// `systemctl enable --now`.
    Now,
    /// `systemctl enable` only (it starts later, or conditionally).
    Enable,
    /// Neither (a template, or enabled by another stage).
    No,
}

/// One embedded file.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedFile {
    /// The path below `apps/hx-agent/systemd/`.
    pub rel: &'static str,
    /// The file name at the destination.
    pub name: &'static str,
    /// The destination directory.
    pub dest: Dest,
    /// Enablement (units only).
    pub enable: Enable,
    /// The content.
    pub text: &'static str,
}

macro_rules! file {
    ($rel:literal, $name:literal, $dest:expr, $enable:expr) => {
        EmbeddedFile {
            rel: $rel,
            name: $name,
            dest: $dest,
            enable: $enable,
            text: include_str!(concat!("../../systemd/", $rel)),
        }
    };
}

/// Every file the installer writes from `systemd/`, in the order the `units` stage enables them.
pub const FILES: &[EmbeddedFile] = &[
    file!(
        "sysusers.d/hx-gatewayd.conf",
        "hx-gatewayd.conf",
        Dest::Sysusers,
        Enable::No
    ),
    file!("tmpfiles.d/hx.conf", "hx.conf", Dest::Tmpfiles, Enable::No),
    file!(
        "logrotate.d/hx-audit",
        "hx-audit",
        Dest::Logrotate,
        Enable::No
    ),
    file!(
        "var-lib-hx-updates.mount",
        "var-lib-hx-updates.mount",
        Dest::Unit,
        Enable::Now
    ),
    file!(
        "var-lib-hx-imagein.mount",
        "var-lib-hx-imagein.mount",
        Dest::Unit,
        Enable::Now
    ),
    file!(
        "hx-host-firewall.service",
        "hx-host-firewall.service",
        Dest::Unit,
        Enable::Enable
    ),
    file!(
        "hx-docker-user.service",
        "hx-docker-user.service",
        Dest::Unit,
        Enable::Enable
    ),
    file!(
        "hx-update-fetcher@.service",
        "hx-update-fetcher@.service",
        Dest::Unit,
        Enable::No
    ),
    file!(
        "hx-image-fetcher@.service",
        "hx-image-fetcher@.service",
        Dest::Unit,
        Enable::No
    ),
    // The Drive helper (docs/ipc.md section 24): installed, not enabled. The Drive-connect flow
    // (W5) enables the socket once a token exists.
    file!("hx-drive.socket", "hx-drive.socket", Dest::Unit, Enable::No),
    file!(
        "hx-drive.service",
        "hx-drive.service",
        Dest::Unit,
        Enable::No
    ),
    file!(
        "hx-privd.socket",
        "hx-privd.socket",
        Dest::Unit,
        Enable::Now
    ),
    file!(
        "hx-privd.service",
        "hx-privd.service",
        Dest::Unit,
        Enable::Now
    ),
    file!(
        "hx-gatewayd-admin.socket",
        "hx-gatewayd-admin.socket",
        Dest::Unit,
        Enable::Now
    ),
    file!(
        "hx-gatewayd-public.socket",
        "hx-gatewayd-public.socket",
        Dest::Unit,
        Enable::Now
    ),
    file!(
        "hx-gatewayd.service",
        "hx-gatewayd.service",
        Dest::Unit,
        Enable::Now
    ),
    // The OnFailure= target of hx-privd.service; it has no [Install] section.
    file!(
        "hx-privd-rescue.service",
        "hx-privd-rescue.service",
        Dest::Unit,
        Enable::No
    ),
    file!(
        "hx-agent-port.service",
        "hx-agent-port.service",
        Dest::Unit,
        Enable::No
    ),
];

/// The row for `name`.
pub fn find(name: &str) -> Option<&'static EmbeddedFile> {
    FILES.iter().find(|f| f.name == name)
}

/// The units that exist in keep mode after an uninstall: they keep protecting the desktop.
pub const FIREWALL_UNITS: &[&str] = &["hx-host-firewall.service", "hx-docker-user.service"];

/// The sockets and services that carry gateway traffic (disabled first by uninstall, U1). The
/// public socket is listed even though its row is added at integration: `systemctl disable` of a
/// unit that does not exist is harmless and its name is fixed.
pub const GATEWAY_UNITS: &[&str] = &[
    "hx-gatewayd.service",
    "hx-gatewayd-public.socket",
    "hx-gatewayd-admin.socket",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::Path;

    fn walk(dir: &Path, base: &Path, out: &mut BTreeSet<String>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, base, out);
            } else {
                out.insert(p.strip_prefix(base).unwrap().to_string_lossy().into_owned());
            }
        }
    }

    #[test]
    fn every_systemd_file_is_embedded() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("systemd");
        let mut on_disk = BTreeSet::new();
        walk(&base, &base, &mut on_disk);
        let table: BTreeSet<String> = FILES.iter().map(|f| f.rel.to_owned()).collect();
        let missing: Vec<_> = on_disk.difference(&table).collect();
        let stale: Vec<_> = table.difference(&on_disk).collect();
        assert!(
            missing.is_empty() && stale.is_empty(),
            "systemd/ files not in units::FILES: {missing:?}; rows without a file: {stale:?}"
        );
        assert_eq!(table.len(), FILES.len(), "a file is listed twice");
    }

    #[test]
    fn embedded_text_is_the_file_and_not_empty() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("systemd");
        for f in FILES {
            assert!(!f.text.trim().is_empty(), "{}", f.rel);
            assert_eq!(std::fs::read_to_string(base.join(f.rel)).unwrap(), f.text);
        }
    }

    #[test]
    fn names_are_unique_and_plain() {
        let mut seen = BTreeSet::new();
        for f in FILES {
            assert!(seen.insert((f.dest as u8, f.name)), "{}", f.name);
            assert!(
                !f.name.contains('/') && !f.name.starts_with('.'),
                "{}",
                f.name
            );
        }
    }

    #[test]
    fn the_port_unit_names_the_subcommand_and_the_state_it_reads() {
        let f = find("hx-agent-port.service").unwrap();
        assert!(
            f.text
                .contains("ExecStart=/usr/lib/hx/current/hx-agent port-rule apply")
        );
        assert!(f.text.contains("PartOf=nftables.service"));
    }
}
