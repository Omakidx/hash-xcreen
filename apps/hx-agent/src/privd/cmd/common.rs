//! Helpers shared by several commands: recipe ids, limit bounds, and the `Desktop` view.

use hx_ipc::privd::pb::{self, DesktopState, DockerState};
use hx_provision::incus::{InstanceState, SESSION_LINK_DEVICE, Transport};
use hx_provision::{Catalog, Desktop, Distro, Preset, RecipeId};

use crate::privd::daemon::{Daemon, LoadedDesktop};
use crate::privd::error::CmdError;
use crate::privd::state::Flag;
use crate::privd::timefmt::parse_rfc3339;

/// The recipe of a `CreateDesktop`: unknown enum values are `INVALID_ARGUMENT`.
pub fn recipe_from_pb(distro: i32, desktop: i32, preset: i32) -> Result<RecipeId, CmdError> {
    let distro = match pb::Distro::try_from(distro) {
        Ok(pb::Distro::Ubuntu2404) => Distro::Ubuntu2404,
        Ok(pb::Distro::Ubuntu2604) => Distro::Ubuntu2604,
        Ok(pb::Distro::Debian12) => Distro::Debian12,
        Ok(pb::Distro::Debian13) => Distro::Debian13,
        _ => return Err(CmdError::invalid("create_desktop.distro")),
    };
    let desktop = match pb::DesktopKind::try_from(desktop) {
        Ok(pb::DesktopKind::Xfce) => Desktop::Xfce,
        _ => return Err(CmdError::invalid("create_desktop.desktop")),
    };
    let preset = match pb::Preset::try_from(preset) {
        Ok(pb::Preset::Basic) => Preset::Basic,
        Ok(pb::Preset::Developer) => Preset::Developer,
        _ => return Err(CmdError::invalid("create_desktop.preset")),
    };
    Ok(RecipeId {
        distro,
        desktop,
        preset,
    })
}

/// `ubuntu-24.04-xfce-basic`, the value of `user.hx.recipe`.
pub fn recipe_text(id: RecipeId) -> String {
    id.file_name().trim_end_matches(".toml").to_string()
}

/// Parses a stored recipe text back; `None` for anything privd did not write.
pub fn recipe_from_text(s: &str) -> Option<RecipeId> {
    RecipeId::all().into_iter().find(|r| recipe_text(*r) == s)
}

/// Wire value of a distro.
pub fn pb_distro(d: Distro) -> pb::Distro {
    match d {
        Distro::Ubuntu2404 => pb::Distro::Ubuntu2404,
        Distro::Ubuntu2604 => pb::Distro::Ubuntu2604,
        Distro::Debian12 => pb::Distro::Debian12,
        Distro::Debian13 => pb::Distro::Debian13,
    }
}

/// Wire value of a preset.
pub fn pb_preset(p: Preset) -> pb::Preset {
    match p {
        Preset::Basic => pb::Preset::Basic,
        Preset::Developer => pb::Preset::Developer,
    }
}

/// `4096MiB` / `4GiB` / `4096MB` as MiB (what Incus reports for `limits.memory`).
pub fn parse_mib(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
    let n: u64 = num.parse().ok()?;
    match unit {
        "MiB" | "MB" => Some(n),
        "GiB" | "GB" => n.checked_mul(1024),
        "" => Some(n / (1024 * 1024)),
        _ => None,
    }
}

/// `40GiB` / `40GB` as GiB (the root device's `size`).
pub fn parse_gib(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
    let n: u64 = num.parse().ok()?;
    match unit {
        "GiB" | "GB" => Some(n),
        "MiB" | "MB" => Some(n / 1024),
        "TiB" | "TB" => n.checked_mul(1024),
        _ => None,
    }
}

/// What the host allows (ipc.md 6.8): computed at call time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostBounds {
    /// CPUs of the host.
    pub cpus: u32,
    /// Total RAM in MiB.
    pub ram_mib: u64,
    /// Free GiB in the storage pool.
    pub pool_free_gib: u64,
}

impl HostBounds {
    /// Memory kept for the host and Incus: the larger of 1 536 MiB and 25% of RAM.
    pub fn memory_reserve_mib(&self) -> u64 {
        1536u64.max(self.ram_mib / 4)
    }

    /// Largest `memory_mib` a desktop may have.
    pub fn max_memory_mib(&self) -> u64 {
        self.ram_mib.saturating_sub(self.memory_reserve_mib())
    }
}

/// The host bounds from the probe. The pool free space is `None` when the pool cannot be read.
pub fn host_bounds<T: Transport + Clone + 'static>(d: &Daemon<T>) -> Result<HostBounds, CmdError> {
    let (ram_mib, _) = d.probe.memory_mib();
    let (_, free) = d.probe.pool_space(&d.cfg.naming.pool).ok_or_else(|| {
        CmdError::precondition(
            pb::ErrorDetail::Pool,
            "the storage pool cannot be read; run SetupHost first",
        )
    })?;
    Ok(HostBounds {
        cpus: d.probe.cpu_count(),
        ram_mib,
        pool_free_gib: free / (1u64 << 30),
    })
}

/// Enforces the bounds of ipc.md 6.8 on a fully specified `Limits`: `1 <= cpu <= host CPUs`;
/// `1024 <= memory_mib <= RAM - reserve`; `min_disk_gib <= disk_gib <= pool free` and no field zero.
pub fn validate_limits(
    cpu: u32,
    memory_mib: u64,
    disk_gib: u64,
    b: &HostBounds,
    min_disk_gib: u64,
) -> Result<(), CmdError> {
    if cpu == 0 || memory_mib == 0 || disk_gib == 0 {
        return Err(CmdError::invalid("limits: no field may be zero"));
    }
    if cpu > b.cpus {
        return Err(CmdError::invalid("limits.cpu: more than the host has"));
    }
    if memory_mib < 1024 {
        return Err(CmdError::invalid("limits.memory_mib: below 1024"));
    }
    if memory_mib > b.max_memory_mib() {
        return Err(CmdError::invalid(
            "limits.memory_mib: leaves too little for the host",
        ));
    }
    if disk_gib < min_disk_gib {
        return Err(CmdError::invalid(
            "limits.disk_gib: below what the desktop already uses",
        ));
    }
    if disk_gib > b.pool_free_gib {
        return Err(CmdError::invalid(
            "limits.disk_gib: more than the pool has free",
        ));
    }
    Ok(())
}

/// The `Desktop` message for a loaded desktop.
pub async fn desktop_view<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    id: &str,
    l: &LoadedDesktop,
) -> Result<pb::Desktop, CmdError> {
    let state = d.incus.instance_state(&l.name).await?;
    let snaps = d
        .incus
        .list_snapshots(&l.name)
        .await?
        .iter()
        .filter(|s| s.name.starts_with("hx-"))
        .count();
    Ok(build_desktop(d, id, l, &state, snaps))
}

fn build_desktop<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    id: &str,
    l: &LoadedDesktop,
    st: &InstanceState,
    snapshots: usize,
) -> pb::Desktop {
    let flags = d.flags_for(id);
    let state = match l.meta.state.as_str() {
        "creating" => DesktopState::Creating,
        "failed" => DesktopState::Failed,
        _ => {
            if st.is_running() {
                DesktopState::Running
            } else if st.status.eq_ignore_ascii_case("stopped") {
                DesktopState::Stopped
            } else {
                DesktopState::Starting
            }
        }
    };
    let nesting = l
        .instance
        .config
        .get("security.nesting")
        .map(String::as_str)
        == Some("true");
    let docker = match (nesting, flags.contains(&Flag::IsolationNotRestored)) {
        (true, true) => DockerState::Degraded,
        (true, false) => DockerState::On,
        _ => DockerState::Off,
    };
    let recipe = recipe_from_text(&l.meta.recipe);
    let cfg = &l.instance.config;
    let root = l
        .instance
        .devices
        .get("root")
        .or_else(|| l.instance.expanded_devices.get("root"));
    let limits = pb::Limits {
        cpu: cfg
            .get("limits.cpu")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        memory_mib: cfg
            .get("limits.memory")
            .and_then(|v| parse_mib(v))
            .unwrap_or(0),
        disk_gib: root
            .and_then(|r| r.get("size"))
            .and_then(|v| parse_gib(v))
            .unwrap_or(0),
    };
    let usage = {
        let mut cpu = d.cpu_samples.lock().unwrap_or_else(|e| e.into_inner());
        let percent = if st.is_running() {
            let cores = if limits.cpu > 0 {
                limits.cpu
            } else {
                d.probe.cpu_count()
            };
            cpu.observe(id, d.clock.unix_ms(), st.cpu_usage_ns, cores)
        } else {
            cpu.forget(id);
            None
        };
        crate::privd::usage::desktop_usage(st, &l.instance, d.clock.unix_secs(), percent)
    };
    pb::Desktop {
        desktop_id: id.to_string(),
        state: state as i32,
        username: l.meta.username.clone(),
        distro: recipe.map_or(pb::Distro::Unspecified, |r| pb_distro(r.distro)) as i32,
        preset: recipe.map_or(pb::Preset::Unspecified, |r| pb_preset(r.preset)) as i32,
        ip: st
            .ipv4
            .values()
            .flatten()
            .next()
            .cloned()
            .unwrap_or_default(),
        limits: Some(limits),
        docker: docker as i32,
        needs_attention: flags.iter().map(|f| f.to_pb() as i32).collect(),
        session: Some(pb::SessionInfo {
            installed_version: cfg
                .get("user.hx.session_version")
                .cloned()
                .unwrap_or_default(),
            link_provisioned: l.instance.devices.contains_key(SESSION_LINK_DEVICE),
        }),
        snapshot_count: u32::try_from(snapshots).unwrap_or(u32::MAX),
        created_unix_s: l.meta.created,
        usage,
    }
}

/// Creation time of a snapshot from Incus's RFC 3339 text.
pub fn created_of(s: &str) -> u64 {
    parse_rfc3339(s).unwrap_or(0)
}

/// The catalog the daemon resolves recipes from: the one compiled into `hx-provision`
/// (`Catalog::embedded`), never a directory.
pub fn catalog<T: Transport + Clone + 'static>(d: &Daemon<T>) -> &Catalog {
    &d.catalog
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipe_text_round_trips_for_every_shipped_recipe() {
        for r in RecipeId::all() {
            assert_eq!(recipe_from_text(&recipe_text(r)), Some(r));
        }
        assert_eq!(recipe_from_text("../etc/passwd"), None);
        assert_eq!(recipe_from_text(""), None);
    }

    #[test]
    fn sizes_parse() {
        assert_eq!(parse_mib("4096MiB"), Some(4096));
        assert_eq!(parse_mib("4GiB"), Some(4096));
        assert_eq!(parse_mib("x"), None);
        assert_eq!(parse_gib("40GiB"), Some(40));
        assert_eq!(parse_gib("2TiB"), Some(2048));
        assert_eq!(parse_gib("40"), None);
    }

    #[test]
    fn limit_bounds_of_ipc_6_8() {
        let b = HostBounds {
            cpus: 8,
            ram_mib: 16_384,
            pool_free_gib: 100,
        };
        // reserve = max(1536, 4096) = 4096, so at most 12288.
        assert_eq!(b.max_memory_mib(), 12_288);
        validate_limits(8, 12_288, 100, &b, 10).unwrap();
        validate_limits(1, 1024, 10, &b, 10).unwrap();
        for (cpu, mem, disk) in [
            (0, 4096, 20),
            (9, 4096, 20),
            (2, 1023, 20),
            (2, 12_289, 20),
            (2, 4096, 9),
            (2, 4096, 101),
            (2, 4096, 0),
        ] {
            assert!(
                validate_limits(cpu, mem, disk, &b, 10).is_err(),
                "{cpu} {mem} {disk}"
            );
        }
        // On a small host the 1536 MiB floor applies.
        let small = HostBounds {
            cpus: 2,
            ram_mib: 4096,
            pool_free_gib: 50,
        };
        assert_eq!(small.max_memory_mib(), 4096 - 1536);
    }
}
