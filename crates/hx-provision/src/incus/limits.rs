//! Changing the limits of an existing instance (ipc.md 6.8).

use super::error::IncusError;

/// Largest values accepted, far above any host; they only keep absurd input from reaching Incus.
pub const MAX_CPU: u32 = 4096;
/// Largest accepted `limits.memory`, in MiB (4 PiB).
pub const MAX_MEMORY_MIB: u64 = 1 << 32;
/// Largest accepted root disk size, in GiB (1 PiB).
pub const MAX_DISK_GIB: u64 = 1 << 20;

/// New limits for a live instance. `None` leaves that limit as it is.
///
/// `hx-provision` enforces only "not zero" and the sanity maxima above; **all host-dependent
/// bounds (CPUs of the host, memory headroom, never below current disk use, pool free space) are
/// `hx-privd`'s job and must be checked before this is called** (ipc.md 6.8). `limits.processes`
/// and every other key are deliberately not settable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LimitsUpdate {
    /// `limits.cpu`.
    pub cpu: Option<u32>,
    /// `limits.memory`, in MiB.
    pub memory_mib: Option<u64>,
    /// Size of the root disk, in GiB (the root device's `size`).
    pub disk_gib: Option<u64>,
}

impl LimitsUpdate {
    pub(crate) fn validate(&self) -> Result<(), IncusError> {
        if self.cpu.is_none() && self.memory_mib.is_none() && self.disk_gib.is_none() {
            return Err(IncusError::InvalidArgument(
                "limits: nothing to change".into(),
            ));
        }
        let bad = |what: &str, max: String| {
            Err(IncusError::InvalidArgument(format!(
                "limits: {what} must be between 1 and {max}"
            )))
        };
        if let Some(c) = self.cpu
            && !(1..=MAX_CPU).contains(&c)
        {
            return bad("cpu", MAX_CPU.to_string());
        }
        if let Some(m) = self.memory_mib
            && !(1..=MAX_MEMORY_MIB).contains(&m)
        {
            return bad("memory_mib", MAX_MEMORY_MIB.to_string());
        }
        if let Some(d) = self.disk_gib
            && !(1..=MAX_DISK_GIB).contains(&d)
        {
            return bad("disk_gib", MAX_DISK_GIB.to_string());
        }
        Ok(())
    }
}

/// What [`Client::set_limits`](super::Client::set_limits) did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LimitsApplied {
    /// The Incus keys that were written (`limits.cpu`, `limits.memory`, `devices.root.size`).
    pub changed: Vec<&'static str>,
    /// Whether the instance must be restarted for the change to take effect. Incus applies CPU,
    /// memory and root-disk limits to a running container immediately and fails the call when a
    /// storage driver cannot resize live, so this is `false` for every successful call; the field
    /// exists so that callers need not change if that ever differs.
    pub restart_required: bool,
}
