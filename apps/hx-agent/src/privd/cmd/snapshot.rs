//! `CreateSnapshot`, `ListSnapshots`, `DeleteSnapshot` (ipc.md 6.10).
//!
//! Snapshot names are generated here (`hx-<kind>-<utc timestamp>-<4 hex>`) or must match
//! `^hx-(manual|preupdate|backup)-[0-9TZ-]+-[0-9a-f]{4}$`; privd never lists, creates over or
//! deletes a snapshot that does not match (ipc.md 7 rule 8).

use hx_ipc::privd::pb::{self, ErrorDetail, Role, response};
use hx_ipc::privd::{is_valid_snapshot_name, snapshot_kind_of};
use hx_provision::incus::Transport;

use super::common::created_of;
use crate::privd::daemon::{Ctx, Daemon, Reply};
use crate::privd::error::CmdError;
use crate::privd::timefmt::snapshot_stamp;

/// Most `manual` snapshots at once.
pub const MAX_MANUAL: usize = 3;
/// Most snapshots `ListSnapshots` returns.
pub const MAX_LIST: usize = 64;
const GIB: u64 = 1 << 30;

fn kind_pb(kind: &str) -> pb::SnapshotKind {
    match kind {
        "manual" => pb::SnapshotKind::Manual,
        "preupdate" => pb::SnapshotKind::Preupdate,
        "backup" => pb::SnapshotKind::Backup,
        _ => pb::SnapshotKind::Unspecified,
    }
}

/// A fresh manual snapshot name.
pub fn new_manual_name(now: u64) -> Result<String, CmdError> {
    let mut b = [0u8; 2];
    getrandom::fill(&mut b).map_err(|_| CmdError::internal("no randomness"))?;
    Ok(format!(
        "hx-manual-{}-{:02x}{:02x}",
        snapshot_stamp(now),
        b[0],
        b[1]
    ))
}

/// `CreateSnapshot` (class A): a `manual` snapshot; at most 3; refused when the pool has less than
/// 15% or 2 GiB free.
pub async fn create<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    r: pb::CreateSnapshotRequest,
) -> Result<Reply, CmdError> {
    let id = r.desktop_id;
    let _g = d.lock_desktop(ctx, &id, false).await?;
    let l = d.load_desktop(&id).await?;
    if l.meta.state != "ready" {
        return Err(CmdError::precondition(
            ErrorDetail::DesktopNotReady,
            "the desktop is not ready",
        ));
    }
    let client = d.incus.scoped();
    let existing = client.list_snapshots(&l.name).await?;
    let manual = existing
        .iter()
        .filter(|s| snapshot_kind_of(&s.name) == Some("manual"))
        .count();
    if manual >= MAX_MANUAL {
        return Err(CmdError::exhausted(
            "at most 3 manual snapshots; delete one first",
            0,
        ));
    }
    let (total, free) = d.probe.pool_space(&d.cfg.naming.pool).ok_or_else(|| {
        CmdError::precondition(ErrorDetail::Pool, "the storage pool cannot be read")
    })?;
    if free < 2 * GIB || free.saturating_mul(100) < total.saturating_mul(15) {
        return Err(CmdError::exhausted(
            "the pool has too little free space for a snapshot",
            0,
        ));
    }
    let now = d.now();
    let name = new_manual_name(now)?;
    debug_assert!(is_valid_snapshot_name(&name));
    d.run_cancellable(ctx, &client, Some(&id), async {
        client.create_snapshot(&l.name, &name).await
    })
    .await?;
    Ok(response::Result::CreateSnapshot(pb::CreateSnapshotResult {
        snapshot: Some(pb::Snapshot {
            name,
            kind: pb::SnapshotKind::Manual as i32,
            created_unix_s: now,
            size_bytes: 0,
        }),
    }))
}

/// `ListSnapshots` (class R): the `hx-` snapshots that match the name pattern, at most 64.
pub async fn list<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    r: pb::ListSnapshotsRequest,
) -> Result<Reply, CmdError> {
    let l = d.load_desktop(&r.desktop_id).await?;
    let snaps = d.incus.list_snapshots(&l.name).await?;
    let out = snaps
        .iter()
        .filter_map(|s| {
            let kind = snapshot_kind_of(&s.name)?;
            Some(pb::Snapshot {
                name: s.name.clone(),
                kind: kind_pb(kind) as i32,
                created_unix_s: created_of(&s.created_at),
                // hx-provision does not report snapshot sizes.
                size_bytes: 0,
            })
        })
        .take(MAX_LIST)
        .collect();
    Ok(response::Result::ListSnapshots(pb::ListSnapshotsResult {
        snapshots: out,
    }))
}

/// `DeleteSnapshot` (class A): Gateway may delete `manual` only, Admin any `hx-` snapshot. A name
/// outside the pattern is `INVALID_ARGUMENT`; one that is already gone succeeds.
pub async fn delete<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    r: pb::DeleteSnapshotRequest,
) -> Result<Reply, CmdError> {
    let kind =
        snapshot_kind_of(&r.name).ok_or_else(|| CmdError::invalid("delete_snapshot.name"))?;
    // Re-checked here: this is the rule that protects update and backup snapshots.
    if ctx.role != Role::Admin && kind != "manual" {
        return Err(CmdError::denied(
            "delete_snapshot.name: only manual snapshots may be deleted by Gateway",
        ));
    }
    let id = r.desktop_id;
    let _g = d.lock_desktop(ctx, &id, false).await?;
    let l = d.load_desktop(&id).await?;
    let client = d.incus.scoped();
    let exists = client
        .list_snapshots(&l.name)
        .await?
        .iter()
        .any(|s| s.name == r.name);
    if exists {
        d.run_cancellable(ctx, &client, Some(&id), async {
            client.delete_snapshot(&l.name, &r.name).await
        })
        .await?;
    }
    Ok(response::Result::DeleteSnapshot(
        pb::DeleteSnapshotResult {},
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_names_match_the_contract_pattern() {
        for t in [0u64, 1_795_256_100, 4_102_444_800] {
            let n = new_manual_name(t).unwrap();
            assert!(is_valid_snapshot_name(&n), "{n}");
            assert_eq!(snapshot_kind_of(&n), Some("manual"));
        }
    }
}
