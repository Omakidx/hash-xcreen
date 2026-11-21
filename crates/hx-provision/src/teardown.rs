//! Teardown helpers (ipc.md 6.13: `DestroyDesktop` and `Uninstall`).
//!
//! Both helpers delete **only objects that carry the hash-xcreen marker** (see
//! [`crate::incus::MARKER`]) *and* have the exact name the caller's [`Naming`] gives. A pool,
//! network, ACL or profile with our name but someone else's description is reported as
//! [`Teardown::SkippedUnmarked`] and left alone; an instance without a `user.hx.*` key is refused
//! with [`ProvisionError::NotOurs`]. Nothing is forced: Incus refuses to delete an object that is
//! still in use, and that error is passed on (so a pool that still holds volumes survives).
//!
//! Everything is idempotent: an object that is already gone is [`Teardown::Absent`], and a call
//! that stopped half way is resumed by calling it again.
//!
//! Not covered here, because `hx-provision` never touches the host outside Incus: the nftables
//! table and unit, the `DOCKER-USER` rules and the sysctl file (installer/privd), and Incus itself.

use std::time::Duration;

use crate::host::Naming;
use crate::incus::{Client, StateAction, Transport, description_is_marked, instance_is_marked};
use crate::orchestrate::ProvisionError;

/// What happened to one object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Teardown {
    /// Deleted now.
    Removed,
    /// Did not exist.
    Absent,
    /// Exists with our name but without our marker; left untouched.
    SkippedUnmarked,
}

/// What [`teardown_host`] did, per object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostTeardown {
    /// The desktop profile.
    pub desktop_profile: Teardown,
    /// The compatibility profile.
    pub compat_profile: Teardown,
    /// The bridge network.
    pub network: Teardown,
    /// The ACL.
    pub acl: Teardown,
    /// The storage pool.
    pub pool: Teardown,
}

/// What [`destroy_desktop`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestroyReport {
    /// `false` when the instance did not exist.
    pub instance_removed: bool,
    /// Snapshots named `hx-*` that were deleted first.
    pub snapshots_removed: usize,
    /// Whether the session-link device was removed.
    pub link_removed: bool,
}

/// Delete the profiles, bridge, ACL and pool named by `naming`, in that order (so each is unused
/// by the time it is deleted), skipping any that does not carry the marker.
///
/// Fails (with what Incus said) at the first object that is still in use, for example a profile
/// that a desktop still uses; call [`destroy_desktop`] first. Objects deleted before the failure
/// stay deleted; call again after fixing the cause.
pub async fn teardown_host<T: Transport>(
    client: &Client<T>,
    naming: &Naming,
) -> Result<HostTeardown, ProvisionError> {
    let desktop_profile = remove_profile(client, &naming.desktop_profile).await?;
    let compat_profile = remove_profile(client, &naming.compat_profile).await?;

    let network = match client.get_network(&naming.bridge).await? {
        None => Teardown::Absent,
        Some(n) if !description_is_marked(&n.description) => Teardown::SkippedUnmarked,
        Some(_) => {
            client.delete_network(&naming.bridge).await?;
            Teardown::Removed
        }
    };

    let acl = match client.get_acl(&naming.acl).await? {
        None => Teardown::Absent,
        Some(a) if !description_is_marked(&a.description) => Teardown::SkippedUnmarked,
        Some(_) => {
            client.delete_acl(&naming.acl).await?;
            Teardown::Removed
        }
    };

    let pool = match client.get_storage_pool(&naming.pool).await? {
        None => Teardown::Absent,
        Some(p) if !description_is_marked(&p.description) => Teardown::SkippedUnmarked,
        Some(_) => {
            client.delete_storage_pool(&naming.pool).await?;
            Teardown::Removed
        }
    };

    Ok(HostTeardown {
        desktop_profile,
        compat_profile,
        network,
        acl,
        pool,
    })
}

async fn remove_profile<T: Transport>(
    client: &Client<T>,
    name: &str,
) -> Result<Teardown, ProvisionError> {
    Ok(match client.get_profile(name).await? {
        None => Teardown::Absent,
        Some(p) if !description_is_marked(&p.description) => Teardown::SkippedUnmarked,
        Some(_) => {
            client.delete_profile(name).await?;
            Teardown::Removed
        }
    })
}

/// Stop and delete a desktop instance, but only if it carries the marker
/// (`user.hx.*`, [`ProvisionError::NotOurs`] otherwise): first its `hx-*` snapshots, then the
/// session-link device, then the instance itself (forced stop, 30 s grace).
///
/// An instance that is already gone is a success (`instance_removed: false`). Deleting an
/// instance deletes whatever else is attached to it, including snapshots that are not named
/// `hx-*`: Incus offers no way to keep them.
pub async fn destroy_desktop<T: Transport>(
    client: &Client<T>,
    instance: &str,
) -> Result<DestroyReport, ProvisionError> {
    let Some(inst) = client.get_instance(instance).await? else {
        return Ok(DestroyReport {
            instance_removed: false,
            snapshots_removed: 0,
            link_removed: false,
        });
    };
    if !instance_is_marked(&inst.config) {
        return Err(ProvisionError::NotOurs(instance.to_string()));
    }
    let mut snapshots_removed = 0;
    for s in client.list_snapshots(instance).await? {
        if s.name.starts_with("hx-") {
            client.delete_snapshot(instance, &s.name).await?;
            snapshots_removed += 1;
        }
    }
    let link_removed = client.remove_session_link(instance).await?;
    if !inst.status.eq_ignore_ascii_case("stopped") {
        client
            .set_state(instance, StateAction::Stop, true, Duration::from_secs(30))
            .await?;
    }
    match client.delete_instance(instance).await {
        Ok(()) => {}
        // Deleted by someone else between our read and now.
        Err(e) if e.is_not_found() => {}
        Err(e) => return Err(e.into()),
    }
    Ok(DestroyReport {
        instance_removed: true,
        snapshots_removed,
        link_removed,
    })
}
