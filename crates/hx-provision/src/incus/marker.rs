//! The hash-xcreen marker on Incus objects (ipc.md 7, rule 8).
//!
//! Destructive helpers act only on objects that carry it, so an object that merely has a name
//! like ours (made by someone else, or left from another tool) is never deleted:
//!
//! - **pool, network, ACL, profiles**: the `description` starts with [`MARKER`];
//! - **instances**: at least one config key starts with [`INSTANCE_KEY_PREFIX`] (`user.hx.`).
//!
//! Everything hash-xcreen creates is marked at creation time (the client sets the description of
//! pools and networks; the profile and ACL builders in [`crate::host`] set theirs;
//! [`DesktopSpec::to_create`](crate::DesktopSpec::to_create) sets `user.hx.state`).

use std::collections::BTreeMap;

/// Description prefix of every pool, network, ACL and profile we create.
pub const MARKER: &str = "hash-xcreen";
/// Config key prefix of every instance we create.
pub const INSTANCE_KEY_PREFIX: &str = "user.hx.";
/// The state key `hx-privd` keeps on each desktop (`creating`, `ready`, ...). It is set to
/// `creating` when the instance is created, so no instance of ours is ever unmarked.
pub const INSTANCE_STATE_KEY: &str = "user.hx.state";
/// Description of the storage pool.
pub const POOL_DESCRIPTION: &str = "hash-xcreen: storage pool for desktops";
/// Description of the bridge network.
pub const NETWORK_DESCRIPTION: &str = "hash-xcreen: isolated bridge for desktops";

/// Whether a pool, network, ACL or profile description carries the marker.
pub fn description_is_marked(description: &str) -> bool {
    description.starts_with(MARKER)
}

/// Whether an instance's config carries the marker.
pub fn instance_is_marked(config: &BTreeMap<String, String>) -> bool {
    config.keys().any(|k| k.starts_with(INSTANCE_KEY_PREFIX))
}
