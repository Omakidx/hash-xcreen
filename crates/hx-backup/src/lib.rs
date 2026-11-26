//! Full-desktop backups to Google Drive with rustic_core: scheduling, retention, verification.
//!
//! This first slice is transport-agnostic: it knows nothing about Drive, Incus, HTTP or
//! `hx-privd`. `rules` and `manifest` have no rustic dependency; `engine` (feature `engine`, off by
//! default) links `rustic_core`. See the crate README for the module map.

#[cfg(feature = "engine")]
pub mod engine;
pub mod manifest;
pub mod rules;
