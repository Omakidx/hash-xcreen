//! Declarative desktop recipes and Incus orchestration.
//!
//! `hx-provision` is a library used by the privileged agent (`hx-privd`). It has two halves:
//!
//! 1. **Recipes** ([`recipe`], [`catalog`], [`plan`], [`manifest`], [`exec`]): parse the TOML
//!    recipes in `recipes/`, resolve includes, variables, presets and add-ons into a flat, ordered
//!    [`plan::Plan`], and apply the plan inside a container through an [`exec::Executor`].
//! 2. **Incus** (`incus`, `host`, `orchestrate`, `docker`): a typed client for the Incus REST API
//!    over its unix socket, and the setup built on it: storage pool, bridge network with ACLs,
//!    profiles, unprivileged container with limits, readiness check, snapshots, and the Docker
//!    opt-in with its self-test.
//!
//! Secrets (the desktop user's password) never appear in recipes, plans, argv, environment, logs
//! or error messages; see [`exec`].
//!
//! The crate contains no `unsafe` and does not panic on malformed API responses.

#![forbid(unsafe_code)]

pub mod catalog;
pub mod error;
pub mod exec;
pub mod host;
pub mod incus;
pub mod lower;
pub mod manifest;
pub mod orchestrate;
pub mod plan;
pub mod recipe;

pub use catalog::{Addon, Catalog, Desktop, Distro, Preset, RecipeId};
pub use error::RecipeError;
pub use exec::{
    Action, ApplyError, ExecError, ExecOutput, ExecRequest, Executor, FilePush, Progress, Secret,
    SecretError, Secrets, StageReport, StepFailure, StepWarning, apply_stage,
};
pub use host::{HostReport, HostSpec, Naming, PoolSource, ensure_host};
pub use manifest::Manifest;
pub use orchestrate::{
    DesktopSpec, IncusExecutor, Limits, ProvisionError, ProvisionReport, build_on_server,
    destroy_instance, finish_prebuilt, wait_system_running,
};
pub use plan::{ImageRef, Plan, Stage, Step};
pub use recipe::{DirSource, MemSource, RecipeSource};
