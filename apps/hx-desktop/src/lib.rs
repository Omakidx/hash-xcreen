//! hash-xcreen desktop client (Slint). See `README.md` for the structure.

pub mod app;
pub mod backend;
pub mod clipboard;
pub mod details;
pub mod files;
pub mod input;
pub mod keys;
pub mod links;
pub mod servers;
pub mod session;
pub mod video;
pub mod wizard;

slint::include_modules!();
