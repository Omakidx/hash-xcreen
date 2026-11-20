//! The shipped recipes, addressed by distro, desktop and preset.

use std::fmt;
use std::str::FromStr;

use crate::error::RecipeError;
use crate::plan::Plan;
use crate::recipe::{DirSource, MemSource, RecipeSource, resolve_addon_only_as, resolve_as};
use crate::user::Username;

/// Guest distro.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Distro {
    /// Ubuntu 24.04 LTS (noble).
    Ubuntu2404,
    /// Ubuntu 26.04 LTS (resolute).
    Ubuntu2604,
    /// Debian 12 (bookworm).
    Debian12,
    /// Debian 13 (trixie).
    Debian13,
}

impl Distro {
    /// Every shipped distro.
    pub const ALL: [Distro; 4] = [
        Distro::Ubuntu2404,
        Distro::Ubuntu2604,
        Distro::Debian12,
        Distro::Debian13,
    ];

    /// Name used in recipe file names and on the command line (`ubuntu-24.04`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ubuntu2404 => "ubuntu-24.04",
            Self::Ubuntu2604 => "ubuntu-26.04",
            Self::Debian12 => "debian-12",
            Self::Debian13 => "debian-13",
        }
    }
}

/// Desktop environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Desktop {
    /// XFCE on headless Xorg.
    Xfce,
}

impl Desktop {
    /// Name used in recipe file names.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Xfce => "xfce",
        }
    }
}

/// Software preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Preset {
    /// XFCE, browser, file manager, text editor.
    Basic,
    /// Basic plus VS Code, git, build tools, Claude Code, Codex CLI.
    Developer,
}

impl Preset {
    /// Every preset.
    pub const ALL: [Preset; 2] = [Preset::Basic, Preset::Developer];

    /// Name used in recipe file names.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Developer => "developer",
        }
    }
}

/// Opt-in add-on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Addon {
    /// Docker Engine with nesting and syscall interception.
    Docker,
}

impl Addon {
    /// Name of the add-on file (`addons/<name>.toml`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
        }
    }

    fn path(self) -> String {
        format!("addons/{}.toml", self.as_str())
    }
}

macro_rules! impl_parse {
    ($t:ty, $what:literal, [$($v:expr),*]) => {
        impl FromStr for $t {
            type Err = RecipeError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                [$($v),*].into_iter().find(|v| v.as_str() == s).ok_or_else(|| RecipeError::UnknownRecipe(format!("{} `{}`", $what, s)))
            }
        }
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

impl_parse!(
    Distro,
    "distro",
    [
        Distro::Ubuntu2404,
        Distro::Ubuntu2604,
        Distro::Debian12,
        Distro::Debian13
    ]
);
impl_parse!(Desktop, "desktop", [Desktop::Xfce]);
impl_parse!(Preset, "preset", [Preset::Basic, Preset::Developer]);
impl_parse!(Addon, "add-on", [Addon::Docker]);

/// A recipe selection: which desktop to provision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecipeId {
    /// Guest distro.
    pub distro: Distro,
    /// Desktop environment.
    pub desktop: Desktop,
    /// Software preset.
    pub preset: Preset,
}

impl RecipeId {
    /// Recipe file name (`ubuntu-24.04-xfce-basic.toml`).
    pub fn file_name(&self) -> String {
        format!("{}-{}-{}.toml", self.distro, self.desktop, self.preset)
    }

    /// Every shipped combination.
    pub fn all() -> Vec<RecipeId> {
        let mut v = Vec::new();
        for distro in Distro::ALL {
            for preset in Preset::ALL {
                v.push(RecipeId {
                    distro,
                    desktop: Desktop::Xfce,
                    preset,
                });
            }
        }
        v
    }
}

/// Recipe files embedded at compile time, as paths relative to the recipes root.
macro_rules! embed {
    ($($p:literal),* $(,)?) => {
        MemSource::new()$(.with($p, include_str!(concat!("../../../recipes/", $p))))*
    };
}

/// The recipes shipped in this repository, compiled into the crate.
pub fn embedded_source() -> MemSource {
    embed!(
        "fragments/xfce-desktop.toml",
        "fragments/distro-ubuntu-24.04.toml",
        "fragments/distro-ubuntu-26.04.toml",
        "fragments/distro-debian-12.toml",
        "fragments/distro-debian-13.toml",
        "fragments/preset-basic.toml",
        "fragments/preset-developer.toml",
        "addons/docker.toml",
        "ubuntu-24.04-xfce-basic.toml",
        "ubuntu-24.04-xfce-developer.toml",
        "ubuntu-26.04-xfce-basic.toml",
        "ubuntu-26.04-xfce-developer.toml",
        "debian-12-xfce-basic.toml",
        "debian-12-xfce-developer.toml",
        "debian-13-xfce-basic.toml",
        "debian-13-xfce-developer.toml",
    )
}

/// A set of recipes that can be resolved by [`RecipeId`].
pub struct Catalog {
    source: Box<dyn RecipeSource + Send + Sync>,
}

impl Catalog {
    /// The recipes compiled into this crate.
    pub fn embedded() -> Self {
        Self {
            source: Box::new(embedded_source()),
        }
    }

    /// Recipes from a directory (for development, or an installed override).
    pub fn from_dir(root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            source: Box::new(DirSource::new(root)),
        }
    }

    /// Use any source.
    pub fn from_source(source: impl RecipeSource + Send + Sync + 'static) -> Self {
        Self {
            source: Box::new(source),
        }
    }

    /// Resolve a recipe with the given add-ons into a plan, with the default user `desk`.
    pub fn resolve(&self, id: RecipeId, addons: &[Addon]) -> Result<Plan, RecipeError> {
        self.resolve_for(id, addons, None)
    }

    /// Resolve with the desktop user the caller chose (`None`: the recipe's `desk`). Use this from
    /// `hx-privd`; a chosen name that differs from `desk` adds a rename step to the post stage so
    /// prebuilt images (built with `desk`) end up with the right account.
    pub fn resolve_for(
        &self,
        id: RecipeId,
        addons: &[Addon],
        username: Option<&Username>,
    ) -> Result<Plan, RecipeError> {
        let paths: Vec<String> = addons.iter().map(|a| a.path()).collect();
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        resolve_as(self.source.as_ref(), &id.file_name(), &refs, username)
    }

    /// Resolve only the steps of an add-on, for a desktop that already exists.
    pub fn resolve_addon(&self, id: RecipeId, addon: Addon) -> Result<Plan, RecipeError> {
        self.resolve_addon_for(id, addon, None)
    }

    /// Like [`Catalog::resolve_addon`] for a desktop whose user is `username`.
    pub fn resolve_addon_for(
        &self,
        id: RecipeId,
        addon: Addon,
        username: Option<&Username>,
    ) -> Result<Plan, RecipeError> {
        resolve_addon_only_as(
            self.source.as_ref(),
            &id.file_name(),
            &addon.path(),
            username,
        )
    }
}
