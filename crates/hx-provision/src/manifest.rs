//! A secret-free summary of what a plan installs.
//!
//! The CI equivalence check builds the desktop both ways (prebuilt image, server build), extracts
//! the same facts from the running container, and compares them with [`Manifest::diff`]. Both
//! paths run the same [`Plan`], so the manifest of the plan is the expected value.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::plan::{Plan, Step};

/// One configured apt repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ManifestRepo {
    /// Repository name.
    pub name: String,
    /// Pinned key fingerprint.
    pub fingerprint: String,
    /// Base URI.
    pub uri: String,
    /// Suite.
    pub suite: String,
}

/// One file with its content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ManifestFile {
    /// Absolute path.
    pub path: String,
    /// Octal mode.
    pub mode: String,
    /// `user[:group]`.
    pub owner: String,
    /// SHA-256 of the content, lower-case hex.
    pub sha256: String,
}

/// Expected packages, repositories, files and services. All lists are sorted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Manifest {
    /// Recipe name.
    pub recipe: String,
    /// Packages requested from apt.
    pub packages: Vec<String>,
    /// Apt repositories.
    pub apt_repos: Vec<ManifestRepo>,
    /// Files written by the recipe.
    pub files: Vec<ManifestFile>,
    /// Units enabled with `systemctl enable`.
    pub system_services: Vec<String>,
    /// Units enabled with `systemctl --global enable`.
    pub user_services: Vec<String>,
    /// Desktop user name, if any.
    pub user: Option<String>,
    /// Groups of the desktop user.
    pub user_groups: Vec<String>,
    /// Instance configuration.
    pub incus_config: BTreeMap<String, String>,
    /// Names of commands in the post stage (they run after both paths).
    pub post_commands: Vec<String>,
}

impl Manifest {
    pub(crate) fn from_plan(plan: &Plan) -> Self {
        let mut m = Manifest {
            recipe: plan.name.clone(),
            incus_config: plan.incus_config.clone(),
            ..Self::default()
        };
        for step in &plan.build {
            match step {
                Step::AptRepo(r) => m.apt_repos.push(ManifestRepo {
                    name: r.name.clone(),
                    fingerprint: r.key_fingerprint.clone(),
                    uri: r.uri.clone(),
                    suite: r.suite.clone(),
                }),
                Step::AptInstall { packages } => m.packages.extend(packages.iter().cloned()),
                Step::WriteFile(f) => m.files.push(ManifestFile {
                    path: f.path.clone(),
                    mode: f.mode.clone(),
                    owner: f.owner.clone(),
                    sha256: f.sha256(),
                }),
                Step::EnableServices { services, .. } => {
                    m.system_services
                        .extend(services.system_enable.iter().cloned());
                    m.user_services
                        .extend(services.user_enable_global.iter().cloned());
                }
                Step::EnsureUser(u) => {
                    m.user = Some(u.name.clone());
                    m.user_groups.extend(u.groups.iter().cloned());
                }
                _ => {}
            }
        }
        for step in &plan.post {
            if let Step::Command(c) = step {
                m.post_commands.push(c.name.clone());
            }
        }
        m.packages.sort();
        m.packages.dedup();
        m.apt_repos.sort();
        m.files.sort();
        m.system_services.sort();
        m.system_services.dedup();
        m.user_services.sort();
        m.user_services.dedup();
        m.user_groups.sort();
        m.user_groups.dedup();
        m
    }

    /// Human-readable differences from `other`; empty when equal.
    pub fn diff(&self, other: &Manifest) -> Vec<String> {
        let mut out = Vec::new();
        diff_list("package", &self.packages, &other.packages, &mut out);
        diff_list("apt repo", &self.apt_repos, &other.apt_repos, &mut out);
        diff_list("file", &self.files, &other.files, &mut out);
        diff_list(
            "system service",
            &self.system_services,
            &other.system_services,
            &mut out,
        );
        diff_list(
            "user service",
            &self.user_services,
            &other.user_services,
            &mut out,
        );
        diff_list(
            "user group",
            &self.user_groups,
            &other.user_groups,
            &mut out,
        );
        diff_list(
            "post command",
            &self.post_commands,
            &other.post_commands,
            &mut out,
        );
        if self.user != other.user {
            out.push(format!("user: {:?} vs {:?}", self.user, other.user));
        }
        if self.incus_config != other.incus_config {
            out.push(format!(
                "incus_config: {:?} vs {:?}",
                self.incus_config, other.incus_config
            ));
        }
        out
    }
}

fn diff_list<T: PartialEq + std::fmt::Debug>(what: &str, a: &[T], b: &[T], out: &mut Vec<String>) {
    for x in a.iter().filter(|x| !b.contains(x)) {
        out.push(format!("{what} only on the left: {x:?}"));
    }
    for x in b.iter().filter(|x| !a.contains(x)) {
        out.push(format!("{what} only on the right: {x:?}"));
    }
}
