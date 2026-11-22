//! The equivalence check between a desktop built on the server and one made from a prebuilt
//! image (contract C5).
//!
//! Image CI creates both desktops on the same runner with the same user and settings, runs
//! [`collect_facts`] on each once it is `running`, and calls [`compare`]. The check is what lets
//! a prebuilt image stand in for a server build: any [`Severity::Error`] drift blocks publication.
//!
//! # How facts are read
//!
//! `dpkg-query` alone prints far more than the 64 KiB an exec capture keeps. So one script
//! writes every fact into a file in a root-only directory under [`crate::orchestrate::WORK_DIR`]
//! inside the container, and each file is read back through the file API with a hard cap of
//! [`MAX_FACT_FILE`] bytes. Password hashes never leave the container: `shadow` is reduced to
//! its non-secret fields by the script itself. The container's output is untrusted data and is
//! parsed strictly, without panics.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::incus::{Client, Transport};
use crate::manifest::Manifest;
use crate::orchestrate::{ProvisionError, WORK_DIR, exec_captured};
use crate::plan::hex;

/// Directory inside the container that holds the fact files while they are collected.
pub const FACTS_DIR: &str = "/run/hx-provision/facts";
/// Largest fact file read back: 16 MiB.
pub const MAX_FACT_FILE: usize = 16 * 1024 * 1024;
/// Most packages that may differ between the two desktops while both are auto-installed.
pub const MAX_AUTO_PACKAGE_DRIFT: usize = 5;
/// Placeholder written over the instance name in `/etc/hostname` and `/etc/hosts` before hashing,
/// so that two instances with different names compare equal and an image that carries the
/// *build* instance's name does not.
pub const INSTANCE_PLACEHOLDER: &str = "@INSTANCE@";
/// Services started on demand (by D-Bus or a socket) whose running state is not compared.
pub const ON_DEMAND_SERVICES: [&str; 9] = [
    "systemd-hostnamed.service",
    "systemd-timedated.service",
    "systemd-localed.service",
    "packagekit.service",
    "colord.service",
    "upower.service",
    "udisks2.service",
    "accounts-daemon.service",
    "rtkit-daemon.service",
];
/// Version of the [`Facts`] document.
pub const FACTS_SCHEMA: u32 = 1;

/// A package as `dpkg-query` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct PackageFact {
    /// Package name.
    pub name: String,
    /// Architecture.
    pub arch: String,
    /// `ii` for an installed package, other abbreviations for the rest.
    pub status: String,
    /// Version.
    pub version: String,
}

/// A file, directory or link, from `find -printf`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct FileFact {
    /// Absolute path.
    pub path: String,
    /// `f` file, `d` directory, `l` symlink, anything else as `find` names it.
    pub kind: String,
    /// Permission bits (`find %m`, octal, including set-id and sticky bits).
    pub mode: u32,
    /// `user:group` by name.
    pub owner: String,
    /// SHA-256 of a regular file's content (absent for the home and state trees, which are
    /// compared without content).
    pub sha256: Option<String>,
    /// Target of a symlink.
    pub target: Option<String>,
}

/// Everything compared between two desktops. Serializable, so image CI can write one file per
/// desktop and compare them in a later step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Facts {
    /// [`FACTS_SCHEMA`].
    pub schema: u32,
    /// The instance the facts were read from.
    pub instance: String,
    /// The desktop user the facts were read for.
    pub user: String,
    /// Every package dpkg knows, sorted.
    pub packages: Vec<PackageFact>,
    /// `apt-mark showauto`, sorted.
    pub apt_auto: Vec<String>,
    /// `apt-mark showmanual`, sorted.
    pub apt_manual: Vec<String>,
    /// SHA-256 of every file of `/etc/apt/sources.list.d`, `/etc/apt/keyrings` and
    /// `/usr/share/keyrings/hx-*`, by path.
    pub apt_files: BTreeMap<String, String>,
    /// The `/etc` tree, minus the excluded names, sorted by path.
    pub etc: Vec<FileFact>,
    /// The package that owns each `/etc` path dpkg knows, by path.
    pub etc_owner: BTreeMap<String, String>,
    /// `/etc/passwd`, sorted lines.
    pub passwd: Vec<String>,
    /// `/etc/group`, sorted lines.
    pub group: Vec<String>,
    /// `/etc/subuid`, sorted lines.
    pub subuid: Vec<String>,
    /// `/etc/subgid`, sorted lines.
    pub subgid: Vec<String>,
    /// `/etc/shadow` without the hash and the last-change field, sorted lines.
    pub shadow: Vec<String>,
    /// `id -nG <user>`, sorted.
    pub user_groups: Vec<String>,
    /// The home and state trees (path, type, mode, owner; no content), by root.
    pub trees: BTreeMap<String, Vec<FileFact>>,
    /// Units of `systemctl list-unit-files --state=enabled`, sorted.
    pub enabled_system: Vec<String>,
    /// Units of `systemctl --global list-unit-files --state=enabled`, sorted.
    pub enabled_user_global: Vec<String>,
    /// Services of `systemctl list-units --type=service --state=running`, sorted.
    pub running_services: Vec<String>,
    /// `systemctl is-system-running`.
    pub system_state: String,
    /// Units of `systemctl --failed`, sorted.
    pub failed_units: Vec<String>,
}

/// The roots whose structure (not content) is compared.
pub fn tree_roots(user: &str) -> Vec<String> {
    vec![
        format!("/home/{user}"),
        "/var/lib/hx-session".into(),
        "/var/lib/systemd/linger".into(),
    ]
}

/// The collection script. Arguments: `$1` the facts directory, `$2` the user. Fixed text; nothing
/// is interpolated into it.
const COLLECT_SCRIPT: &str = r#"d=$1; u=$2
export LC_ALL=C
umask 077
rm -rf -- "$d"; mkdir -p -- "$d"
dpkg-query -W -f '${Package}\t${Architecture}\t${db:Status-Abbrev}\t${Version}\n' > "$d/packages"
apt-mark showauto 2>/dev/null | sort > "$d/auto"
apt-mark showmanual 2>/dev/null | sort > "$d/manual"
{ find /etc/apt/sources.list.d /etc/apt/keyrings -type f -print0 2>/dev/null
  find /usr/share/keyrings -name 'hx-*' -type f -print0 2>/dev/null; } | xargs -0 -r sha256sum -z > "$d/aptfiles"
# /etc, without the names that legitimately differ between any two boots or builds.
excl=( \( -path '/etc/ssh/ssh_host_*' -o -name 'shadow*' -o -name 'gshadow*' -o -name '*-' \
  -o -name ld.so.cache -o -name resolv.conf -o -name machine-id -o -name adjtime \
  -o -name '*.dpkg-dist' -o -name '*.dpkg-old' -o -name '*.dpkg-new' \) -prune -o )
fmt='%y\t%m\t%u\t%g\t%p\t%l\0'
find /etc -xdev "${excl[@]}" -printf "$fmt" > "$d/etc"
find /etc -xdev "${excl[@]}" -type f -print0 | xargs -0 -r sha256sum -z > "$d/etchash"
awk 'FNR==1{p=FILENAME; sub(".*/","",p); sub(/\.list$/,"",p)} /^\/etc\//{print p "\t" $0}' /var/lib/dpkg/info/*.list > "$d/etcowner" 2>/dev/null
sort /etc/passwd > "$d/passwd"
sort /etc/group > "$d/group"
sort /etc/subuid > "$d/subuid" 2>/dev/null
sort /etc/subgid > "$d/subgid" 2>/dev/null
awk -F: 'BEGIN{OFS=":"} {$2=""; $3=""; print}' /etc/shadow | sort > "$d/shadow"
id -nG "$u" 2>/dev/null | tr ' ' '\n' | sort > "$d/usergroups"
# Home and state trees: structure only. Caches, per-application state and what the XFCE session
# generates at its own pace (.config/xfce4: panel, desktop and xfconf files appear when the session
# first runs) are not compared.
find "/home/$u" -xdev \( \( -path '*/.cache' -o -path '*/.config/xfce4' \) -printf "$fmt" -prune \) -o \( -path '*/.local/share/*/*' -prune \) -o -printf "$fmt" > "$d/tree0" 2>/dev/null
find /var/lib/hx-session -xdev -printf "$fmt" > "$d/tree1" 2>/dev/null
find /var/lib/systemd/linger -xdev -printf "$fmt" > "$d/tree2" 2>/dev/null
systemctl list-unit-files --state=enabled --no-legend --no-pager > "$d/svc_enabled" 2>/dev/null
systemctl --global list-unit-files --state=enabled --no-legend --no-pager > "$d/svc_user_enabled" 2>/dev/null
systemctl list-units --type=service --state=running --no-legend --plain --no-pager > "$d/svc_running" 2>/dev/null
systemctl is-system-running > "$d/sysstate" 2>/dev/null
systemctl --failed --no-legend --plain --no-pager > "$d/failed" 2>/dev/null
true
"#;

fn bad(file: &str, why: impl std::fmt::Display) -> ProvisionError {
    ProvisionError::Invalid(format!("facts file `{file}`: {why}"))
}

async fn fetch<T: Transport>(
    client: &Client<T>,
    instance: &str,
    name: &str,
) -> Result<Vec<u8>, ProvisionError> {
    client
        .read_file(instance, &format!("{FACTS_DIR}/{name}"), MAX_FACT_FILE)
        .await?
        .ok_or_else(|| bad(name, "missing"))
}

fn text(file: &str, bytes: Vec<u8>) -> Result<String, ProvisionError> {
    String::from_utf8(bytes).map_err(|_| bad(file, "not UTF-8"))
}

fn sorted_lines(file: &str, bytes: Vec<u8>) -> Result<Vec<String>, ProvisionError> {
    let mut v: Vec<String> = text(file, bytes)?
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    v.sort();
    Ok(v)
}

/// First whitespace-separated word of each line, sorted (unit listings).
fn first_words(file: &str, bytes: Vec<u8>) -> Result<Vec<String>, ProvisionError> {
    let mut v: Vec<String> = text(file, bytes)?
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_string)
        .collect();
    v.sort();
    v.dedup();
    Ok(v)
}

/// `sha256sum -z` output: records `<hex>  <path>` separated by NUL.
fn hashes(file: &str, bytes: &[u8]) -> Result<BTreeMap<String, String>, ProvisionError> {
    let mut out = BTreeMap::new();
    for rec in bytes.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let s = std::str::from_utf8(rec).map_err(|_| bad(file, "not UTF-8"))?;
        let (h, p) = s
            .split_once("  ")
            .ok_or_else(|| bad(file, "malformed hash record"))?;
        if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(bad(file, "malformed hash"));
        }
        out.insert(p.to_string(), h.to_ascii_lowercase());
    }
    Ok(out)
}

/// `find -printf '%y\t%m\t%u\t%g\t%p\t%l\0'` output.
fn find_records(file: &str, bytes: &[u8]) -> Result<Vec<FileFact>, ProvisionError> {
    let mut out = Vec::new();
    for rec in bytes.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let s = std::str::from_utf8(rec).map_err(|_| bad(file, "not UTF-8"))?;
        let f: Vec<&str> = s.split('\t').collect();
        if f.len() != 6 {
            return Err(bad(file, "malformed record"));
        }
        let mode = u32::from_str_radix(f[1], 8).map_err(|_| bad(file, "malformed mode"))?;
        out.push(FileFact {
            path: f[4].to_string(),
            kind: f[0].to_string(),
            mode,
            owner: format!("{}:{}", f[2], f[3]),
            sha256: None,
            target: (!f[5].is_empty()).then(|| f[5].to_string()),
        });
    }
    out.sort();
    Ok(out)
}

fn packages(file: &str, bytes: Vec<u8>) -> Result<Vec<PackageFact>, ProvisionError> {
    let mut out = Vec::new();
    for line in text(file, bytes)?.lines().filter(|l| !l.is_empty()) {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 4 {
            return Err(bad(file, "malformed package line"));
        }
        out.push(PackageFact {
            name: f[0].to_string(),
            arch: f[1].to_string(),
            status: f[2].trim().to_string(),
            version: f[3].to_string(),
        });
    }
    out.sort();
    Ok(out)
}

/// Read the facts of a running desktop. `user` is the account the desktop was created for
/// (after the prebuilt path's rename); `instance` must be running.
///
/// `/etc/hostname` and `/etc/hosts` are hashed with the instance name replaced by
/// [`INSTANCE_PLACEHOLDER`].
pub async fn collect_facts<T: Transport>(
    client: &Client<T>,
    instance: &str,
    user: &str,
) -> Result<Facts, ProvisionError> {
    crate::user::Username::new(user)
        .map_err(|e| ProvisionError::Invalid(format!("user `{user}`: {e}")))?;
    let argv: Vec<String> = ["bash", "-c", COLLECT_SCRIPT, "bash", FACTS_DIR, user]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let run = exec_captured(
        client,
        instance,
        &argv,
        &[],
        None,
        None,
        Duration::from_secs(900),
    )
    .await;
    let facts = match run {
        Ok(r) if r.exit_code == 0 => read_facts(client, instance, user).await,
        Ok(r) => Err(ProvisionError::Invalid(format!(
            "collecting facts failed (exit {}): {}",
            r.exit_code,
            crate::exec::sanitize(&r.stderr, 300)
        ))),
        Err(e) => Err(e.into()),
    };
    // Always remove the files (best effort), including the work directory's parent state.
    let _ = exec_captured(
        client,
        instance,
        &["rm".into(), "-rf".into(), "--".into(), FACTS_DIR.into()],
        &[],
        None,
        None,
        Duration::from_secs(60),
    )
    .await;
    let _ = WORK_DIR;
    facts
}

async fn read_facts<T: Transport>(
    client: &Client<T>,
    instance: &str,
    user: &str,
) -> Result<Facts, ProvisionError> {
    let get = async |n: &str| fetch(client, instance, n).await;
    let mut etc = find_records("etc", &get("etc").await?)?;
    let etchash = hashes("etchash", &get("etchash").await?)?;
    for f in &mut etc {
        if f.kind == "f" {
            f.sha256 = etchash.get(&f.path).cloned();
        }
    }
    // The instance name lives in these two (Incus renders them from the instance name).
    for path in ["/etc/hostname", "/etc/hosts"] {
        if let Some(f) = etc.iter_mut().find(|f| f.path == path && f.kind == "f")
            && let Some(body) = client.read_file(instance, path, 64 * 1024).await?
        {
            let norm = String::from_utf8_lossy(&body).replace(instance, INSTANCE_PLACEHOLDER);
            f.sha256 = Some(hex(&Sha256::digest(norm.as_bytes())));
        }
    }
    let mut etc_owner = BTreeMap::new();
    for line in text("etcowner", get("etcowner").await?)?
        .lines()
        .filter(|l| !l.is_empty())
    {
        let (pkg, path) = line
            .split_once('\t')
            .ok_or_else(|| bad("etcowner", "malformed line"))?;
        // `pkg:arch` file names: the owner is the package.
        etc_owner.insert(path.to_string(), pkg.to_string());
    }
    let mut trees = BTreeMap::new();
    for (i, root) in tree_roots(user).into_iter().enumerate() {
        trees.insert(
            root,
            find_records("tree", &get(&format!("tree{i}")).await?)?,
        );
    }
    Ok(Facts {
        schema: FACTS_SCHEMA,
        instance: instance.to_string(),
        user: user.to_string(),
        packages: packages("packages", get("packages").await?)?,
        apt_auto: sorted_lines("auto", get("auto").await?)?,
        apt_manual: sorted_lines("manual", get("manual").await?)?,
        apt_files: hashes("aptfiles", &get("aptfiles").await?)?,
        etc,
        etc_owner,
        passwd: sorted_lines("passwd", get("passwd").await?)?,
        group: sorted_lines("group", get("group").await?)?,
        subuid: sorted_lines("subuid", get("subuid").await?)?,
        subgid: sorted_lines("subgid", get("subgid").await?)?,
        shadow: sorted_lines("shadow", get("shadow").await?)?,
        user_groups: sorted_lines("usergroups", get("usergroups").await?)?,
        trees,
        enabled_system: first_words("svc_enabled", get("svc_enabled").await?)?,
        enabled_user_global: first_words("svc_user_enabled", get("svc_user_enabled").await?)?,
        running_services: first_words("svc_running", get("svc_running").await?)?,
        system_state: text("sysstate", get("sysstate").await?)?.trim().to_string(),
        failed_units: first_words("failed", get("failed").await?)?,
    })
}

// ---------------------------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------------------------

/// What kind of fact differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Area {
    /// Installed packages, versions, manual/auto marks.
    Packages,
    /// apt sources and keyrings.
    AptSources,
    /// Files the recipe writes.
    RecipeFiles,
    /// The `/etc` tree.
    Etc,
    /// `passwd`, `group`, `subuid`, `subgid`, `shadow`, the user's groups.
    Accounts,
    /// Home and state trees.
    Trees,
    /// Enabled and running units, boot state.
    Services,
    /// What the plan's manifest expects.
    Manifest,
}

impl Area {
    /// Stable lower-case name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Packages => "packages",
            Self::AptSources => "apt-sources",
            Self::RecipeFiles => "recipe-files",
            Self::Etc => "etc",
            Self::Accounts => "accounts",
            Self::Trees => "trees",
            Self::Services => "services",
            Self::Manifest => "manifest",
        }
    }
}

/// How much a drift matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Reported and tolerated by the rules (a differing version, up to
    /// [`MAX_AUTO_PACKAGE_DRIFT`] auto-installed packages, content of a package whose version
    /// differs).
    Info,
    /// The two desktops are not equivalent: image CI fails.
    Error,
}

/// One difference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Drift {
    /// What kind of fact.
    pub area: Area,
    /// Whether it blocks.
    pub severity: Severity,
    /// The package, path or unit concerned.
    pub subject: String,
    /// What differs, naming the side (`A` is the server build, `B` the prebuilt path).
    pub detail: String,
}

impl Drift {
    fn error(area: Area, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            area,
            severity: Severity::Error,
            subject: subject.into(),
            detail: detail.into(),
        }
    }
    fn info(area: Area, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            ..Self::error(area, subject, detail)
        }
    }
}

/// Whether any drift blocks (is a [`Severity::Error`]).
pub fn has_errors(drifts: &[Drift]) -> bool {
    drifts.iter().any(|d| d.severity == Severity::Error)
}

/// A Markdown table of the drifts, for `GITHUB_STEP_SUMMARY`.
pub fn render_table(drifts: &[Drift]) -> String {
    if drifts.is_empty() {
        return "No drift: the prebuilt desktop is equivalent to the server build.\n".into();
    }
    let esc = |s: &str| s.replace('|', "\\|").replace('\n', " ");
    let mut out = String::from("| Severity | Area | Subject | Detail |\n|---|---|---|---|\n");
    for d in drifts {
        out.push_str(&format!(
            "| {} | {} | `{}` | {} |\n",
            match d.severity {
                Severity::Info => "info",
                Severity::Error => "ERROR",
            },
            d.area.as_str(),
            esc(&d.subject),
            esc(&d.detail)
        ));
    }
    out
}

fn set_diff(
    area: Area,
    what: &str,
    a: &[String],
    b: &[String],
    subject: &dyn Fn(&str) -> String,
    out: &mut Vec<Drift>,
) {
    let (sa, sb): (BTreeSet<&String>, BTreeSet<&String>) = (a.iter().collect(), b.iter().collect());
    for x in sa.difference(&sb) {
        out.push(Drift::error(area, subject(x), format!("{what} only on A")));
    }
    for x in sb.difference(&sa) {
        out.push(Drift::error(area, subject(x), format!("{what} only on B")));
    }
}

fn installed_index(f: &Facts) -> BTreeMap<String, &PackageFact> {
    f.packages
        .iter()
        .filter(|p| p.status == "ii")
        .map(|p| (pkg_key(p), p))
        .collect()
}

fn etc_index(f: &Facts) -> BTreeMap<String, &FileFact> {
    f.etc.iter().map(|e| (e.path.clone(), e)).collect()
}

fn tree_index<'a>(f: &'a Facts, root: &str) -> BTreeMap<String, &'a FileFact> {
    f.trees
        .get(root)
        .map(|v| v.iter().map(|e| (e.path.clone(), e)).collect())
        .unwrap_or_default()
}

fn pkg_key(p: &PackageFact) -> String {
    format!("{}:{}", p.name, p.arch)
}

/// Whether `name:arch` is marked in an `apt-mark` list (native packages are listed bare, foreign
/// ones with `:arch`).
fn marked(list: &[String], p: &PackageFact) -> bool {
    list.iter().any(|l| *l == p.name || *l == pkg_key(p))
}

fn compare_packages(a: &Facts, b: &Facts, out: &mut Vec<Drift>) {
    let (ia, ib) = (installed_index(a), installed_index(b));
    let mut auto_diffs: Vec<Drift> = Vec::new();
    for (k, p) in &ia {
        if !ib.contains_key(k) {
            let d = format!("installed only on A ({})", p.version);
            if marked(&a.apt_manual, p) {
                out.push(Drift::error(Area::Packages, k, d));
            } else {
                auto_diffs.push(Drift::info(Area::Packages, k, d));
            }
        }
    }
    for (k, p) in &ib {
        if !ia.contains_key(k) {
            let d = format!("installed only on B ({})", p.version);
            if marked(&b.apt_manual, p) {
                out.push(Drift::error(Area::Packages, k, d));
            } else {
                auto_diffs.push(Drift::info(Area::Packages, k, d));
            }
        }
    }
    if auto_diffs.len() > MAX_AUTO_PACKAGE_DRIFT {
        for d in &mut auto_diffs {
            d.severity = Severity::Error;
            d.detail.push_str(&format!(
                "; more than {MAX_AUTO_PACKAGE_DRIFT} packages differ"
            ));
        }
    }
    out.append(&mut auto_diffs);
    for (k, pa) in &ia {
        if let Some(pb) = ib.get(k)
            && pa.version != pb.version
        {
            out.push(Drift::info(
                Area::Packages,
                k,
                format!("version {} on A, {} on B", pa.version, pb.version),
            ));
        }
    }
    set_diff(
        Area::Packages,
        "marked manual",
        &a.apt_manual,
        &b.apt_manual,
        &|x| x.to_string(),
        out,
    );
}

fn compare_apt_files(a: &Facts, b: &Facts, out: &mut Vec<Drift>) {
    let paths: BTreeSet<&String> = a.apt_files.keys().chain(b.apt_files.keys()).collect();
    for p in paths {
        match (a.apt_files.get(p), b.apt_files.get(p)) {
            (Some(x), Some(y)) if x == y => {}
            (Some(_), Some(_)) => out.push(Drift::error(Area::AptSources, p, "content differs")),
            (Some(_), None) => out.push(Drift::error(Area::AptSources, p, "only on A")),
            (None, Some(_)) => out.push(Drift::error(Area::AptSources, p, "only on B")),
            (None, None) => {}
        }
    }
}

/// `user[:group]` as the plan wrote it, with the build user mapped to the chosen account.
fn expected_owner(owner: &str, build_user: Option<&str>, user: &str) -> (String, Option<String>) {
    let map = |n: &str| {
        if Some(n) == build_user {
            user.to_string()
        } else {
            n.to_string()
        }
    };
    match owner.split_once(':') {
        Some((u, g)) => (map(u), Some(map(g))),
        None => (map(owner), None),
    }
}

fn compare_recipe_files(a: &Facts, b: &Facts, manifest: &Manifest, out: &mut Vec<Drift>) {
    for f in &manifest.files {
        let want_mode = u32::from_str_radix(&f.mode, 8).ok();
        for (label, side) in [("A", a), ("B", b)] {
            let Some(got) = side.etc.iter().find(|e| e.path == f.path) else {
                out.push(Drift::error(
                    Area::RecipeFiles,
                    &f.path,
                    format!("missing on {label} (or outside /etc, which is not collected)"),
                ));
                continue;
            };
            if got.kind != "f" {
                out.push(Drift::error(
                    Area::RecipeFiles,
                    &f.path,
                    format!("on {label} it is not a regular file"),
                ));
                continue;
            }
            if got.sha256.as_deref() != Some(f.sha256.as_str()) {
                out.push(Drift::error(
                    Area::RecipeFiles,
                    &f.path,
                    format!("content on {label} differs from the plan"),
                ));
            }
            if Some(got.mode) != want_mode {
                out.push(Drift::error(
                    Area::RecipeFiles,
                    &f.path,
                    format!(
                        "mode on {label} is {:o}, the plan says {}",
                        got.mode, f.mode
                    ),
                ));
            }
            let (wu, wg) = expected_owner(&f.owner, manifest.user.as_deref(), &side.user);
            let (gu, gg) = got
                .owner
                .split_once(':')
                .unwrap_or((got.owner.as_str(), ""));
            if gu != wu || wg.as_deref().is_some_and(|g| g != gg) {
                out.push(Drift::error(
                    Area::RecipeFiles,
                    &f.path,
                    format!(
                        "owner on {label} is {}, the plan says {}",
                        got.owner, f.owner
                    ),
                ));
            }
        }
    }
}

fn compare_etc(a: &Facts, b: &Facts, out: &mut Vec<Drift>) {
    let (ea, eb) = (etc_index(a), etc_index(b));
    let version_of = |f: &Facts, pkg: &str| -> Option<String> {
        f.packages
            .iter()
            .find(|p| p.status == "ii" && (p.name == pkg || pkg_key(p) == pkg))
            .map(|p| p.version.clone())
    };
    let paths: BTreeSet<&String> = ea.keys().chain(eb.keys()).collect();
    for p in paths {
        let (x, y) = match (ea.get(p), eb.get(p)) {
            (Some(x), Some(y)) => (x, y),
            (Some(_), None) => {
                out.push(Drift::error(Area::Etc, p, "only on A"));
                continue;
            }
            (None, Some(_)) => {
                out.push(Drift::error(Area::Etc, p, "only on B"));
                continue;
            }
            (None, None) => continue,
        };
        if x.kind != y.kind {
            out.push(Drift::error(
                Area::Etc,
                p,
                format!("type {} on A, {} on B", x.kind, y.kind),
            ));
            continue;
        }
        if x.mode != y.mode {
            out.push(Drift::error(
                Area::Etc,
                p,
                format!("mode {:o} on A, {:o} on B", x.mode, y.mode),
            ));
        }
        if x.owner != y.owner {
            out.push(Drift::error(
                Area::Etc,
                p,
                format!("owner {} on A, {} on B", x.owner, y.owner),
            ));
        }
        if x.sha256 != y.sha256 || x.target != y.target {
            // Content of a file of a package whose version differs may differ.
            let owner = a.etc_owner.get(p).or_else(|| b.etc_owner.get(p));
            let versions_differ = owner.is_some_and(|pkg| version_of(a, pkg) != version_of(b, pkg));
            let what = if x.target != y.target {
                format!(
                    "link target {:?} on A, {:?} on B",
                    x.target.as_deref().unwrap_or(""),
                    y.target.as_deref().unwrap_or("")
                )
            } else {
                "content differs".to_string()
            };
            if versions_differ {
                out.push(Drift::info(
                    Area::Etc,
                    p,
                    format!(
                        "{what} (package {} has another version)",
                        owner.map(String::as_str).unwrap_or("?")
                    ),
                ));
            } else {
                out.push(Drift::error(Area::Etc, p, what));
            }
        }
    }
}

fn compare_accounts(a: &Facts, b: &Facts, manifest: &Manifest, out: &mut Vec<Drift>) {
    if a.user != b.user {
        out.push(Drift::error(
            Area::Accounts,
            "user",
            format!(
                "the facts were read for different users: {} and {}",
                a.user, b.user
            ),
        ));
    }
    for (what, x, y) in [
        ("passwd", &a.passwd, &b.passwd),
        ("group", &a.group, &b.group),
        ("subuid", &a.subuid, &b.subuid),
        ("subgid", &a.subgid, &b.subgid),
        ("shadow", &a.shadow, &b.shadow),
    ] {
        set_diff(
            Area::Accounts,
            &format!("{what} line"),
            x,
            y,
            &|l| format!("{what}: {}", l.split(':').next().unwrap_or("")),
            out,
        );
    }
    for (label, side) in [("A", a), ("B", b)] {
        let has =
            |lines: &[String], name: &str| lines.iter().any(|l| l.split(':').next() == Some(name));
        if !has(&side.passwd, &side.user) {
            out.push(Drift::error(
                Area::Accounts,
                &side.user,
                format!("the user is not in passwd on {label}"),
            ));
        }
        // The rename check: the build user must be gone.
        let mut builders = vec![crate::user::DEFAULT_USERNAME];
        builders.extend(manifest.user.as_deref());
        builders.sort();
        builders.dedup();
        for build in builders.into_iter().filter(|b| *b != side.user) {
            for (what, lines) in [("passwd", &side.passwd), ("group", &side.group)] {
                if has(lines, build) {
                    out.push(Drift::error(
                        Area::Accounts,
                        build,
                        format!("the build user is still in {what} on {label}"),
                    ));
                }
            }
        }
        for g in &manifest.user_groups {
            if !side.user_groups.contains(g) {
                out.push(Drift::error(
                    Area::Accounts,
                    g,
                    format!("{} is not in group `{g}` on {label}", side.user),
                ));
            }
        }
    }
}

fn compare_trees(a: &Facts, b: &Facts, out: &mut Vec<Drift>) {
    let roots: BTreeSet<&String> = a.trees.keys().chain(b.trees.keys()).collect();
    for root in roots {
        let (ta, tb) = (tree_index(a, root), tree_index(b, root));
        let paths: BTreeSet<&String> = ta.keys().chain(tb.keys()).collect();
        for p in paths {
            match (ta.get(p), tb.get(p)) {
                (Some(x), Some(y)) => {
                    if x.kind != y.kind {
                        out.push(Drift::error(
                            Area::Trees,
                            p,
                            format!("type {} on A, {} on B", x.kind, y.kind),
                        ));
                    } else if x.mode != y.mode || x.owner != y.owner {
                        out.push(Drift::error(
                            Area::Trees,
                            p,
                            format!(
                                "{:o} {} on A, {:o} {} on B",
                                x.mode, x.owner, y.mode, y.owner
                            ),
                        ));
                    }
                }
                (Some(_), None) => out.push(Drift::error(Area::Trees, p, "only on A")),
                (None, Some(_)) => out.push(Drift::error(Area::Trees, p, "only on B")),
                (None, None) => {}
            }
        }
    }
}

fn unit_in(list: &[String], unit: &str) -> bool {
    list.iter()
        .any(|u| u == unit || *u == format!("{unit}.service"))
}

fn compare_services(a: &Facts, b: &Facts, out: &mut Vec<Drift>) {
    let id = |s: &str| s.to_string();
    set_diff(
        Area::Services,
        "enabled",
        &a.enabled_system,
        &b.enabled_system,
        &id,
        out,
    );
    set_diff(
        Area::Services,
        "enabled for all users",
        &a.enabled_user_global,
        &b.enabled_user_global,
        &id,
        out,
    );
    // Services that D-Bus or a socket starts on demand and that stop again when idle run or not
    // depending on what happened to use them last: reported, not blocking.
    let mut running = Vec::new();
    set_diff(
        Area::Services,
        "running",
        &a.running_services,
        &b.running_services,
        &id,
        &mut running,
    );
    for mut d in running {
        if ON_DEMAND_SERVICES.contains(&d.subject.as_str()) {
            d.severity = Severity::Info;
            d.detail.push_str(" (started on demand)");
        }
        out.push(d);
    }
    for (label, side) in [("A", a), ("B", b)] {
        if side.system_state != "running" {
            out.push(Drift::error(
                Area::Services,
                "is-system-running",
                format!("`{}` on {label}", side.system_state),
            ));
        }
        for u in &side.failed_units {
            out.push(Drift::error(
                Area::Services,
                u,
                format!("failed on {label}"),
            ));
        }
    }
}

fn compare_manifest(a: &Facts, b: &Facts, manifest: &Manifest, out: &mut Vec<Drift>) {
    for (label, side) in [("A", a), ("B", b)] {
        let installed: BTreeSet<&str> = side
            .packages
            .iter()
            .filter(|p| p.status == "ii")
            .map(|p| p.name.as_str())
            .collect();
        for pkg in &manifest.packages {
            let name = pkg.split(':').next().unwrap_or(pkg);
            if !installed.contains(name) {
                out.push(Drift::error(
                    Area::Manifest,
                    pkg,
                    format!("requested by the recipe but not installed on {label}"),
                ));
            }
        }
        for r in &manifest.apt_repos {
            for path in [
                format!("/etc/apt/sources.list.d/{}.sources", r.name),
                format!("/etc/apt/keyrings/{}.gpg", r.name),
            ] {
                if !side.apt_files.contains_key(&path) {
                    out.push(Drift::error(
                        Area::Manifest,
                        &path,
                        format!("apt repository `{}` is not configured on {label}", r.name),
                    ));
                }
            }
        }
        for u in &manifest.system_services {
            if !unit_in(&side.enabled_system, u) {
                out.push(Drift::error(
                    Area::Manifest,
                    u,
                    format!("enabled by the recipe but not enabled on {label}"),
                ));
            }
        }
        for u in &manifest.user_services {
            if !unit_in(&side.enabled_user_global, u) {
                out.push(Drift::error(
                    Area::Manifest,
                    u,
                    format!("enabled for all users by the recipe but not so on {label}"),
                ));
            }
        }
    }
}

/// Compare the server-built desktop `a` with the prebuilt-path desktop `b`, and each against what
/// the plan's `manifest` expects. Empty when they are equivalent; otherwise every difference,
/// [`Severity::Error`] ones blocking ([`has_errors`]). Sorted by area, severity and subject.
pub fn compare(a: &Facts, b: &Facts, manifest: &Manifest) -> Vec<Drift> {
    let mut out = Vec::new();
    compare_packages(a, b, &mut out);
    compare_apt_files(a, b, &mut out);
    compare_recipe_files(a, b, manifest, &mut out);
    compare_etc(a, b, &mut out);
    compare_accounts(a, b, manifest, &mut out);
    compare_trees(a, b, &mut out);
    compare_services(a, b, &mut out);
    compare_manifest(a, b, manifest, &mut out);
    out.sort_by(|x, y| {
        (x.area, std::cmp::Reverse(x.severity), &x.subject, &x.detail).cmp(&(
            y.area,
            std::cmp::Reverse(y.severity),
            &y.subject,
            &y.detail,
        ))
    });
    out
}
