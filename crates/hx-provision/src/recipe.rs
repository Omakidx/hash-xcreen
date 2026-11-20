//! Recipe loading: sources, `include` resolution, merging, variables, validation.
//!
//! Resolution is a pure function of the recipe files: no clock, no network, no environment.
//! The same inputs always give the same [`Plan`].
//!
//! Merge rules (identical to the S3 spike): tables merge recursively, arrays concatenate in
//! order, and for scalars the later value wins.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use toml::{Table, Value};

use crate::error::RecipeError;
use crate::plan::{AptRepo, CommandSpec, FileSpec, ImageRef, Plan, ServiceSpec, Step, UserSpec};

/// Deepest allowed `include` nesting.
pub const MAX_INCLUDE_DEPTH: usize = 8;

/// Default wall-clock limit for a recipe command.
pub const DEFAULT_STEP_TIMEOUT_SECS: u64 = 1800;
const MAX_STEP_TIMEOUT_SECS: u64 = 7200;

/// Provides recipe file contents by path relative to the recipes root, using `/` separators.
pub trait RecipeSource {
    /// Read one file. `path` is already normalised: relative, no `..`, no leading `/`.
    fn read(&self, path: &str) -> Result<String, RecipeError>;
}

/// Recipes in a directory on disk. Paths that resolve (through symlinks) outside the root are refused.
#[derive(Debug, Clone)]
pub struct DirSource {
    root: PathBuf,
}

impl DirSource {
    /// Use `root` as the recipes root directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl RecipeSource for DirSource {
    fn read(&self, path: &str) -> Result<String, RecipeError> {
        let read_err = |m: String| RecipeError::Read {
            path: path.to_string(),
            message: m,
        };
        let full = self.root.join(Path::new(path));
        let canon = full.canonicalize().map_err(|e| read_err(e.to_string()))?;
        let root = self
            .root
            .canonicalize()
            .map_err(|e| read_err(e.to_string()))?;
        if !canon.starts_with(&root) {
            return Err(read_err("resolves outside the recipes root".into()));
        }
        std::fs::read_to_string(&canon).map_err(|e| read_err(e.to_string()))
    }
}

/// Recipes held in memory (tests, and the set embedded in the crate).
#[derive(Debug, Clone, Default)]
pub struct MemSource {
    files: BTreeMap<String, String>,
}

impl MemSource {
    /// Empty source.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a file.
    pub fn with(mut self, path: &str, content: &str) -> Self {
        self.files.insert(path.to_string(), content.to_string());
        self
    }

    /// Paths present, sorted.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }
}

impl RecipeSource for MemSource {
    fn read(&self, path: &str) -> Result<String, RecipeError> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| RecipeError::Read {
                path: path.to_string(),
                message: "no such file".into(),
            })
    }
}

// ---------------------------------------------------------------------------------------------
// Raw schema (what a recipe file may contain). Unknown keys are rejected at every level.
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields, default)]
struct RawRecipe {
    recipe: RawMeta,
    vars: BTreeMap<String, String>,
    incus_config: BTreeMap<String, String>,
    apt_repo: Vec<RawAptRepo>,
    apt: RawApt,
    user: RawUser,
    file: Vec<RawFile>,
    services: RawServices,
    pre_step: Vec<RawStep>,
    step: Vec<RawStep>,
    post_step: Vec<RawStep>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields, default)]
struct RawMeta {
    name: String,
    base_image: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct RawAptRepo {
    name: String,
    key_url: String,
    key_fingerprint: String,
    uri: String,
    suite: String,
    components: String,
    pin: Option<String>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields, default)]
struct RawApt {
    packages: Vec<String>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields, default)]
struct RawUser {
    name: String,
    uid: Option<u32>,
    shell: Option<String>,
    groups: Vec<String>,
    linger: bool,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct RawFile {
    path: String,
    content: String,
    #[serde(default = "default_mode")]
    mode: String,
    #[serde(default = "default_owner")]
    owner: String,
}

fn default_mode() -> String {
    "0644".into()
}

fn default_owner() -> String {
    "root:root".into()
}

#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields, default)]
struct RawServices {
    system_enable: Vec<String>,
    user_enable_global: Vec<String>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct RawStep {
    name: String,
    run: String,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    as_user: bool,
    #[serde(default)]
    optional: bool,
    timeout_secs: Option<u64>,
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------------------------
// Loading and merging
// ---------------------------------------------------------------------------------------------

fn merge(a: &mut Table, b: Table) {
    for (k, v) in b {
        match (a.get_mut(&k), v) {
            (Some(Value::Table(x)), Value::Table(y)) => merge(x, y),
            (Some(Value::Array(x)), Value::Array(y)) => x.extend(y),
            (_, v) => {
                a.insert(k, v);
            }
        }
    }
}

/// Join `include` onto the directory of `from`, lexically. Refuses absolute paths and paths that
/// leave the root.
fn join_include(from: &str, include: &str) -> Result<String, String> {
    if include.is_empty() {
        return Err("is empty".into());
    }
    if include.starts_with('/') || include.contains('\\') || include.contains('\0') {
        return Err("must be a relative path with `/` separators".into());
    }
    let mut parts: Vec<&str> = from.split('/').collect();
    parts.pop(); // file name
    for seg in include.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err("leaves the recipes root".into());
                }
            }
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        return Err("does not name a file".into());
    }
    Ok(parts.join("/"))
}

fn load_file(
    src: &dyn RecipeSource,
    path: &str,
    stack: &mut Vec<String>,
) -> Result<Table, RecipeError> {
    if stack.iter().any(|p| p == path) {
        let mut chain = stack.clone();
        chain.push(path.to_string());
        return Err(RecipeError::IncludeCycle { chain });
    }
    if stack.len() >= MAX_INCLUDE_DEPTH {
        return Err(RecipeError::IncludeTooDeep {
            path: path.to_string(),
            max: MAX_INCLUDE_DEPTH,
        });
    }
    let text = src.read(path)?;
    let mut own: Table = text
        .parse()
        .map_err(|e: toml::de::Error| RecipeError::Parse {
            path: path.to_string(),
            message: e.to_string(),
        })?;
    let includes = match own.remove("include") {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .into_iter()
            .map(|v| match v {
                Value::String(s) => Ok(s),
                other => Err(RecipeError::BadInclude {
                    path: path.to_string(),
                    include: other.to_string(),
                    reason: "is not a string".into(),
                }),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err(RecipeError::Parse {
                path: path.to_string(),
                message: "`include` must be an array of strings".into(),
            });
        }
    };
    // Per-file schema check, so unknown keys are reported against the file that has them.
    own.clone()
        .try_into::<RawRecipe>()
        .map_err(|e| RecipeError::Parse {
            path: path.to_string(),
            message: e.to_string(),
        })?;

    stack.push(path.to_string());
    let mut out = Table::new();
    for inc in includes {
        let target = join_include(path, &inc).map_err(|reason| RecipeError::BadInclude {
            path: path.to_string(),
            include: inc.clone(),
            reason,
        })?;
        merge(&mut out, load_file(src, &target, stack)?);
    }
    stack.pop();
    merge(&mut out, own);
    Ok(out)
}

/// An add-on may add content, not redefine the recipe.
fn check_addon(path: &str, t: &Table) -> Result<(), RecipeError> {
    let bad = |m: &str| RecipeError::Parse {
        path: path.to_string(),
        message: m.to_string(),
    };
    if t.contains_key("recipe") {
        return Err(bad("an add-on may not define [recipe]"));
    }
    if t.contains_key("vars") {
        return Err(bad("an add-on may not define [vars]"));
    }
    if let Some(Value::Table(u)) = t.get("user")
        && u.keys().any(|k| k != "groups")
    {
        return Err(bad("an add-on may only set [user].groups"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------------------------

fn valid_var_name(n: &str) -> bool {
    let mut c = n.chars();
    matches!(c.next(), Some('a'..='z')) && c.all(|x| matches!(x, 'a'..='z' | '0'..='9' | '_'))
}

fn expand_str(s: &str, vars: &BTreeMap<String, String>, key: &str) -> Result<String, RecipeError> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find("{{") {
        let (before, after) = rest.split_at(pos);
        let after = &after[2..];
        if let Some(stripped) = before.strip_suffix('\\') {
            // `\{{` is a literal `{{`.
            out.push_str(stripped);
            out.push_str("{{");
            rest = after;
            continue;
        }
        out.push_str(before);
        let end = after.find("}}").ok_or_else(|| RecipeError::BadTemplate {
            key: key.to_string(),
            reason: "`{{` without a closing `}}`".into(),
        })?;
        let name = after[..end].trim();
        if !valid_var_name(name) {
            return Err(RecipeError::BadTemplate {
                key: key.to_string(),
                reason: format!(
                    "`{name}` is not a valid variable name (lower-case letters, digits, `_`)"
                ),
            });
        }
        let value = vars.get(name).ok_or_else(|| RecipeError::MissingVar {
            name: name.to_string(),
            key: key.to_string(),
        })?;
        out.push_str(value);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

fn expand_value(
    v: &mut Value,
    vars: &BTreeMap<String, String>,
    key: &str,
) -> Result<(), RecipeError> {
    match v {
        Value::String(s) => *s = expand_str(s, vars, key)?,
        Value::Array(a) => {
            for (i, x) in a.iter_mut().enumerate() {
                expand_value(x, vars, &format!("{key}[{i}]"))?;
            }
        }
        Value::Table(t) => {
            for (k, x) in t.iter_mut() {
                let sub = if key.is_empty() {
                    k.clone()
                } else {
                    format!("{key}.{k}")
                };
                expand_value(x, vars, &sub)?;
            }
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------------------------

fn name_ok(s: &str, extra: &[char], max: usize) -> bool {
    let mut chars = s.chars();
    let first_ok = matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit());
    first_ok
        && s.len() <= max
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || extra.contains(&c))
}

fn ident_ok(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_')
        && s.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn package_ok(s: &str) -> bool {
    let (name, arch) = match s.split_once(':') {
        Some((n, a)) => (n, Some(a)),
        None => (s, None),
    };
    name_ok(name, &['+', '.', '-'], 128)
        && arch.is_none_or(|a| !a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric()))
}

fn unit_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | ':' | '-'))
        && s.contains('.')
}

fn abs_path_ok(s: &str) -> bool {
    s.starts_with('/')
        && s.len() > 1
        && s.len() < 4096
        && !s.ends_with('/')
        && !s.chars().any(|c| c == '\0' || c == '\n')
        && !s.split('/').any(|seg| seg == "..")
}

fn mode_ok(s: &str) -> bool {
    (3..=4).contains(&s.len()) && s.chars().all(|c| ('0'..='7').contains(&c))
}

fn owner_ok(s: &str) -> bool {
    match s.split_once(':') {
        Some((u, g)) => ident_ok(u) && ident_ok(g),
        None => ident_ok(s),
    }
}

fn no_space_ok(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn parse_image(s: &str) -> Result<ImageRef, RecipeError> {
    let f = "recipe.base_image";
    let alias_ok = |a: &str| {
        !a.is_empty()
            && a.len() <= 128
            && a.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '/' | '_' | '-'))
    };
    match s.split_once(':') {
        Some(("images", a)) if alias_ok(a) => Ok(ImageRef::Remote {
            alias: a.to_string(),
        }),
        Some(("local", a)) if alias_ok(a) => Ok(ImageRef::Local {
            alias: a.to_string(),
        }),
        _ => Err(RecipeError::invalid(
            f,
            format!("`{s}` must be `images:<alias>` or `local:<alias>`"),
        )),
    }
}

fn check_incus_config(cfg: &BTreeMap<String, String>) -> Result<(), RecipeError> {
    crate::plan::check_instance_config(cfg)
        .map_err(|(k, why)| RecipeError::invalid(format!("incus_config.{k}"), why))
}

fn convert_steps(
    list: &str,
    raw: Vec<RawStep>,
    user: &str,
) -> Result<Vec<CommandSpec>, RecipeError> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for (i, s) in raw.into_iter().enumerate() {
        let f = |k: &str| format!("{list}[{i}].{k}");
        let ok = !s.name.is_empty()
            && s.name.len() <= 64
            && s.name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' '));
        if !ok {
            return Err(RecipeError::invalid(
                f("name"),
                "1-64 characters from letters, digits, `.`, `_`, `-` and space",
            ));
        }
        if !seen.insert(s.name.clone()) {
            return Err(RecipeError::invalid(
                f("name"),
                format!("duplicate step name `{}`", s.name),
            ));
        }
        if s.run.trim().is_empty() {
            return Err(RecipeError::invalid(f("run"), "is empty"));
        }
        if s.run.contains('\0') {
            return Err(RecipeError::invalid(f("run"), "contains a NUL byte"));
        }
        let timeout = s.timeout_secs.unwrap_or(DEFAULT_STEP_TIMEOUT_SECS);
        if timeout == 0 || timeout > MAX_STEP_TIMEOUT_SECS {
            return Err(RecipeError::invalid(
                f("timeout_secs"),
                format!("must be 1..={MAX_STEP_TIMEOUT_SECS}"),
            ));
        }
        if s.as_user && user.is_empty() {
            return Err(RecipeError::invalid(
                f("as_user"),
                "needs a [user] with a name",
            ));
        }
        if !s.enabled {
            continue;
        }
        out.push(CommandSpec {
            name: s.name,
            run: s.run,
            as_user: s.as_user.then(|| user.to_string()),
            optional: s.optional,
            timeout_secs: timeout,
        });
    }
    Ok(out)
}

fn dedup(v: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    v.into_iter().filter(|x| seen.insert(x.clone())).collect()
}

/// Expand variables in a merged table and turn it into a validated plan.
fn table_to_plan(mut t: Table) -> Result<Plan, RecipeError> {
    // Variables: [vars] plus `user` from [user].name. [vars] values are not themselves expanded.
    let raw_vars: BTreeMap<String, String> = match t.get("vars") {
        Some(v) => v
            .clone()
            .try_into()
            .map_err(|e: toml::de::Error| RecipeError::invalid("vars", e.to_string()))?,
        None => BTreeMap::new(),
    };
    for k in raw_vars.keys() {
        if !valid_var_name(k) {
            return Err(RecipeError::invalid(
                format!("vars.{k}"),
                "variable names are lower-case letters, digits and `_`",
            ));
        }
    }
    let mut vars = raw_vars;
    if let Some(Value::String(n)) = t.get("user").and_then(|u| u.get("name")) {
        vars.entry("user".to_string()).or_insert_with(|| n.clone());
    }
    let vars_table = t.remove("vars");
    let mut tv = Value::Table(t);
    expand_value(&mut tv, &vars, "")?;
    let Value::Table(mut t) = tv else {
        return Err(RecipeError::invalid(
            "<root>",
            "internal: root is not a table",
        ));
    };
    if let Some(v) = vars_table {
        t.insert("vars".into(), v);
    }
    let raw: RawRecipe =
        Value::Table(t)
            .try_into()
            .map_err(|e: toml::de::Error| RecipeError::Parse {
                path: "<merged recipe>".into(),
                message: e.to_string(),
            })?;

    // [recipe]
    if !name_ok(&raw.recipe.name, &['.', '_', '-'], 64) {
        return Err(RecipeError::invalid(
            "recipe.name",
            "required; lower-case letters, digits, `.`, `_`, `-`",
        ));
    }
    if raw.recipe.base_image.is_empty() {
        return Err(RecipeError::invalid("recipe.base_image", "required"));
    }
    let base_image = parse_image(&raw.recipe.base_image)?;
    check_incus_config(&raw.incus_config)?;

    // [user]
    let u = &raw.user;
    let user = if u.name.is_empty() {
        if u.uid.is_some() || u.shell.is_some() || !u.groups.is_empty() || u.linger {
            return Err(RecipeError::invalid(
                "user.name",
                "required when other [user] keys are set",
            ));
        }
        None
    } else {
        if !ident_ok(&u.name) {
            return Err(RecipeError::invalid(
                "user.name",
                "lower-case letters, digits, `_`, `-`; at most 32 characters",
            ));
        }
        if let Some(uid) = u.uid
            && !(1000..60000).contains(&uid)
        {
            return Err(RecipeError::invalid("user.uid", "must be in 1000..60000"));
        }
        let shell = u.shell.clone().unwrap_or_else(|| "/bin/bash".into());
        if !abs_path_ok(&shell) {
            return Err(RecipeError::invalid(
                "user.shell",
                "must be an absolute path",
            ));
        }
        for (i, g) in u.groups.iter().enumerate() {
            if !ident_ok(g) {
                return Err(RecipeError::invalid(
                    format!("user.groups[{i}]"),
                    format!("`{g}` is not a valid group name"),
                ));
            }
        }
        Some(UserSpec {
            name: u.name.clone(),
            uid: u.uid,
            shell,
            groups: dedup(u.groups.clone()),
            linger: u.linger,
        })
    };
    let user_name = user.as_ref().map(|u| u.name.clone()).unwrap_or_default();

    // [[apt_repo]]
    let mut repos = Vec::new();
    let mut repo_names = BTreeSet::new();
    for (i, r) in raw.apt_repo.into_iter().enumerate() {
        let f = |k: &str| format!("apt_repo[{i}].{k}");
        if !name_ok(&r.name, &['.', '_', '-'], 48) {
            return Err(RecipeError::invalid(
                f("name"),
                "lower-case letters, digits, `.`, `_`, `-`",
            ));
        }
        if !repo_names.insert(r.name.clone()) {
            return Err(RecipeError::invalid(
                f("name"),
                format!("duplicate repository `{}`", r.name),
            ));
        }
        if !r.key_url.starts_with("https://") || !no_space_ok(&r.key_url) {
            return Err(RecipeError::invalid(
                f("key_url"),
                "must be an https:// URL without spaces",
            ));
        }
        let fp = r.key_fingerprint.to_ascii_uppercase();
        if fp.len() != 40 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(RecipeError::invalid(
                f("key_fingerprint"),
                "must be the full 40 hex digit fingerprint, without spaces",
            ));
        }
        if !(r.uri.starts_with("https://") || r.uri.starts_with("http://")) || !no_space_ok(&r.uri)
        {
            return Err(RecipeError::invalid(
                f("uri"),
                "must be an http(s):// URL without spaces",
            ));
        }
        if !no_space_ok(&r.suite) {
            return Err(RecipeError::invalid(f("suite"), "must be a single word"));
        }
        if r.components.split_whitespace().next().is_none()
            || r.components.chars().any(|c| c.is_control())
        {
            return Err(RecipeError::invalid(
                f("components"),
                "must name at least one component",
            ));
        }
        if r.pin
            .as_deref()
            .is_some_and(|p| p.trim().is_empty() || p.contains('\0'))
        {
            return Err(RecipeError::invalid(f("pin"), "must not be empty"));
        }
        repos.push(AptRepo {
            name: r.name,
            key_url: r.key_url,
            key_fingerprint: fp,
            uri: r.uri,
            suite: r.suite,
            components: r
                .components
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
            pin: r.pin,
        });
    }

    // [apt]
    let packages = dedup(raw.apt.packages);
    for (i, p) in packages.iter().enumerate() {
        if !package_ok(p) {
            return Err(RecipeError::invalid(
                format!("apt.packages[{i}]"),
                format!("`{p}` is not a valid Debian package name"),
            ));
        }
    }

    // [[file]]
    let mut files = Vec::new();
    let mut paths = BTreeSet::new();
    for (i, fl) in raw.file.into_iter().enumerate() {
        let f = |k: &str| format!("file[{i}].{k}");
        if !abs_path_ok(&fl.path) {
            return Err(RecipeError::invalid(
                f("path"),
                "must be an absolute path without `..`",
            ));
        }
        if !paths.insert(fl.path.clone()) {
            return Err(RecipeError::invalid(
                f("path"),
                format!("`{}` is defined more than once", fl.path),
            ));
        }
        if !mode_ok(&fl.mode) {
            return Err(RecipeError::invalid(
                f("mode"),
                "must be 3 or 4 octal digits",
            ));
        }
        if !owner_ok(&fl.owner) {
            return Err(RecipeError::invalid(
                f("owner"),
                "must be `user` or `user:group`",
            ));
        }
        if fl.content.contains('\0') {
            return Err(RecipeError::invalid(f("content"), "contains a NUL byte"));
        }
        files.push(FileSpec {
            path: fl.path,
            mode: fl.mode,
            owner: fl.owner,
            content: fl.content,
        });
    }

    // [services]
    for (list, units) in [
        ("system_enable", &raw.services.system_enable),
        ("user_enable_global", &raw.services.user_enable_global),
    ] {
        for (i, s) in units.iter().enumerate() {
            if !unit_ok(s) {
                return Err(RecipeError::invalid(
                    format!("services.{list}[{i}]"),
                    format!("`{s}` is not a unit name"),
                ));
            }
        }
    }
    let services = ServiceSpec {
        system_enable: dedup(raw.services.system_enable),
        user_enable_global: dedup(raw.services.user_enable_global),
    };

    let pre = convert_steps("pre_step", raw.pre_step, &user_name)?;
    let steps = convert_steps("step", raw.step, &user_name)?;
    let post_cmds = convert_steps("post_step", raw.post_step, &user_name)?;

    // Assemble the build stage.
    let mut build = vec![Step::WaitNetwork, Step::AptBootstrap];
    build.extend(repos.into_iter().map(Step::AptRepo));
    build.extend(pre.into_iter().map(Step::Command));
    if !packages.is_empty() {
        build.push(Step::AptInstall { packages });
    }
    if let Some(u) = &user {
        build.push(Step::EnsureUser(u.clone()));
    }
    build.extend(files.into_iter().map(Step::WriteFile));
    let linger_user = user.as_ref().filter(|u| u.linger).map(|u| u.name.clone());
    if !services.system_enable.is_empty()
        || !services.user_enable_global.is_empty()
        || linger_user.is_some()
    {
        build.push(Step::EnableServices {
            services,
            linger_user,
        });
    }
    build.extend(steps.into_iter().map(Step::Command));

    // Assemble the post stage.
    let mut post = vec![Step::WaitNetwork];
    if let Some(u) = &user {
        post.push(Step::EnsureUser(u.clone()));
        post.push(Step::SetPassword {
            user: u.name.clone(),
        });
    }
    post.push(Step::SecurityUpdates);
    post.extend(post_cmds.into_iter().map(Step::Command));

    let mut plan_vars = vars;
    plan_vars.retain(|k, _| k != "user" || user.is_some());
    Ok(Plan {
        name: raw.recipe.name,
        base_image,
        vars: plan_vars,
        incus_config: raw.incus_config,
        build,
        post,
    })
}

// ---------------------------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------------------------

/// Resolve `recipe_path` with the given add-on files (merged in order) into a [`Plan`].
///
/// Paths are relative to the root of `src`.
pub fn resolve(
    src: &dyn RecipeSource,
    recipe_path: &str,
    addon_paths: &[&str],
) -> Result<Plan, RecipeError> {
    let mut t = load_file(src, recipe_path, &mut Vec::new())?;
    for a in addon_paths {
        let at = load_file(src, a, &mut Vec::new())?;
        check_addon(a, &at)?;
        merge(&mut t, at);
    }
    table_to_plan(t)
}

/// The steps of one add-on only, to apply it to a desktop that already exists (for example one
/// imported from a prebuilt image that has no Docker). Variables, the recipe name and the user
/// come from the base recipe. The plan has no post stage.
pub fn resolve_addon_only(
    src: &dyn RecipeSource,
    recipe_path: &str,
    addon_path: &str,
) -> Result<Plan, RecipeError> {
    let base = load_file(src, recipe_path, &mut Vec::new())?;
    let mut addon = load_file(src, addon_path, &mut Vec::new())?;
    check_addon(addon_path, &addon)?;
    // Borrow the facts an add-on may refer to from the base recipe.
    if let Some(v) = base.get("vars") {
        addon.insert("vars".into(), v.clone());
    }
    if let Some(v) = base.get("recipe") {
        addon.insert("recipe".into(), v.clone());
    }
    if let Some(Value::Table(bu)) = base.get("user") {
        let mut u = match addon.remove("user") {
            Some(Value::Table(t)) => t,
            _ => Table::new(),
        };
        for k in ["name", "uid", "shell"] {
            if let Some(v) = bu.get(k) {
                u.insert(k.into(), v.clone());
            }
        }
        addon.insert("user".into(), Value::Table(u));
    }
    let mut plan = table_to_plan(addon)?;
    plan.post.clear();
    Ok(plan)
}
