//! Spike S3 recipe runner: applies a declarative TOML recipe to an Incus
//! container using only the `incus` CLI (`exec`, `file push`, `config set`).
//!
//! Usage:
//!   hx-recipe apply <recipe.toml> <container> [--addon <addon.toml>]... [--skip-install]
//!   hx-recipe post  <recipe.toml> <container> [--addon <addon.toml>]...
//!   hx-recipe show  <recipe.toml> [--addon <addon.toml>]...
//!
//! Merge rules for `include` / addons: tables merge recursively, arrays
//! concatenate in order, scalars from the later file win. `{{var}}` in any
//! string is replaced from `[vars]` (plus `user` from `[user].name`).

use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;
use toml::{Table, Value};

#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
struct Recipe {
    #[serde(default)]
    recipe: Meta,
    #[serde(default)]
    vars: BTreeMap<String, String>,
    #[serde(default)]
    incus_config: BTreeMap<String, String>,
    #[serde(default)]
    apt_repo: Vec<AptRepo>,
    #[serde(default)]
    apt: Apt,
    #[serde(default)]
    user: User,
    #[serde(default)]
    file: Vec<File>,
    #[serde(default)]
    services: Services,
    #[serde(default)]
    pre_step: Vec<Step>,
    #[serde(default)]
    step: Vec<Step>,
    #[serde(default)]
    post_step: Vec<Step>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
struct Meta {
    #[serde(default)]
    name: String,
    #[serde(default)]
    base_image: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct AptRepo {
    name: String,
    key_url: String,
    /// Full fingerprint the downloaded key must contain; the run fails otherwise.
    key_fingerprint: String,
    uri: String,
    suite: String,
    components: String,
    /// Optional apt preferences body written to /etc/apt/preferences.d/<name>.pref.
    pin: Option<String>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
struct Apt {
    #[serde(default)]
    packages: Vec<String>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
struct User {
    #[serde(default)]
    name: String,
    #[serde(default)]
    uid: Option<u32>,
    #[serde(default)]
    shell: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    linger: bool,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct File {
    path: String,
    #[serde(default = "d_mode")]
    mode: String,
    #[serde(default = "d_owner")]
    owner: String,
    content: String,
}
fn d_mode() -> String {
    "0644".into()
}
fn d_owner() -> String {
    "root:root".into()
}

#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
struct Services {
    #[serde(default)]
    system_enable: Vec<String>,
    #[serde(default)]
    user_enable_global: Vec<String>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Step {
    name: String,
    run: String,
    #[serde(default = "d_true")]
    enabled: bool,
    /// Run as the recipe user instead of root.
    #[serde(default)]
    as_user: bool,
}
fn d_true() -> bool {
    true
}

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

fn load(path: &Path) -> Result<Table, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut own: Table = text.parse().map_err(|e| format!("{}: {e}", path.display()))?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut out = Table::new();
    if let Some(Value::Array(incs)) = own.remove("include") {
        for i in incs {
            let p = dir.join(i.as_str().ok_or("include must be strings")?);
            merge(&mut out, load(&p)?);
        }
    }
    merge(&mut out, own);
    Ok(out)
}

fn subst(v: &mut Value, vars: &BTreeMap<String, String>) {
    match v {
        Value::String(s) => {
            for (k, val) in vars {
                *s = s.replace(&format!("{{{{{k}}}}}"), val);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| subst(x, vars)),
        Value::Table(t) => t.iter_mut().for_each(|(_, x)| subst(x, vars)),
        _ => {}
    }
}

fn dedup(v: &mut Vec<String>) {
    let mut seen = std::collections::BTreeSet::new();
    v.retain(|p| seen.insert(p.clone()));
}

fn load_recipe(path: &Path, addons: &[PathBuf]) -> Result<Recipe, String> {
    let mut t = load(path)?;
    for a in addons {
        merge(&mut t, load(a)?);
    }
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    if let Some(Value::Table(vt)) = t.get("vars") {
        for (k, v) in vt {
            vars.insert(k.clone(), v.as_str().unwrap_or_default().to_string());
        }
    }
    if let Some(n) = t.get("user").and_then(|u| u.get("name")).and_then(|n| n.as_str()) {
        vars.entry("user".into()).or_insert(n.to_string());
    }
    let mut v = Value::Table(t);
    subst(&mut v, &vars);
    let mut r: Recipe = v.try_into().map_err(|e| format!("schema: {e}"))?;
    dedup(&mut r.apt.packages);
    dedup(&mut r.user.groups);
    Ok(r)
}

struct Incus {
    name: String,
}

impl Incus {
    fn run(&self, script: &str, stdin: Option<&[u8]>, user: Option<&str>) -> Result<(), String> {
        let mut c = Command::new("incus");
        c.args(["exec", &self.name, "--env", "DEBIAN_FRONTEND=noninteractive"]);
        if let Some(u) = user {
            c.args(["--user", &uid_of(u), "--env", &format!("HOME=/home/{u}")]);
        }
        c.args(["--", "bash", "-euo", "pipefail", "-c", script]);
        self.spawn(c, stdin)
    }

    fn spawn(&self, mut c: Command, stdin: Option<&[u8]>) -> Result<(), String> {
        c.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
        let mut child = c.spawn().map_err(|e| e.to_string())?;
        if let (Some(data), Some(mut si)) = (stdin, child.stdin.take()) {
            si.write_all(data).map_err(|e| e.to_string())?;
        }
        let st = child.wait().map_err(|e| e.to_string())?;
        if st.success() { Ok(()) } else { Err(format!("exit status {st}")) }
    }

    fn push(&self, f: &File) -> Result<(), String> {
        let mut c = Command::new("incus");
        c.args(["file", "push", "-", &format!("{}{}", self.name, f.path), "--create-dirs", "--mode", &f.mode]);
        self.spawn(c, Some(f.content.as_bytes()))?;
        self.run(&format!("chown {} {}", f.owner, sq(&f.path)), None, None)
    }
}

/// `incus exec --user` takes a numeric uid; the recipe user is uid 1000 by convention.
fn uid_of(_name: &str) -> String {
    "1000".into()
}

fn stage<T>(name: &str, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let t = Instant::now();
    eprintln!("== stage {name}: start");
    let r = f();
    eprintln!("STAGE {name} {:.1}s {}", t.elapsed().as_secs_f64(), if r.is_ok() { "ok" } else { "FAILED" });
    r
}

fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Bounded apt network behaviour: a hung mirror connection must fail and retry, not block for minutes.
const APT_OPTS: &str = "-o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 -o Acquire::Retries=3";

/// `apt-get update` with a hard 120 s cap per try: on the spike host an IPv6 transfer occasionally stalled
/// for minutes without tripping apt's own timeouts.
const APT_UPDATE: &str = "for i in 1 2 3 4; do timeout 120 apt-get -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 -o Acquire::Retries=3 update -qq && break; [ $i = 4 ] && exit 1; done";

const WAIT_NET: &str = "for i in $(seq 1 60); do getent hosts deb.debian.org >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1";

fn apply(r: &Recipe, c: &Incus, install: bool) -> Result<(), String> {
    let total = Instant::now();
    if !r.incus_config.is_empty() {
        stage("incus-config", || {
            for (k, v) in &r.incus_config {
                let st = Command::new("incus")
                    .args(["config", "set", &c.name, &format!("{k}={v}")])
                    .status()
                    .map_err(|e| e.to_string())?;
                if !st.success() {
                    return Err(format!("config set {k}"));
                }
            }
            let st = Command::new("incus").args(["restart", &c.name]).status().map_err(|e| e.to_string())?;
            if st.success() { Ok(()) } else { Err("restart".into()) }
        })?;
    }
    stage("wait-network", || c.run(WAIT_NET, None, None))?;
    if install {
        stage("apt-bootstrap", || {
            c.run(&format!("{APT_UPDATE} && apt-get {APT_OPTS} install -y -qq --no-install-recommends ca-certificates curl gnupg"), None, None)
        })?;
        stage("apt-repos", || {
            for repo in &r.apt_repo {
                let key = format!("/etc/apt/keyrings/{}.gpg", repo.name);
                let script = format!(
                    "install -d -m 0755 /etc/apt/keyrings; \
                     curl -fsSL {url} -o /tmp/k.raw; \
                     gpg --show-keys --with-colons /tmp/k.raw | grep -q '^fpr:::::::::{fp}:' || {{ echo 'FINGERPRINT MISMATCH for {n}'; exit 1; }}; \
                     (gpg --dearmor < /tmp/k.raw > {key} 2>/dev/null || cp /tmp/k.raw {key}); chmod 0644 {key}; rm /tmp/k.raw; \
                     printf 'Types: deb\\nURIs: %s\\nSuites: %s\\nComponents: %s\\nSigned-By: %s\\n' {uri} {suite} {comp} {key} > /etc/apt/sources.list.d/{n}.sources",
                    url = sq(&repo.key_url),
                    fp = repo.key_fingerprint,
                    n = repo.name,
                    key = key,
                    uri = sq(&repo.uri),
                    suite = sq(&repo.suite),
                    comp = sq(&repo.components)
                );
                c.run(&script, None, None)?;
                if let Some(pin) = &repo.pin {
                    c.run(&format!("cat > /etc/apt/preferences.d/{}.pref", repo.name), Some(pin.as_bytes()), None)?;
                }
            }
            Ok(())
        })?;
        stage("pre-steps", || run_steps(&r.pre_step, r, c))?;
        stage("apt-install", || {
            if r.apt.packages.is_empty() {
                return Ok(());
            }
            let pk: Vec<String> = r.apt.packages.iter().map(|p| sq(p)).collect();
            c.run(
                &format!("{APT_UPDATE} && apt-get {APT_OPTS} install -y -qq --no-install-recommends {}", pk.join(" ")),
                None,
                None,
            )
        })?;
        stage("user", || ensure_user(r, c))?;
        stage("files", || r.file.iter().try_for_each(|f| c.push(f)))?;
        stage("services", || {
            let mut s = String::from("systemctl daemon-reload; ");
            for u in &r.services.system_enable {
                s += &format!("systemctl enable {}; ", sq(u));
            }
            for u in &r.services.user_enable_global {
                s += &format!("systemctl --global enable {}; ", sq(u));
            }
            if r.user.linger && !r.user.name.is_empty() {
                s += &format!("loginctl enable-linger {}; ", sq(&r.user.name));
            }
            c.run(&s, None, None)
        })?;
        stage("steps", || run_steps(&r.step, r, c))?;
    }
    eprintln!("TOTAL apply {:.1}s", total.elapsed().as_secs_f64());
    Ok(())
}

fn ensure_user(r: &Recipe, c: &Incus) -> Result<(), String> {
    if r.user.name.is_empty() {
        return Ok(());
    }
    let u = &r.user;
    let shell = u.shell.clone().unwrap_or("/bin/bash".into());
    let uid = u.uid.map(|i| format!("--uid {i}")).unwrap_or_default();
    // Ubuntu base images ship an `ubuntu` user at uid 1000; remove it so the uid is free.
    let script = format!(
        "id -u {n} >/dev/null 2>&1 || {{ if id ubuntu >/dev/null 2>&1; then userdel -r ubuntu 2>/dev/null || true; fi; \
         useradd --create-home --shell {sh} {uid} {n}; passwd -l {n} >/dev/null; }}; \
         for g in {groups}; do getent group $g >/dev/null || groupadd $g; usermod -aG $g {n}; done",
        n = sq(&u.name),
        sh = sq(&shell),
        uid = uid,
        groups = u.groups.iter().map(|g| sq(g)).collect::<Vec<_>>().join(" ")
    );
    c.run(&script, None, None)
}

fn run_steps(steps: &[Step], r: &Recipe, c: &Incus) -> Result<(), String> {
    for s in steps {
        if !s.enabled {
            eprintln!("  step '{}' disabled, skipped", s.name);
            continue;
        }
        eprintln!("  step '{}'", s.name);
        let user = s.as_user.then_some(r.user.name.as_str());
        c.run(&s.run, None, user)?;
    }
    Ok(())
}

/// Prebuilt-image post stage: user exists, password set, security updates, extra steps.
/// The Linux password is read from HX_PASSWORD (never from the recipe).
fn post(r: &Recipe, c: &Incus) -> Result<(), String> {
    let total = Instant::now();
    stage("wait-network", || c.run(WAIT_NET, None, None))?;
    stage("user", || ensure_user(r, c))?;
    stage("password", || {
        if let Ok(pw) = std::env::var("HX_PASSWORD") {
            c.run("chpasswd", Some(format!("{}:{}\n", r.user.name, pw).as_bytes()), None)?;
        }
        Ok(())
    })?;
    stage("security-updates", || {
        c.run(&format!("{APT_UPDATE} && apt-get {APT_OPTS} -y -qq -o Dpkg::Options::=--force-confold upgrade"), None, None)
    })?;
    stage("post-steps", || run_steps(&r.post_step, r, c))?;
    eprintln!("TOTAL post {:.1}s", total.elapsed().as_secs_f64());
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut pos, mut addons, mut skip) = (vec![], vec![], false);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addon" => {
                i += 1;
                addons.push(PathBuf::from(&args[i]));
            }
            "--skip-install" => skip = true,
            a => pos.push(a.to_string()),
        }
        i += 1;
    }
    let res = (|| -> Result<(), String> {
        let recipe = || load_recipe(Path::new(pos.get(1).ok_or("recipe path")?), &addons);
        match pos.first().map(String::as_str) {
            Some("show") => {
                println!("{:#?}", recipe()?);
                Ok(())
            }
            Some("apply") => apply(&recipe()?, &Incus { name: pos.get(2).ok_or("container")?.clone() }, !skip),
            Some("post") => post(&recipe()?, &Incus { name: pos.get(2).ok_or("container")?.clone() }),
            _ => Err("usage: hx-recipe <apply|post|show> <recipe.toml> [container] [--addon f]...".into()),
        }
    })();
    if let Err(e) = res {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
