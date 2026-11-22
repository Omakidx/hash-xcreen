//! Turning plan steps into container commands.
//!
//! Everything here is pure: the same step and secrets always give the same actions, so the exact
//! commands are unit-testable without a container.
//!
//! Every apt invocation is bounded (apt's own HTTP timeouts and retries, a hard `timeout` per
//! attempt, several attempts): in S3, `apt-get update` hung for over nine minutes twice.

use std::time::Duration;

use crate::exec::{Action, ExecRequest, FilePush, Secrets};
use crate::plan::{AptRepo, CommandSpec, FileSpec, ServiceSpec, Step, UserSpec};

/// The step needs a secret that was not supplied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a required secret is missing")]
pub struct MissingSecret;

const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Shared shell helpers for apt steps.
const APT_PRELUDE: &str = r#"export DEBIAN_FRONTEND=noninteractive
APT_OPTS="-o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 -o Acquire::Retries=3 -o DPkg::Lock::Timeout=120"
apt_update() {
  for i in 1 2 3 4; do
    timeout 120 apt-get $APT_OPTS update -qq && return 0
    echo "apt-get update: attempt $i failed" >&2
    sleep $((i * 5))
  done
  return 1
}
apt_run() {
  t=$1; label=$2; shift 2
  for i in 1 2 3; do
    timeout "$t" apt-get $APT_OPTS "$@" && return 0
    echo "apt-get $label: attempt $i failed" >&2
    dpkg --configure -a >/dev/null 2>&1 || true
    sleep $((i * 10))
  done
  return 1
}
"#;

/// Single-quote a string for `sh`.
pub(crate) fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn base_env() -> Vec<(String, String)> {
    vec![
        ("DEBIAN_FRONTEND".into(), "noninteractive".into()),
        ("LANG".into(), "C.UTF-8".into()),
        ("PATH".into(), PATH.into()),
    ]
}

fn bash(label: &str, script: String, timeout_secs: u64) -> Action {
    Action::Exec(ExecRequest {
        label: label.to_string(),
        argv: vec![
            "bash".into(),
            "-euo".into(),
            "pipefail".into(),
            "-c".into(),
            script,
        ],
        env: base_env(),
        cwd: None,
        stdin: None,
        timeout: Duration::from_secs(timeout_secs),
    })
}

fn apt_repo(r: &AptRepo) -> Vec<Action> {
    let key = format!("/etc/apt/keyrings/{}.gpg", r.name);
    let sources = format!("/etc/apt/sources.list.d/{}.sources", r.name);
    // The key file must contain exactly one primary key and it must be the pinned one.
    let script = format!(
        r#"install -d -m 0755 /etc/apt/keyrings
tmp=$(mktemp); gh=$(mktemp -d)
trap 'rm -rf "$tmp" "$gh"' EXIT
export GNUPGHOME="$gh"
curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 --connect-timeout 20 --max-time 120 {url} -o "$tmp"
fps=$(gpg --batch --show-keys --with-colons "$tmp" | awk -F: '$1=="pub"{{p=1;next}} p&&$1=="fpr"{{print $10;p=0}}')
if [ "$fps" != {fp} ]; then echo "key fingerprint mismatch for repository {name}: got [$fps]" >&2; exit 1; fi
gpg --batch --quiet --import "$tmp"
gpg --batch --export-options export-minimal --export {fp} > {key}
if [ ! -s {key} ]; then echo "could not export the pinned key for repository {name}" >&2; exit 1; fi
chmod 0644 {key}
printf 'Types: deb\nURIs: %s\nSuites: %s\nComponents: %s\nSigned-By: %s\n' {uri} {suite} {components} {key} > {sources}
"#,
        url = sq(&r.key_url),
        fp = sq(&r.key_fingerprint),
        name = r.name,
        key = sq(&key),
        uri = sq(&r.uri),
        suite = sq(&r.suite),
        components = sq(&r.components),
        sources = sq(&sources),
    );
    let mut v = vec![bash(&format!("apt-repo {}", r.name), script, 300)];
    if let Some(pin) = &r.pin {
        v.push(Action::Push(FilePush {
            path: format!("/etc/apt/preferences.d/{}.pref", r.name),
            content: pin.as_bytes().to_vec(),
            mode: 0o644,
        }));
    }
    v
}

fn ensure_user(u: &UserSpec) -> Action {
    let uid = u.uid.map(|i| format!("--uid {i}")).unwrap_or_default();
    let want = u.uid.map(|i| i.to_string()).unwrap_or_default();
    // Refuse to adopt an existing system account or one with another uid. Ubuntu base images ship
    // an `ubuntu` user at uid 1000; it is removed so the uid is free.
    let script = format!(
        r#"n={n}; want={want}
if id -u "$n" >/dev/null 2>&1; then
  cur=$(id -u "$n")
  if [ "$cur" -lt 1000 ]; then echo "account $n already exists as a system account (uid $cur)" >&2; exit 1; fi
  if [ -n "$want" ] && [ "$cur" != "$want" ]; then echo "account $n already exists with uid $cur, expected $want" >&2; exit 1; fi
else
  gid=$(getent group "$n" | cut -d: -f3 || true)
  if [ -n "$gid" ] && [ "$gid" -lt 1000 ]; then echo "group $n already exists as a system group (gid $gid)" >&2; exit 1; fi
  if [ "$n" != ubuntu ] && id ubuntu >/dev/null 2>&1; then userdel -r ubuntu 2>/dev/null || true; fi
  useradd --create-home --shell {sh} {uid} "$n"
  passwd -l "$n" >/dev/null
fi
for g in {groups}; do getent group "$g" >/dev/null || groupadd "$g"; usermod -aG "$g" "$n"; done
"#,
        n = sq(&u.name),
        want = sq(&want),
        sh = sq(&u.shell),
        groups = u.groups.iter().map(|g| sq(g)).collect::<Vec<_>>().join(" "),
    );
    bash(&format!("ensure-user {}", u.name), script, 120)
}

/// Rename the build user of a prebuilt image to the chosen account. Home directory, primary group
/// and lingering move with it; processes of the old user (its lingering user manager) are ended
/// first, and `usermod` is retried while they exit. No-op unless `from` exists and `to` does not.
fn rename_user(from: &str, to: &str) -> Action {
    let script = format!(
        r#"from={from}; to={to}
if id -u "$from" >/dev/null 2>&1 && ! id -u "$to" >/dev/null 2>&1; then
  loginctl disable-linger "$from" >/dev/null 2>&1 || true
  loginctl terminate-user "$from" >/dev/null 2>&1 || true
  ok=0
  for i in $(seq 1 30); do
    if usermod -l "$to" -d "/home/$to" -m "$from" 2>/dev/null; then ok=1; break; fi
    sleep 1
  done
  if [ "$ok" != 1 ]; then echo "could not rename $from to $to" >&2; exit 1; fi
  if getent group "$from" >/dev/null && ! getent group "$to" >/dev/null; then groupmod -n "$to" "$from"; fi
  # usermod -l leaves the subordinate id ranges under the old name.
  for f in /etc/subuid /etc/subgid; do
    if [ -f "$f" ]; then sed -i "s/^$from:/$to:/" "$f"; fi
  done
  loginctl enable-linger "$to"
fi
"#,
        from = sq(from),
        to = sq(to),
    );
    bash(&format!("rename-user {from} {to}"), script, 120)
}

fn write_file(f: &FileSpec) -> Vec<Action> {
    let dir = f
        .path
        .rsplit_once('/')
        .map(|(d, _)| if d.is_empty() { "/" } else { d })
        .unwrap_or("/");
    let mut v = vec![bash(
        &format!("mkdir {dir}"),
        format!("install -d -m 0755 {}", sq(dir)),
        60,
    )];
    let mode = u32::from_str_radix(&f.mode, 8).unwrap_or(0o644);
    v.push(Action::Push(FilePush {
        path: f.path.clone(),
        content: f.content.as_bytes().to_vec(),
        mode,
    }));
    if f.owner != "root:root" && f.owner != "root" {
        v.push(bash(
            &format!("chown {}", f.path),
            format!("chown {} {}", sq(&f.owner), sq(&f.path)),
            60,
        ));
    }
    v
}

fn enable_services(s: &ServiceSpec, linger_user: &Option<String>) -> Action {
    let mut script = String::from("systemctl daemon-reload\n");
    for u in &s.system_enable {
        script += &format!("systemctl enable {}\n", sq(u));
    }
    for u in &s.user_enable_global {
        script += &format!("systemctl --global enable {}\n", sq(u));
    }
    if let Some(u) = linger_user {
        script += &format!("loginctl enable-linger {}\n", sq(u));
    }
    bash("enable-services", script, 300)
}

fn command(c: &CommandSpec) -> Action {
    let (argv, cwd) = match &c.as_user {
        None => (
            vec![
                "bash".to_string(),
                "-euo".into(),
                "pipefail".into(),
                "-c".into(),
                c.run.clone(),
            ],
            None,
        ),
        Some(user) => (
            vec![
                "runuser".to_string(),
                "-u".into(),
                user.clone(),
                "--".into(),
                "env".into(),
                format!("HOME=/home/{user}"),
                "bash".into(),
                "-euo".into(),
                "pipefail".into(),
                "-c".into(),
                c.run.clone(),
            ],
            Some(format!("/home/{user}")),
        ),
    };
    Action::Exec(ExecRequest {
        label: format!("command {}", c.name),
        argv,
        env: base_env(),
        cwd,
        stdin: None,
        timeout: Duration::from_secs(c.timeout_secs),
    })
}

/// Lower one plan step into container actions.
pub fn lower(step: &Step, secrets: &Secrets) -> Result<Vec<Action>, MissingSecret> {
    Ok(match step {
        Step::WaitNetwork => vec![bash(
            "wait-network",
            "for i in $(seq 1 60); do for h in deb.debian.org archive.ubuntu.com; do getent hosts \"$h\" >/dev/null 2>&1 && exit 0; done; sleep 1; done; echo 'no DNS resolution after 60 s' >&2; exit 1"
                .into(),
            90,
        )],
        Step::AptBootstrap => vec![bash(
            "apt-bootstrap",
            format!("{APT_PRELUDE}apt_update\napt_run 1800 install install -y -qq --no-install-recommends ca-certificates curl gnupg\n"),
            2400,
        )],
        Step::AptRepo(r) => apt_repo(r),
        Step::Command(c) => vec![command(c)],
        Step::AptInstall { packages } => {
            let pk = packages.iter().map(|p| sq(p)).collect::<Vec<_>>().join(" ");
            vec![bash(
                "apt-install",
                format!("{APT_PRELUDE}apt_update\napt_run 3600 install install -y -qq --no-install-recommends {pk}\n"),
                4500,
            )]
        }
        Step::EnsureUser(u) => vec![ensure_user(u)],
        Step::WriteFile(f) => write_file(f),
        Step::EnableServices { services, linger_user } => vec![enable_services(services, linger_user)],
        Step::RenameUser { from, to } => vec![rename_user(from, to)],
        Step::SetPassword { user } => {
            let pw = secrets.user_password().ok_or(MissingSecret)?;
            // `user:password\n` on stdin of chpasswd. Nothing secret in argv or env.
            let mut line = Vec::with_capacity(user.len() + 2 + pw.expose().len());
            line.extend_from_slice(user.as_bytes());
            line.push(b':');
            line.extend_from_slice(pw.expose());
            line.push(b'\n');
            vec![Action::Exec(ExecRequest {
                label: "set-password".into(),
                argv: vec!["chpasswd".into()],
                env: base_env(),
                cwd: None,
                stdin: Some(crate::exec::Secret::new(line)),
                timeout: Duration::from_secs(60),
            })]
        }
        Step::SecurityUpdates => vec![bash(
            "security-updates",
            format!("{APT_PRELUDE}apt_update\napt_run 3600 upgrade -y -qq -o Dpkg::Options::=--force-confold upgrade\n"),
            4500,
        )],
    })
}
