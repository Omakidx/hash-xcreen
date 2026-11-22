//! `install`: upload `install.sh`, run it as a file with `--ssh`, feed it the C2 frames, stream
//! its C3 progress.
//!
//! ```text
//! sh -c 'umask 077 && mktemp -d /tmp/hx-setup.XXXXXX'                 -> /tmp/hx-setup.AbC123 (0700)
//! sh -c 'umask 077 && cat > "$1/install.sh" && wc -c < ...' sh <dir>  <- the script on stdin
//! [sudo -S -k -p '' | sudo -n] sh <dir>/install.sh --ssh --progress json <options>
//!                                      <- [sudo password line] HXI1 frames, then EOF
//! ```
//!
//! Secrets travel only on that last stdin; argv holds the wizard's non-secret options, each
//! single-quoted. With `sudo -S` the password line comes first and is checked in a separate
//! command beforehand (`sudo -S -k true`), so a wrong password stops the run before the C2 frames
//! exist on the wire: sudo's retry would otherwise read them as its next password attempt.
//!
//! **Resume.** The installer converges: stages it finished are skipped. After a lost connection
//! or a retryable failure, open a new [`Connection`] and call [`install`] again with the same
//! options and *newly supplied* [`Secrets`]; nothing is stored. The server-side process is not
//! detached: when the SSH channel closes the installer ends (its HUP/EPIPE handling exits 1 and
//! releases the lock), and a run that is still shutting down answers `LOCKED` (retryable).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;

use russh::ChannelMsg;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::error::{InstallerFailure, Result, SshSetupError};
use crate::frames::Secrets;
use crate::preflight::{SudoMode, detect_sudo};
use crate::progress::{
    InstallEvent, InstallResult, Line, LineSplitter, LogStream, Phase, StageState, parse_line,
};
use crate::ssh::Connection;
use crate::text::{quote, sanitize};

/// Largest `install.sh` accepted.
pub const MAX_SCRIPT: usize = 1024 * 1024;

/// Where the installer script comes from.
#[derive(Debug, Clone)]
pub enum InstallScript {
    /// Bytes bundled with the app.
    Bytes(Vec<u8>),
    /// A file the caller names (for example a downloaded and verified `install.sh`).
    Path(PathBuf),
}

impl InstallScript {
    async fn load(&self) -> Result<Vec<u8>> {
        let bytes = match self {
            Self::Bytes(b) => b.clone(),
            Self::Path(p) => {
                let p = p.clone();
                tokio::task::spawn_blocking(move || std::fs::read(p))
                    .await
                    .map_err(|_| SshSetupError::InvalidInput("cannot read install.sh".into()))?
                    .map_err(|e| {
                        SshSetupError::InvalidInput(format!(
                            "cannot read install.sh ({})",
                            sanitize(&e.kind().to_string(), 60)
                        ))
                    })?
            }
        };
        if bytes.is_empty() || bytes.len() > MAX_SCRIPT || !bytes.starts_with(b"#!") {
            return Err(SshSetupError::InvalidInput(
                "install.sh is empty, larger than 1 MiB or has no #! line".into(),
            ));
        }
        Ok(bytes)
    }
}

/// The wizard's non-secret choices, as `install.sh` / `hx-agent install` options. Everything
/// is validated lightly here (the installer is the authority) and single-quoted into the remote
/// command line. Secrets have no place here: they go in [`Secrets`].
#[derive(Debug, Clone, Default)]
pub struct InstallOptions {
    /// `--channel stable|beta`.
    pub channel: Option<String>,
    /// `--release-dir <abs dir>` (a release already on the server).
    pub release_dir: Option<String>,
    /// `--allow-old-release`.
    pub allow_old_release: bool,
    /// `--distro` (`ubuntu-24.04`, ...).
    pub distro: Option<String>,
    /// `--desktop xfce`.
    pub desktop: Option<String>,
    /// `--user`.
    pub user: Option<String>,
    /// `--hostname`.
    pub hostname: Option<String>,
    /// `--timezone`.
    pub timezone: Option<String>,
    /// `--locale`.
    pub locale: Option<String>,
    /// `--keyboard`.
    pub keyboard: Option<String>,
    /// `--apps basic|developer`.
    pub apps: Option<String>,
    /// `--docker` (the wizard requires the isolation tick before setting this).
    pub docker: bool,
    /// `--backup off|12h|24h`.
    pub backup: Option<String>,
    /// `--backup-keep`.
    pub backup_keep: Option<u32>,
    /// `--cpu`.
    pub cpu: Option<u32>,
    /// `--memory` (MiB as a number, or `8G`).
    pub memory: Option<String>,
    /// `--disk` (GiB).
    pub disk: Option<u32>,
    /// `--storage-device`.
    pub storage_device: Option<String>,
    /// `--port`.
    pub port: Option<u16>,
    /// `--domain`.
    pub domain: Option<String>,
    /// `--allow-private-networks`.
    pub allow_private_networks: bool,
}

impl InstallOptions {
    /// The quoted argument list (without `--ssh`, which the engine always adds).
    pub fn to_args(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let mut val = |flag: &str, v: &Option<String>| -> Result<()> {
            if let Some(v) = v {
                if v.is_empty() || v.starts_with('-') {
                    return Err(SshSetupError::InvalidInput(format!(
                        "{flag} needs a value that does not start with '-'"
                    )));
                }
                out.push(flag.to_owned());
                out.push(quote(v)?);
            }
            Ok(())
        };
        val("--channel", &self.channel)?;
        val("--release-dir", &self.release_dir)?;
        val("--distro", &self.distro)?;
        val("--desktop", &self.desktop)?;
        val("--user", &self.user)?;
        val("--hostname", &self.hostname)?;
        val("--timezone", &self.timezone)?;
        val("--locale", &self.locale)?;
        val("--keyboard", &self.keyboard)?;
        val("--apps", &self.apps)?;
        val("--backup", &self.backup)?;
        val("--memory", &self.memory)?;
        val("--storage-device", &self.storage_device)?;
        val("--domain", &self.domain)?;
        let mut num = |flag: &str, v: Option<String>| {
            if let Some(v) = v {
                out.push(flag.to_owned());
                out.push(v);
            }
        };
        num("--backup-keep", self.backup_keep.map(|v| v.to_string()));
        num("--cpu", self.cpu.map(|v| v.to_string()));
        num("--disk", self.disk.map(|v| v.to_string()));
        num("--port", self.port.map(|v| v.to_string()));
        for (on, flag) in [
            (self.docker, "--docker"),
            (self.allow_private_networks, "--allow-private-networks"),
            (self.allow_old_release, "--allow-old-release"),
        ] {
            if on {
                out.push(flag.to_owned());
            }
        }
        Ok(out)
    }
}

/// One install run.
#[derive(Debug, Clone)]
pub struct InstallRequest {
    /// The script.
    pub script: InstallScript,
    /// The options.
    pub options: InstallOptions,
    /// Bound on the whole installer run (default 3 hours: the desktop build takes about 12
    /// minutes, a slow host much longer).
    pub run_timeout: Duration,
}

impl InstallRequest {
    /// A request with the default timeout.
    pub fn new(script: InstallScript, options: InstallOptions) -> Self {
        Self {
            script,
            options,
            run_timeout: Duration::from_secs(3 * 60 * 60),
        }
    }
}

async fn emit(tx: &mpsc::Sender<InstallEvent>, ev: InstallEvent) {
    // A closed receiver (the window was closed) must not stop the install: keep running.
    let _ = tx.send(ev).await;
}

/// Runs the install over `conn` and streams events to `events`. Returns the typed result, or the
/// typed error (see [`SshSetupError`]); on [`SshSetupError::ConnectionLost`] and retryable
/// installer failures, connect again and call this again with the secrets re-supplied.
pub async fn install(
    conn: &Connection,
    req: &InstallRequest,
    secrets: &Secrets,
    events: &mpsc::Sender<InstallEvent>,
) -> Result<InstallResult> {
    let script = req.script.load().await?;
    let args = req.options.to_args()?;

    emit(events, InstallEvent::Phase(Phase::SudoCheck)).await;
    let mode = detect_sudo(conn).await?;
    match mode {
        SudoMode::Unavailable => return Err(SshSetupError::SudoUnavailable),
        SudoMode::NeedsPassword => verify_sudo_password(conn, secrets).await?,
        SudoMode::Root | SudoMode::Passwordless => {}
    }
    // Build the secret stream before anything is uploaded: a bad value fails early.
    let stdin = secrets.stdin_stream(mode == SudoMode::NeedsPassword)?;

    emit(events, InstallEvent::Phase(Phase::Upload)).await;
    let dir = upload(conn, &script).await?;

    emit(events, InstallEvent::Phase(Phase::Run)).await;
    let r = run(conn, &dir, mode, &args, &stdin, req.run_timeout, events).await;
    drop(stdin);

    emit(events, InstallEvent::Phase(Phase::Cleanup)).await;
    cleanup(conn, &dir).await;
    r
}

async fn verify_sudo_password(conn: &Connection, secrets: &Secrets) -> Result<()> {
    let pw = secrets
        .sudo_password()
        .ok_or(SshSetupError::SudoPasswordRequired)?;
    let mut line = zeroize::Zeroizing::new(Vec::with_capacity(pw.len() + 1));
    line.extend_from_slice(pw.as_bytes());
    line.push(b'\n');
    let out = conn
        .exec(
            "sudo -S -k -p '' true",
            Some(&line),
            Duration::from_secs(30),
        )
        .await?;
    if out.success() {
        return Ok(());
    }
    let e = out.stderr_text().to_ascii_lowercase();
    if e.contains("not in the sudoers")
        || e.contains("may not run sudo")
        || e.contains("is not allowed to run sudo")
    {
        Err(SshSetupError::SudoUnavailable)
    } else {
        Err(SshSetupError::SudoPasswordWrong)
    }
}

fn valid_dir(d: &str) -> bool {
    d.strip_prefix("/tmp/hx-setup.")
        .is_some_and(|r| r.len() == 6 && r.bytes().all(|b| b.is_ascii_alphanumeric()))
}

async fn upload(conn: &Connection, script: &[u8]) -> Result<String> {
    let t = Duration::from_secs(30);
    let out = conn
        .exec(
            "sh -c 'umask 077 && mktemp -d /tmp/hx-setup.XXXXXX'",
            None,
            t,
        )
        .await?;
    let dir = out.stdout_text().trim().to_owned();
    if !out.success() || !valid_dir(&dir) {
        return Err(SshSetupError::Protocol(
            "the server could not make a private temporary directory".into(),
        ));
    }
    let cmd = format!(
        "sh -c 'umask 077 && cat > \"$1/install.sh\" && wc -c < \"$1/install.sh\"' sh {}",
        quote(&dir)?
    );
    let out = conn
        .exec(&cmd, Some(script), Duration::from_secs(120))
        .await?;
    let size: usize = out.stdout_text().trim().parse().unwrap_or(usize::MAX);
    if !out.success() || size != script.len() {
        cleanup(conn, &dir).await;
        return Err(SshSetupError::Protocol(
            "install.sh did not arrive complete on the server".into(),
        ));
    }
    Ok(dir)
}

async fn cleanup(conn: &Connection, dir: &str) {
    if !valid_dir(dir) {
        return;
    }
    if let Ok(q) = quote(dir) {
        let cmd = format!("sh -c 'rm -rf -- \"$1\"' sh {q}");
        let _ = conn.exec(&cmd, None, Duration::from_secs(15)).await;
    }
}

async fn run(
    conn: &Connection,
    dir: &str,
    mode: SudoMode,
    args: &[String],
    stdin: &[u8],
    run_timeout: Duration,
    events: &mpsc::Sender<InstallEvent>,
) -> Result<InstallResult> {
    let prefix = match mode {
        SudoMode::Root => "",
        SudoMode::Passwordless => "sudo -n ",
        // -k: never reuse a cached timestamp, so sudo always reads the password line that
        // `stdin` starts with (a skipped read would shift the C2 magic).
        SudoMode::NeedsPassword => "sudo -S -k -p '' ",
        SudoMode::Unavailable => return Err(SshSetupError::SudoUnavailable),
    };
    let script = quote(&format!("{dir}/install.sh"))?;
    let mut cmd = format!("{prefix}sh {script} --ssh --progress json");
    for a in args {
        cmd.push(' ');
        cmd.push_str(a);
    }

    let mut ch = conn.open_exec(&cmd).await?;
    let lost = |_| SshSetupError::ConnectionLost { last_stage: None };
    ch.data(stdin).await.map_err(lost)?;
    ch.eof().await.map_err(lost)?;

    let deadline = Instant::now() + run_timeout;
    let mut out_split = LineSplitter::default();
    let mut err_split = LineSplitter::default();
    let mut tail: VecDeque<String> = VecDeque::new();
    let mut warnings = Vec::new();
    let mut running: Option<String> = None;
    let mut verdict: Option<Line> = None;
    let mut exit: Option<u32> = None;
    let mut signalled = false;

    macro_rules! on_stdout_line {
        ($l:expr) => {{
            match parse_line(&$l) {
                Line::Event(ev) => {
                    match &ev {
                        InstallEvent::Stage { id, state, .. } => {
                            if *state == StageState::Start {
                                running = Some(id.clone());
                            } else if running.as_deref() == Some(id.as_str()) {
                                running = None;
                            }
                        }
                        InstallEvent::Warn { message, .. } => {
                            if warnings.len() < 100 {
                                warnings.push(message.clone());
                            }
                        }
                        _ => {}
                    }
                    emit(events, ev).await;
                }
                l @ (Line::Ok(_) | Line::Failed(_)) => verdict = Some(l),
                Line::Ignored => {}
            }
        }};
    }
    macro_rules! on_stderr_line {
        ($l:expr) => {{
            let text = sanitize(&$l, 400);
            if tail.len() == 20 {
                tail.pop_front();
            }
            tail.push_back(text.clone());
            emit(
                events,
                InstallEvent::Log {
                    stream: LogStream::Stderr,
                    text,
                },
            )
            .await;
        }};
    }

    loop {
        let msg = tokio::select! {
            m = ch.wait() => m,
            () = tokio::time::sleep_until(deadline) => {
                let _ = ch.close().await;
                return Err(SshSetupError::Timeout("the install (no result before the limit)"));
            }
        };
        let Some(msg) = msg else { break };
        match msg {
            ChannelMsg::Data { data } => {
                let mut lines = Vec::new();
                out_split.push(&data, |l| lines.push(l));
                for l in lines {
                    on_stdout_line!(l);
                }
            }
            ChannelMsg::ExtendedData { data, ext: 1 } => {
                let mut lines = Vec::new();
                err_split.push(&data, |l| lines.push(l));
                for l in lines {
                    on_stderr_line!(l);
                }
            }
            ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
            ChannelMsg::ExitSignal { .. } => signalled = true,
            _ => {}
        }
    }
    if let Some(l) = out_split.finish() {
        on_stdout_line!(l);
    }
    if let Some(l) = err_split.finish() {
        on_stderr_line!(l);
    }

    match verdict {
        Some(Line::Ok(mut r)) => {
            let mut all = warnings;
            for w in std::mem::take(&mut r.warnings) {
                if !all.contains(&w) {
                    all.push(w);
                }
            }
            r.warnings = all;
            Ok(*r)
        }
        Some(Line::Failed(f)) => Err(SshSetupError::InstallerFailed(f)),
        _ => {
            if exit.is_none() && !signalled {
                return Err(SshSetupError::ConnectionLost {
                    last_stage: running,
                });
            }
            let code = exit.unwrap_or(255);
            let last = tail.back().cloned().unwrap_or_default();
            let joined = tail
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join("\n");
            if code != 0
                && (joined.contains("incorrect password")
                    || joined.contains("sorry, try again")
                    || joined.contains("no password was provided"))
            {
                return Err(SshSetupError::SudoPasswordWrong);
            }
            if code == 0 {
                return Err(SshSetupError::Protocol(
                    "the installer ended without a result line".into(),
                ));
            }
            Err(SshSetupError::InstallerFailed(InstallerFailure {
                stage: running.unwrap_or_else(|| "unknown".into()),
                code: "EXIT".into(),
                message: if last.is_empty() {
                    "the installer ended without a result line".into()
                } else {
                    last
                },
                retryable: code == 11,
                exit: code,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_quoted_and_checked() {
        let o = InstallOptions {
            distro: Some("ubuntu-24.04".into()),
            user: Some("o'brien".into()),
            docker: true,
            port: Some(8443),
            cpu: Some(2),
            ..Default::default()
        };
        let a = o.to_args().unwrap();
        assert_eq!(
            a,
            [
                "--distro",
                "'ubuntu-24.04'",
                "--user",
                "'o'\\''brien'",
                "--cpu",
                "2",
                "--port",
                "8443",
                "--docker"
            ]
        );
        let bad = InstallOptions {
            hostname: Some("--token".into()),
            ..Default::default()
        };
        assert!(bad.to_args().is_err());
        let bad = InstallOptions {
            domain: Some("a\nb".into()),
            ..Default::default()
        };
        assert!(bad.to_args().is_err());
    }

    #[test]
    fn temp_dir_names_are_checked() {
        assert!(valid_dir("/tmp/hx-setup.AbC123"));
        assert!(!valid_dir("/tmp/hx-setup.AbC12"));
        assert!(!valid_dir("/tmp/hx-setup.AbC12;"));
        assert!(!valid_dir("/etc/hx-setup.AbC123"));
        assert!(!valid_dir("/tmp/hx-setup.AbC123/../x"));
    }
}
