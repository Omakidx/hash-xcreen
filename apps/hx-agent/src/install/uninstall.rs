//! The CLI side of `hx-agent uninstall` (design D6, steps U0 to U8).
//!
//! privd's `Uninstall` removes only what privd created (the desktop and Incus objects in destroy
//! mode, the firewall table, the link devices). Everything else is done here, because privd's own
//! sandbox cannot do it (`ProtectSystem=strict`, no `CAP_DAC_OVERRIDE`, it cannot write unit
//! directories or run `userdel`, and it would stop its own unit):
//!
//! | Step | What |
//! |---|---|
//! | U0 | lock, the confirmation (done by the command), the resume file |
//! | U1 | `systemctl disable --now` the gateway units, so no gateway traffic arrives |
//! | U2 | privd `Uninstall` (an old privd answers `UNIMPLEMENTED`: the manual steps, exit 6) |
//! | U3 | stop and disable privd's units, the fetcher, the updates mount (destroy: the firewall units too) |
//! | U4 | remove the port rule (ufw, nft by comment) and its unit |
//! | U5 | remove files and directories; gatewayd's state is emptied by a child running as that user |
//! | U6 | `userdel hx-gatewayd` |
//! | U7 | `daemon-reload`, `reset-failed` |
//! | U8 | drop the resume file |
//!
//! The resume file is `/var/lib/hx-uninstall.json`, outside `/var/lib/hx`, which U5 removes. Every
//! step is idempotent and recorded when done, so a run that stops resumes after the last one.
//! Incus and the Zabbly repository stay installed; the result says how to remove the repository.
//!
//! **Rule 15** (`docs/ipc.md` 7): root never walks a directory the gateway can write. gatewayd's
//! state directory is emptied by a child process that runs as the `hx-gatewayd` uid and gid
//! (`hx-agent __empty-dir`), with `unlinkat` relative to descriptors opened `O_NOFOLLOW`; root then
//! removes the empty directory relative to a `/var/lib` descriptor.

use std::io;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};

use super::daemons::{Daemons, OnProgress, UninstallSummary};
use super::error::{InstallError, Result};
use super::fsx::read_text;
use super::paths::{self, Paths};
use super::runner::{Call, Runner, Tool};
use super::stages::port;
use super::state;
use super::units::{self, Dest, FIREWALL_UNITS, GATEWAY_UNITS};
use crate::privd::state::write_atomic;

/// Units the other workstreams add that are not rows of the units table yet (their names are
/// fixed, and removing a file that is not there is fine).
pub const EXTRA_UNIT_FILES: &[&str] = &["hx-gatewayd-public.socket", "hx-privd-rescue.service"];

/// Empties a directory as another user.
pub trait Cleaner {
    /// Empties `dir` (not the directory itself) running as `uid`:`gid`.
    fn empty_as_owner(&mut self, dir: &Path, uid: u32, gid: u32) -> io::Result<()>;
}

/// The real cleaner: runs this binary as the owner with `__empty-dir`.
///
/// The binary is found by its path, or, if that path is gone (the release directory was removed
/// under it), through a descriptor of the running executable that was opened at construction and
/// is inherited by the child (`/proc/self/fd/N`). U5 also empties gatewayd's state **before** it
/// removes `/usr/lib/hx`, so the path normally still exists.
#[derive(Debug)]
pub struct SelfExecCleaner {
    exe_fd: Option<std::os::fd::OwnedFd>,
    exe_path: Option<PathBuf>,
}

impl Default for SelfExecCleaner {
    fn default() -> Self {
        Self::new()
    }
}

impl SelfExecCleaner {
    /// Opens `/proc/self/exe` now and remembers where the executable is.
    pub fn new() -> Self {
        let file = std::fs::File::open("/proc/self/exe").ok();
        Self::with_exe(file, std::env::current_exe().ok())
    }

    /// A cleaner for a given executable (tests).
    pub fn with_exe(file: Option<std::fs::File>, path: Option<PathBuf>) -> Self {
        let exe_fd = file.map(std::os::fd::OwnedFd::from).inspect(|fd| {
            // Inherited by the child: no close-on-exec.
            let _ = rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::empty());
        });
        Self {
            exe_fd,
            exe_path: path,
        }
    }

    fn program(&self) -> io::Result<PathBuf> {
        use std::os::fd::AsRawFd;
        if let Some(p) = self.exe_path.as_ref().filter(|p| p.exists()) {
            return Ok(p.clone());
        }
        match &self.exe_fd {
            Some(fd) => Ok(PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "the agent executable is gone",
            )),
        }
    }
}

impl Cleaner for SelfExecCleaner {
    fn empty_as_owner(&mut self, dir: &Path, uid: u32, gid: u32) -> io::Result<()> {
        use std::os::unix::process::CommandExt;
        // `uid` makes std drop the supplementary groups before `setuid` when running as root.
        let st = std::process::Command::new(self.program()?)
            .arg("__empty-dir")
            .arg(dir)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .gid(gid)
            .uid(uid)
            .status()?;
        if st.success() {
            Ok(())
        } else {
            Err(io::Error::other("the cleaning child failed"))
        }
    }
}

/// Removes everything below `dir` with `unlinkat`, relative to descriptors opened `O_NOFOLLOW`:
/// a symlink is removed as an entry and never followed, and nothing outside `dir` is touched.
pub fn empty_dir_beneath(dir: &Path) -> io::Result<()> {
    let fd = rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    empty_fd(&fd, 0)
}

fn empty_fd(fd: &impl AsFd, depth: u32) -> io::Result<()> {
    if depth > 64 {
        return Err(io::Error::other("the directory tree is too deep"));
    }
    let names: Vec<std::ffi::CString> = {
        let dup = rustix::io::fcntl_dupfd_cloexec(fd, 0)?;
        let mut v = Vec::new();
        for e in Dir::read_from(&dup)? {
            let e = e?;
            let n = e.file_name();
            if n.to_bytes() != b"." && n.to_bytes() != b".." {
                v.push(n.to_owned());
            }
        }
        v
    };
    for name in names {
        let st = rustix::fs::statat(fd, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(st.st_mode) == FileType::Directory {
            let sub = rustix::fs::openat(
                fd,
                name.as_c_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            empty_fd(&sub, depth + 1)?;
            drop(sub);
            rustix::fs::unlinkat(fd, name.as_c_str(), AtFlags::REMOVEDIR)?;
        } else {
            rustix::fs::unlinkat(fd, name.as_c_str(), AtFlags::empty())?;
        }
    }
    Ok(())
}

/// The resume file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct UninstallState {
    /// 1.
    pub schema: u32,
    /// The mode of this uninstall.
    pub keep_desktop: bool,
    /// Steps finished (`U1` ... `U7`).
    pub done: Vec<String>,
    /// privd's `Uninstall` has completed.
    pub privd_done: bool,
}

/// What the uninstall did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// The mode.
    pub keep_desktop: bool,
    /// The steps that ran now (not those skipped on resume).
    pub ran: Vec<String>,
    /// privd's account of what it removed and kept.
    pub summary: UninstallSummary,
    /// Things that could not be done and do not stop the uninstall.
    pub warnings: Vec<String>,
    /// What stays, and how to remove it.
    pub notes: Vec<String>,
}

/// How an uninstall can end without finishing.
#[derive(Debug)]
pub enum UninstallError {
    /// privd answered `UNIMPLEMENTED` (an old privd): the manual steps. `changed` is true when
    /// a step before U2 had already been taken and was undone.
    Unimplemented,
    /// privd cannot be reached and could not be started: print the manual steps for its part.
    PrivdUnreachable,
    /// Anything else.
    Failed(InstallError),
}

impl From<InstallError> for UninstallError {
    fn from(e: InstallError) -> Self {
        Self::Failed(e)
    }
}

/// Everything the uninstall uses.
pub struct UninstallDeps<'a> {
    /// The root.
    pub paths: Paths,
    /// Runs tools.
    pub runner: &'a mut dyn Runner,
    /// privd.
    pub daemons: &'a mut dyn Daemons,
    /// Empties gatewayd's state.
    pub cleaner: &'a mut dyn Cleaner,
    /// The Unix clock.
    pub now: fn() -> u64,
    /// Waits `d` (tests do not).
    pub sleep: fn(std::time::Duration),
    /// Run the host-level steps (U1, U3, U4, U6, U7): false for a non-production configuration.
    pub host: bool,
    /// The effective uid.
    pub euid: u32,
}

const STEPS: [&str; 7] = ["U1", "U2", "U3", "U4", "U5", "U6", "U7"];

fn load_state(p: &Path) -> Result<Option<UninstallState>> {
    match std::fs::read(p) {
        Ok(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|_| InstallError::internal("hx-uninstall.json is corrupt")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn save_state(p: &Path, s: &UninstallState) -> Result<()> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut b = serde_json::to_vec_pretty(s).map_err(io::Error::other)?;
    b.push(b'\n');
    write_atomic(p, &b, 0o600)?;
    Ok(())
}

fn sysctl(d: &mut UninstallDeps<'_>, args: &[&str]) -> Option<i32> {
    d.runner
        .run(&Call::new(Tool::Systemctl, args).timeout_secs(120))
        .ok()
        .map(|o| o.status)
}

fn systemctl_args(verb: &[&str], units: &[&str]) -> Vec<String> {
    verb.iter()
        .chain(units.iter())
        .map(|s| (*s).to_owned())
        .collect()
}

fn gateway_ids(paths: &Paths) -> Option<(u32, u32)> {
    let t = read_text(&paths.at(paths::PASSWD))?;
    t.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.first() == Some(&paths::GATEWAY_USER) && f.len() >= 4)
            .then(|| Some((f[2].parse().ok()?, f[3].parse().ok()?)))
            .flatten()
    })
}

/// The files the installer writes, as an EXACT set of absolute paths (never a prefix, never read
/// from the state: a tampered `install-state.json` cannot add to it). In keep mode the firewall
/// ruleset and its two units stay.
pub fn exact_files(keep: bool) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for f in units::FILES {
        if keep && f.dest == Dest::Unit && FIREWALL_UNITS.contains(&f.name) {
            continue;
        }
        let dir = match f.dest {
            Dest::Unit => paths::UNIT_DIR,
            Dest::Sysusers => paths::SYSUSERS_DIR,
            Dest::Tmpfiles => paths::TMPFILES_DIR,
            Dest::Logrotate => paths::LOGROTATE_DIR,
        };
        v.push(format!("{dir}/{}", f.name));
    }
    for n in EXTRA_UNIT_FILES {
        v.push(format!("{}/{n}", paths::UNIT_DIR));
    }
    for p in [
        paths::PORT_DROPIN,
        paths::RESOLVERS_DROPIN,
        paths::RESCUE_BIN,
        paths::GATEWAYD_TOML,
        paths::PRIVD_TOML,
        "/etc/hx/creds/pepper.cred",
        "/etc/hx/creds/pepper.cred.tmp",
        "/etc/hx/creds/identity.cred",
        "/etc/hx/creds/identity.cred.tmp",
    ] {
        v.push(p.to_owned());
    }
    if !keep {
        v.push(paths::HOST_FIREWALL.to_owned());
    }
    v
}

/// The installer's own drop-in directories: the only directories that are `rmdir`'d (and only
/// when empty).
const DROPIN_DIRS: [&str; 2] = [
    "/etc/systemd/system/hx-gatewayd-public.socket.d",
    "/etc/systemd/system/hx-update-fetcher@.service.d",
];

/// Unlinks one file (never a directory, never through a link at the last component): the parent
/// is opened and the name is removed relative to that descriptor.
fn unlink_file(abs: &Path) -> io::Result<()> {
    let (Some(parent), Some(name)) = (abs.parent(), abs.file_name()) else {
        return Ok(());
    };
    let pfd = match rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    match rustix::fs::unlinkat(&pfd, name, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn remove_path(p: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_dir() => std::fs::remove_dir_all(p),
        Ok(_) => std::fs::remove_file(p),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn u5_files(d: &mut UninstallDeps<'_>, keep: bool) -> Result<()> {
    let p = d.paths.clone();
    // gatewayd's state FIRST: it is emptied by a child that runs this very binary, which lives in
    // /usr/lib/hx/current until the last step below. As that user (rule 15).
    let state_dir = p.at(paths::GATEWAYD_STATE);
    if std::fs::symlink_metadata(&state_dir).is_ok() {
        match gateway_ids(&p) {
            Some((uid, gid)) => {
                d.cleaner
                    .empty_as_owner(&state_dir, uid, gid)
                    .map_err(|e| {
                        InstallError::tool(format!(
                            "cannot empty gatewayd's state as its user: {e}"
                        ))
                    })?;
            }
            None => {
                return Err(InstallError::tool(
                    "the hx-gatewayd user is gone but its state directory remains; refusing to walk it as root",
                ));
            }
        }
        let parent = state_dir.parent().unwrap_or(Path::new("/"));
        let pfd = rustix::fs::open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| InstallError::tool(format!("cannot open {}: {e}", parent.display())))?;
        let name = state_dir.file_name().unwrap_or_default();
        rustix::fs::unlinkat(&pfd, name, AtFlags::REMOVEDIR).map_err(|e| {
            InstallError::tool(format!("cannot remove gatewayd's state directory: {e}"))
        })?;
    }
    // The files the installer wrote: an exact set, unlinked one by one.
    for f in exact_files(keep) {
        unlink_file(&p.at(&f))?;
    }
    for dir in DROPIN_DIRS {
        // Only when empty; anything else in there is not ours.
        let _ = std::fs::remove_dir(p.at(dir));
    }
    // privd's directories. The fetcher can write to the updates directory: it is removed with
    // rmdir only (its tmpfs is unmounted by U3), never walked by root.
    let updates = p.at("/var/lib/hx/updates");
    match std::fs::remove_dir(&updates) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(InstallError::tool(
                "/var/lib/hx/updates is not empty or still mounted; refusing to walk it as root",
            ));
        }
    }
    for dir in [
        paths::USR_LIB_HX,
        paths::RESCUE_DIR,
        paths::VAR_LIB_HX,
        paths::VAR_LOG_HX,
        paths::RUN_HX,
    ] {
        remove_path(&p.at(dir))?;
    }
    // /etc/hx.
    let etc = p.at(paths::ETC_HX);
    if keep {
        if let Ok(rd) = std::fs::read_dir(&etc) {
            for e in rd.flatten() {
                if e.file_name() != "host-firewall.nft" {
                    remove_path(&e.path())?;
                }
            }
        }
    } else {
        remove_path(&etc)?;
    }
    Ok(())
}

/// Runs the uninstall. `confirm` has been done by the caller.
pub fn run(
    keep_desktop: bool,
    mut d: UninstallDeps<'_>,
    on_progress: OnProgress<'_>,
    say: &mut dyn FnMut(&str),
) -> std::result::Result<Report, UninstallError> {
    if d.euid != 0 {
        return Err(InstallError::not_root().into());
    }
    let _lock = super::lock::acquire(&d.paths.at(paths::LOCK_FILE), None)?;
    let st_path = d.paths.at(paths::UNINSTALL_STATE);
    // An unreadable state must not silently skip the port rule (U4): it is searched by comment.
    let (installed, state_unreadable) = match state::load(&d.paths.at(paths::STATE_FILE)) {
        Ok(s) => (s, false),
        Err(_) => (None, true),
    };
    let mut st = match load_state(&st_path)? {
        Some(s) => {
            if s.keep_desktop && !keep_desktop && s.privd_done {
                return Err(InstallError::conflict(
                    "this uninstall already finished privd's part in keep mode; the desktop can no longer be destroyed by it (use: incus delete --force hx-main)",
                )
                .into());
            }
            if !s.keep_desktop && keep_desktop {
                return Err(InstallError::conflict(
                    "this uninstall already started in destroy mode; it cannot go back to keeping the desktop",
                )
                .into());
            }
            UninstallState { keep_desktop, ..s }
        }
        None => UninstallState {
            schema: 1,
            keep_desktop,
            ..UninstallState::default()
        },
    };
    save_state(&st_path, &st)?;
    let mut report = Report {
        keep_desktop,
        ..Report::default()
    };

    for step in STEPS {
        if st.done.iter().any(|x| x == step) {
            continue;
        }
        match step {
            "U1" => {
                say("U1: stopping the gateway units\n");
                if d.host {
                    let args = systemctl_args(&["disable", "--now"], GATEWAY_UNITS);
                    let _ = d
                        .runner
                        .run(&Call::owned(Tool::Systemctl, args).timeout_secs(120));
                }
            }
            "U2" => {
                say("U2: asking hx-privd to remove what it created\n");
                if !st.privd_done {
                    // privd's own marker says its part is done (`privd_done` in
                    // /var/lib/hx/uninstall-state), or its state directory is gone.
                    let marker_done = read_text(&d.paths.at(paths::PRIVD_UNINSTALL_STATE))
                        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                        .is_some_and(|v| v["privd_done"] == true);
                    let privd_gone =
                        marker_done || (!d.paths.at(paths::VAR_LIB_HX).exists() && d.host);
                    if privd_gone {
                        // privd's state directory is gone: its part was done by an earlier run.
                        st.privd_done = true;
                    } else {
                        match call_privd(&mut d, keep_desktop, on_progress) {
                            Ok(s) => {
                                report.summary = s;
                                st.privd_done = true;
                            }
                            Err(UninstallError::Unimplemented) => {
                                if d.host {
                                    let args = systemctl_args(&["enable", "--now"], GATEWAY_UNITS);
                                    let _ = d
                                        .runner
                                        .run(&Call::owned(Tool::Systemctl, args).timeout_secs(120));
                                }
                                let _ = std::fs::remove_file(&st_path);
                                return Err(UninstallError::Unimplemented);
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
            "U3" => {
                say("U3: stopping privd and its helpers\n");
                if d.host {
                    let mut units = vec![
                        "hx-privd.socket",
                        "hx-privd.service",
                        "hx-privd-rescue.service",
                        "var-lib-hx-updates.mount",
                        // The image fetcher's tmpfs under /var/lib/hx (1D): still mounted, it
                        // makes U5's removal of /var/lib/hx fail with "resource busy".
                        "var-lib-hx-imagein.mount",
                    ];
                    if !keep_desktop {
                        units.extend_from_slice(FIREWALL_UNITS);
                    }
                    let _ = d.runner.run(
                        &Call::owned(
                            Tool::Systemctl,
                            systemctl_args(&["disable", "--now"], &units),
                        )
                        .timeout_secs(120),
                    );
                    let _ = d.runner.run(&Call::new(
                        Tool::Systemctl,
                        &[
                            "stop",
                            "hx-update-fetcher@*.service",
                            "hx-image-fetcher@*.service",
                        ],
                    ));
                }
            }
            "U4" => {
                say("U4: removing the port rule\n");
                if d.host {
                    match installed.as_ref().and_then(|s| s.created.port_rule.clone()) {
                        Some(rec) => {
                            port::remove(d.runner, &rec)?;
                            if rec.backend == "manual" {
                                report.notes.push(format!(
                                    "the firewall rule for port {} was opened by hand; remove it by hand",
                                    rec.port
                                ));
                            }
                        }
                        None => {
                            if state_unreadable {
                                report.warnings.push(
                                    "install-state.json is unreadable: the port rule is searched by its comment (nftables and ufw)"
                                        .into(),
                                );
                            }
                            port::remove_fallback(d.runner)?;
                        }
                    }
                    // Harmless when it was never enabled.
                    let _ = d.runner.run(&Call::new(
                        Tool::Systemctl,
                        &["disable", "--now", "hx-agent-port.service"],
                    ));
                }
            }
            "U5" => {
                say("U5: removing files\n");
                u5_files(&mut d, keep_desktop)?;
            }
            "U6" => {
                say("U6: removing the hx-gatewayd user\n");
                if d.host && gateway_ids(&d.paths).is_some() {
                    let o = d
                        .runner
                        .run(&Call::new(Tool::Userdel, &[paths::GATEWAY_USER]))
                        .map_err(|e| InstallError::tool(format!("userdel: {e}")))?;
                    // 12: the home directory could not be removed (it is already gone).
                    if !matches!(o.status, 0 | 12) {
                        return Err(InstallError::tool(format!(
                            "userdel failed with status {}",
                            o.status
                        ))
                        .into());
                    }
                }
            }
            _ => {
                say("U7: reloading systemd\n");
                if d.host {
                    sysctl(&mut d, &["daemon-reload"]);
                    sysctl(&mut d, &["reset-failed"]);
                }
            }
        }
        st.done.push(step.to_owned());
        report.ran.push(step.to_owned());
        // After U5 the state directory may be gone; the resume file lives outside it.
        save_state(&st_path, &st)?;
    }
    if let Some(i) = &installed
        && i.created.incus.as_ref().is_some_and(|x| x.by_installer)
    {
        report
            .notes
            .push("Incus stays installed (it may hold other instances); remove it with your package manager if you want".into());
    }
    if installed
        .as_ref()
        .is_some_and(|i| !i.created.apt.is_empty())
    {
        report.notes.push(
            "the Zabbly apt repository stays; remove it with: rm /etc/apt/keyrings/hx-zabbly.asc /etc/apt/sources.list.d/hx-zabbly-incus.sources && apt-get update".into(),
        );
    }
    if keep_desktop {
        report.notes.push(
            "the desktop, its pool, the host firewall and its units were kept; see the manual steps for removing them later".into(),
        );
    }
    // U8: drop the resume file.
    let _ = std::fs::remove_file(&st_path);
    let _ = (d.now)();
    Ok(report)
}

fn call_privd(
    d: &mut UninstallDeps<'_>,
    keep: bool,
    on: OnProgress<'_>,
) -> std::result::Result<UninstallSummary, UninstallError> {
    use crate::install::error::Code;
    let mut attempt = d.daemons.uninstall(keep, &mut *on);
    if let Err(e) = &attempt
        && e.code == Code::Unavailable
        && d.host
    {
        // privd's socket may simply not be started: try once.
        let started = d
            .runner
            .run(&Call::new(Tool::Systemctl, &["start", "hx-privd.socket"]))
            .is_ok_and(|o| o.ok());
        if started {
            (d.sleep)(std::time::Duration::from_secs(1));
            attempt = d.daemons.uninstall(keep, on);
        }
    }
    match attempt {
        Ok(s) => Ok(s),
        Err(e) if e.code == Code::Unimplemented => Err(UninstallError::Unimplemented),
        Err(e) if e.code == Code::Unavailable => Err(UninstallError::PrivdUnreachable),
        Err(e) => Err(UninstallError::Failed(e)),
    }
}

/// The path of the resume file for a root (for tests).
pub fn resume_path(p: &Paths) -> PathBuf {
    p.at(paths::UNINSTALL_STATE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emptying_never_follows_a_symlink_and_removes_everything_below() {
        let d = tempfile::tempdir().unwrap();
        let outside = d.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("precious"), b"x").unwrap();
        let t = d.path().join("state");
        std::fs::create_dir_all(t.join("a/b")).unwrap();
        std::fs::write(t.join("a/b/f"), b"1").unwrap();
        std::fs::write(t.join("g"), b"2").unwrap();
        std::os::unix::fs::symlink(&outside, t.join("a/link")).unwrap();
        std::os::unix::fs::symlink(outside.join("precious"), t.join("flink")).unwrap();
        empty_dir_beneath(&t).unwrap();
        assert!(t.exists() && std::fs::read_dir(&t).unwrap().next().is_none());
        assert!(
            outside.join("precious").exists(),
            "a link target must survive"
        );
    }

    #[test]
    fn emptying_a_symlinked_root_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("f"), b"1").unwrap();
        let l = d.path().join("l");
        std::os::unix::fs::symlink(&real, &l).unwrap();
        assert!(empty_dir_beneath(&l).is_err());
        assert!(real.join("f").exists());
    }

    #[test]
    fn the_removal_set_is_exact_and_holds_only_files() {
        let all = exact_files(false);
        assert!(all.iter().any(|f| f == paths::PORT_DROPIN));
        assert!(all.iter().any(|f| f == paths::RESOLVERS_DROPIN));
        assert!(all.iter().any(|f| f == paths::RESCUE_BIN));
        assert!(all.iter().any(|f| f == paths::HOST_FIREWALL));
        for f in &all {
            assert!(
                f.starts_with('/') && !f.contains("..") && !f.ends_with('/'),
                "{f}"
            );
            assert!(!f.ends_with(".d") && !f.ends_with(".wants"), "{f}");
        }
        let keep = exact_files(true);
        assert!(
            !keep
                .iter()
                .any(|f| f == paths::HOST_FIREWALL || f.ends_with("hx-host-firewall.service"))
        );
    }

    #[test]
    fn unlinking_never_removes_a_directory_or_follows_the_last_link() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("dir");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("keep"), b"x").unwrap();
        assert!(unlink_file(&dir).is_err(), "a directory is refused");
        assert!(dir.join("keep").exists());
        let target = d.path().join("target");
        std::fs::write(&target, b"x").unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        unlink_file(&link).unwrap();
        assert!(target.exists() && !link.exists());
        unlink_file(&d.path().join("missing")).unwrap();
    }
}
