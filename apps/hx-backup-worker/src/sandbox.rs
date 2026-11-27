//! The worker's self-applied sandbox (ipc.md §24).
//!
//! The helper container is the outer layer (own user namespace, no network interface, the LXC
//! seccomp profile). This module is the inner one, applied by the process itself in two moments:
//!
//! 1. [`early_hardening`], before any peer byte is read: `PR_SET_NO_NEW_PRIVS`,
//!    `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`;
//! 2. [`harden`], when the job and its secrets have arrived (the job kind decides what is kept) and
//!    before the first thread starts: drop capabilities to [`capabilities_for`], then install the
//!    seccomp allowlist of [`program`].
//!
//! The allowlist is a list of what `rustic_core`, its thread pool and the link need, never of what
//! is merely harmless. It has no `socket`, `connect`, `bind`, `execve`, `ptrace` or `mount`; outside
//! `RESTORE` it opens files read-only and has no call that writes the file system or an extended
//! attribute. A violation kills the process (`SIGSYS`); [`Mode::Errno`] exists only so that a test
//! can observe a refusal and is never chosen by the binary.
//!
//! This is the only module of the package with `unsafe`: `capget`/`capset`, `PR_CAPBSET_DROP` and the
//! signal handlers have no safe wrapper in `rustix`. Each block says why it is sound.

use std::collections::BTreeMap;
use std::io;

use hx_ipc::repo::pb;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

/// Why the sandbox could not be set up. The worker exits with 70.
#[derive(Debug, thiserror::Error)]
#[error("sandbox: {0}")]
pub struct SandboxError(pub String);

fn err(what: &str, e: impl std::fmt::Display) -> SandboxError {
    SandboxError(format!("{what}: {e}"))
}

/// What a seccomp violation does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Kill the process (`SIGSYS`). The only mode of the binary.
    Enforce,
    /// Fail the call with `EPERM`. For the sandbox test, which has to survive its own probes.
    Errno,
}

// ----- capabilities -----

/// A Linux capability by number (`linux/capability.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cap {
    /// `CAP_CHOWN`
    Chown = 0,
    /// `CAP_DAC_OVERRIDE`
    DacOverride = 1,
    /// `CAP_DAC_READ_SEARCH`
    DacReadSearch = 2,
    /// `CAP_FOWNER`
    Fowner = 3,
    /// `CAP_FSETID`
    Fsetid = 4,
    /// `CAP_MKNOD`
    Mknod = 27,
    /// `CAP_SETFCAP`
    Setfcap = 31,
}

/// The capabilities a job of `kind` keeps (ipc.md §24).
#[must_use]
pub fn capabilities_for(kind: pb::JobKind) -> &'static [Cap] {
    match kind {
        pb::JobKind::Backup => &[Cap::DacReadSearch],
        pb::JobKind::Restore => &[
            Cap::Chown,
            Cap::DacOverride,
            Cap::Fowner,
            Cap::Fsetid,
            Cap::Setfcap,
            Cap::Mknod,
        ],
        _ => &[],
    }
}

fn mask(keep: &[Cap]) -> u64 {
    keep.iter().fold(0, |m, c| m | 1u64 << (*c as u8))
}

/// The capability sets of the calling thread, as masks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapSets {
    /// Effective.
    pub effective: u64,
    /// Permitted.
    pub permitted: u64,
    /// Inheritable.
    pub inheritable: u64,
}

/// Reads the capability sets of the calling thread.
///
/// # Errors
/// The OS error of `capget`.
pub fn capability_sets() -> io::Result<CapSets> {
    let d = sys::capget()?;
    let join = |lo: u32, hi: u32| u64::from(lo) | u64::from(hi) << 32;
    Ok(CapSets {
        effective: join(d[0].effective, d[1].effective),
        permitted: join(d[0].permitted, d[1].permitted),
        inheritable: join(d[0].inheritable, d[1].inheritable),
    })
}

fn last_cap() -> u8 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
        .filter(|n| *n < 64)
        .unwrap_or(40)
}

/// Drops every capability not in `keep`: out of the bounding set; permitted and effective become
/// `keep` (never more than the process had); inheritable and ambient become empty. The result is
/// read back; a difference is an error.
///
/// # Errors
/// [`SandboxError`] if any step or the read-back fails.
pub fn drop_capabilities(keep: &[Cap]) -> Result<(), SandboxError> {
    let want = mask(keep);
    for cap in 0..=last_cap() {
        if want & (1u64 << cap) == 0 {
            sys::bounding_drop(cap).map_err(|e| err("PR_CAPBSET_DROP", e))?;
        }
    }
    let before = capability_sets().map_err(|e| err("capget", e))?;
    let keep_now = before.permitted & want;
    sys::capset_to(keep_now, keep_now, 0).map_err(|e| err("capset", e))?;
    sys::ambient_clear().map_err(|e| err("PR_CAP_AMBIENT_CLEAR_ALL", e))?;
    let after = capability_sets().map_err(|e| err("capget", e))?;
    if after.permitted & !want != 0 || after.effective & !want != 0 || after.inheritable != 0 {
        return Err(SandboxError("capabilities remain after the drop".into()));
    }
    for cap in 0..=last_cap() {
        if want & (1u64 << cap) == 0 && sys::bounding_has(cap).unwrap_or(true) {
            return Err(SandboxError(
                "a capability remains in the bounding set".into(),
            ));
        }
    }
    Ok(())
}

// ----- the early steps and the signals -----

/// `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` (ipc.md §24, step 1).
///
/// # Errors
/// [`SandboxError`].
pub fn early_hardening() -> Result<(), SandboxError> {
    use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};
    rustix::thread::set_no_new_privs(true).map_err(|e| err("PR_SET_NO_NEW_PRIVS", e))?;
    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(|e| err("PR_SET_DUMPABLE", e))?;
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|e| err("RLIMIT_CORE", e))
}

/// The signal dispositions of PID 1: `SIGCHLD` ignored (the kernel reaps orphans), `SIGTERM` exits
/// with 143 (PID 1 ignores a signal without a handler).
///
/// # Errors
/// The OS error of `sigaction`.
pub fn install_signal_handlers() -> io::Result<()> {
    sys::install_signals()
}

/// Takes ownership of the descriptor systemd passed (`LISTEN_FDS=1`: descriptor 3).
///
/// # Errors
/// The OS error when `fd` is not an open descriptor.
pub fn take_activated_fd(fd: i32) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{BorrowedFd, FromRawFd};
    // SAFETY: the caller has checked `LISTEN_PID` and `LISTEN_FDS`, so descriptor `fd` was opened by
    // the service manager for this process and nobody else in it owns it. `fcntl(F_GETFD)` proves
    // it is open before an `OwnedFd` is made, and the process calls this once.
    unsafe {
        rustix::io::fcntl_getfd(BorrowedFd::borrow_raw(fd))?;
        Ok(std::os::fd::OwnedFd::from_raw_fd(fd))
    }
}

// ----- seccomp -----

macro_rules! syscalls {
    ($($name:ident),* $(,)?) => { [$((libc::$name, stringify!($name))),*] };
}

/// Syscalls every kind may use, allowed without a check of the arguments.
fn common() -> Vec<(i64, &'static str)> {
    let mut v: Vec<(i64, &'static str)> = Vec::new();
    v.extend(syscalls![
        // memory
        SYS_brk,
        SYS_mmap,
        SYS_munmap,
        SYS_mremap,
        SYS_mprotect,
        SYS_madvise,
        // threads and signals; clone3 only so that the second program can answer ENOSYS
        SYS_clone3,
        SYS_futex,
        SYS_set_robust_list,
        SYS_set_tid_address,
        SYS_rseq,
        SYS_sigaltstack,
        SYS_rt_sigaction,
        SYS_rt_sigprocmask,
        SYS_rt_sigreturn,
        SYS_exit,
        SYS_exit_group,
        SYS_gettid,
        SYS_getpid,
        SYS_tgkill,
        SYS_sched_yield,
        SYS_sched_getaffinity,
        // time and randomness
        SYS_clock_gettime,
        SYS_clock_getres,
        SYS_gettimeofday,
        SYS_nanosleep,
        SYS_clock_nanosleep,
        SYS_getrandom,
        // descriptors (the link is an existing socket: no socket(2), connect or bind)
        SYS_read,
        SYS_write,
        SYS_readv,
        SYS_writev,
        SYS_pread64,
        SYS_lseek,
        SYS_close,
        SYS_dup,
        SYS_dup3,
        SYS_fcntl,
        SYS_pipe2,
        SYS_eventfd2,
        SYS_epoll_create1,
        SYS_epoll_ctl,
        SYS_epoll_pwait,
        SYS_ppoll,
        SYS_recvmsg,
        SYS_sendmsg,
        SYS_recvfrom,
        SYS_sendto,
        SYS_getsockopt,
        // reading the file system
        SYS_newfstatat,
        SYS_fstat,
        SYS_statx,
        SYS_statfs,
        SYS_fstatfs,
        SYS_readlinkat,
        SYS_faccessat,
        SYS_faccessat2,
        SYS_getdents64,
        SYS_getcwd,
        SYS_fadvise64,
        // extended attributes: reading is allowed everywhere (a backup records them)
        SYS_getxattr,
        SYS_lgetxattr,
        SYS_fgetxattr,
        SYS_listxattr,
        SYS_llistxattr,
        SYS_flistxattr,
        // identity and limits
        SYS_getuid,
        SYS_geteuid,
        SYS_getgid,
        SYS_getegid,
        SYS_getgroups,
        // read-only: lets a test (and a curious operator) see what was kept
        SYS_capget,
        SYS_uname,
        SYS_sysinfo,
    ]);
    #[cfg(target_arch = "x86_64")]
    v.extend(syscalls![
        SYS_arch_prctl,
        SYS_poll,
        SYS_epoll_wait,
        SYS_pipe,
        SYS_dup2,
        SYS_getrlimit,
        SYS_stat,
        SYS_lstat,
        SYS_access,
        SYS_readlink,
        SYS_getdents,
    ]);
    v
}

/// Calls that change the file system: only `RESTORE` has them.
fn writes() -> Vec<(i64, &'static str)> {
    let mut v: Vec<(i64, &'static str)> = Vec::new();
    v.extend(syscalls![
        SYS_pwrite64,
        SYS_mkdirat,
        SYS_symlinkat,
        SYS_linkat,
        SYS_mknodat,
        SYS_renameat,
        SYS_renameat2,
        SYS_unlinkat,
        SYS_fchmod,
        SYS_fchmodat,
        SYS_fchown,
        SYS_fchownat,
        SYS_utimensat,
        SYS_truncate,
        SYS_ftruncate,
        SYS_fallocate,
        SYS_fsync,
        SYS_fdatasync,
        SYS_umask,
        SYS_chdir,
        SYS_fchdir,
        SYS_setxattr,
        SYS_lsetxattr,
        SYS_fsetxattr,
        SYS_removexattr,
        SYS_lremovexattr,
        SYS_fremovexattr,
    ]);
    #[cfg(target_arch = "x86_64")]
    v.extend(syscalls![
        SYS_mkdir,
        SYS_rmdir,
        SYS_symlink,
        SYS_link,
        SYS_mknod,
        SYS_rename,
        SYS_unlink,
        SYS_chmod,
        SYS_chown,
        SYS_lchown,
        SYS_utimes,
        SYS_futimesat,
    ]);
    v
}

/// The names of every syscall the allowlist of `kind` has, for the documentation and the tests.
#[must_use]
pub fn allowed_names(kind: pb::JobKind) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = common().into_iter().map(|(_, n)| n).collect();
    names.extend([
        "SYS_openat",
        "SYS_ioctl",
        "SYS_clone",
        "SYS_prctl",
        "SYS_prlimit64",
    ]);
    #[cfg(target_arch = "x86_64")]
    names.push("SYS_open");
    if kind == pb::JobKind::Restore {
        names.extend(writes().into_iter().map(|(_, n)| n));
    }
    names.sort_unstable();
    names
}

fn cond(
    arg: u8,
    len: SeccompCmpArgLen,
    op: SeccompCmpOp,
    value: u64,
) -> Result<SeccompCondition, SandboxError> {
    SeccompCondition::new(arg, len, op, value).map_err(|e| err("seccomp condition", e))
}

fn rule(conditions: Vec<SeccompCondition>) -> Result<SeccompRule, SandboxError> {
    SeccompRule::new(conditions).map_err(|e| err("seccomp rule", e))
}

fn arg_eq(arg: u8, value: u64) -> Result<SeccompRule, SandboxError> {
    rule(vec![cond(
        arg,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        value,
    )?])
}

/// `(flags & mask) == 0` on argument `arg`.
fn flags_clear(arg: u8, m: u64) -> Result<SeccompCondition, SandboxError> {
    cond(arg, SeccompCmpArgLen::Dword, SeccompCmpOp::MaskedEq(m), 0)
}

fn arch() -> Result<TargetArch, SandboxError> {
    TargetArch::try_from(std::env::consts::ARCH).map_err(|e| err("architecture", e))
}

fn mismatch(mode: Mode) -> SeccompAction {
    match mode {
        Mode::Enforce => SeccompAction::KillProcess,
        Mode::Errno => SeccompAction::Errno(libc::EPERM as u32),
    }
}

/// The allowlist program for a job of `kind`.
///
/// # Errors
/// [`SandboxError`] if the filter cannot be built.
pub fn program(kind: pb::JobKind, mode: Mode) -> Result<BpfProgram, SandboxError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for (nr, _) in common() {
        rules.insert(nr, vec![]);
    }
    // The network family is allowed here only so that the EPERM program below answers it: a kill
    // would take glibc's name-service lookups down with it (ipc.md §24).
    for nr in NETWORK {
        rules.insert(nr, vec![]);
    }
    let restore = kind == pb::JobKind::Restore;
    if restore {
        for (nr, _) in writes() {
            rules.insert(nr, vec![]);
        }
    }

    // open: read-only outside RESTORE (no write access, no create, no truncate, no O_TMPFILE).
    const O_ACCMODE: u64 = 0o3;
    const O_CREAT: u64 = 0o100;
    const O_TRUNC: u64 = 0o1000;
    // __O_TMPFILE is 0o20000000 (not O_CLOEXEC, 0o2000000, which every open uses)
    const O_TMPFILE_BIT: u64 = 0o20000000;
    let read_only = |flags_arg: u8| -> Result<Vec<SeccompRule>, SandboxError> {
        if restore {
            return Ok(vec![]);
        }
        Ok(vec![rule(vec![
            flags_clear(flags_arg, O_ACCMODE)?,
            flags_clear(flags_arg, O_CREAT | O_TRUNC | O_TMPFILE_BIT)?,
        ])?])
    };
    rules.insert(libc::SYS_openat, read_only(2)?);
    #[cfg(target_arch = "x86_64")]
    rules.insert(libc::SYS_open, read_only(1)?);

    // ioctl: what std and the runtime use on descriptors (FIONREAD, FIOCLEX, FIONCLEX, FIONBIO,
    // TCGETS for the terminal check of the log writer).
    rules.insert(
        libc::SYS_ioctl,
        vec![
            arg_eq(1, 0x5421)?,
            arg_eq(1, 0x541B)?,
            arg_eq(1, 0x5451)?,
            arg_eq(1, 0x5450)?,
            arg_eq(1, 0x5401)?,
        ],
    );

    // clone: a thread and nothing else (CLONE_VM, CLONE_SIGHAND and CLONE_THREAD set, no
    // namespace flag). clone3 is answered ENOSYS by the second program.
    const THREAD_FLAGS: u64 = (libc::CLONE_VM | libc::CLONE_SIGHAND | libc::CLONE_THREAD) as u64;
    const NAMESPACE_FLAGS: u64 = (libc::CLONE_NEWNS
        | libc::CLONE_NEWCGROUP
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET) as u64;
    rules.insert(
        libc::SYS_clone,
        vec![rule(vec![
            cond(
                0,
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::MaskedEq(THREAD_FLAGS),
                THREAD_FLAGS,
            )?,
            cond(
                0,
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::MaskedEq(NAMESPACE_FLAGS),
                0,
            )?,
        ])?],
    );

    // prlimit64: read limits only. A call with a new limit (argument 2, a pointer) is refused, so a
    // compromised worker cannot raise its own limits.
    rules.insert(
        libc::SYS_prlimit64,
        vec![rule(vec![cond(
            2,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::Eq,
            0,
        )?])?],
    );

    // prctl: name a thread, and clear (never set) the dumpable flag.
    const PR_SET_DUMPABLE: u64 = 4;
    const PR_SET_NAME: u64 = 15;
    const PR_GET_NAME: u64 = 16;
    rules.insert(
        libc::SYS_prctl,
        vec![
            arg_eq(0, PR_SET_NAME)?,
            arg_eq(0, PR_GET_NAME)?,
            rule(vec![
                cond(
                    0,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Eq,
                    PR_SET_DUMPABLE,
                )?,
                cond(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 0)?,
            ])?,
        ],
    );

    SeccompFilter::new(rules, mismatch(mode), SeccompAction::Allow, arch()?)
        .map_err(|e| err("seccomp filter", e))?
        .try_into()
        .map_err(|e: seccompiler::BackendError| err("seccomp program", e))
}

/// Socket creation and use: refused with `EPERM`, never killed.
const NETWORK: [i64; 5] = [
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
];

fn eperm_program() -> Result<BpfProgram, SandboxError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for nr in NETWORK {
        rules.insert(nr, vec![]);
    }
    SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch()?,
    )
    .map_err(|e| err("seccomp filter", e))?
    .try_into()
    .map_err(|e: seccompiler::BackendError| err("seccomp program", e))
}

/// `clone3` answers `ENOSYS` (its flags are in a struct a filter cannot read; glibc and the Rust
/// runtime fall back to `clone`), everything else is left to [`program`].
fn enosys_program() -> Result<BpfProgram, SandboxError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    rules.insert(libc::SYS_clone3, vec![]);
    SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch()?,
    )
    .map_err(|e| err("seccomp filter", e))?
    .try_into()
    .map_err(|e: seccompiler::BackendError| err("seccomp program", e))
}

/// Installs the allowlist for `kind` on every thread of the process. Irreversible. The ENOSYS
/// program goes first: once the allowlist is in force, installing anything is forbidden.
///
/// # Errors
/// [`SandboxError`].
pub fn install_seccomp(kind: pb::JobKind, mode: Mode) -> Result<(), SandboxError> {
    let enosys = enosys_program()?;
    let eperm = eperm_program()?;
    let allow = program(kind, mode)?;
    seccompiler::apply_filter_all_threads(&enosys).map_err(|e| err("seccomp", e))?;
    seccompiler::apply_filter_all_threads(&eperm).map_err(|e| err("seccomp", e))?;
    seccompiler::apply_filter_all_threads(&allow).map_err(|e| err("seccomp", e))
}

/// The second step of the sandbox (ipc.md §24): drop capabilities to the job kind's table, then
/// install its seccomp allowlist. Call it once, after the last secret has arrived and before any
/// other thread exists.
///
/// # Errors
/// [`SandboxError`]; the worker exits with 70 and the job never starts.
pub fn harden(kind: pb::JobKind, mode: Mode) -> Result<(), SandboxError> {
    drop_capabilities(capabilities_for(kind))?;
    install_seccomp(kind, mode)
}

// ----- the unsafe part -----

mod sys {
    use std::io;

    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct Data {
        pub effective: u32,
        pub permitted: u32,
        pub inheritable: u32,
    }

    const VERSION_3: u32 = 0x2008_0522;

    fn cvt(r: libc::c_long) -> io::Result<libc::c_long> {
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(r)
        }
    }

    pub fn capget() -> io::Result<[Data; 2]> {
        let mut header = Header {
            version: VERSION_3,
            pid: 0,
        };
        let mut data = [Data::default(); 2];
        // SAFETY: `header` and `data` are valid, properly laid out for `capget(2)` version 3
        // (one header, two data structs) and live for the call; pid 0 is the calling thread.
        cvt(unsafe { libc::syscall(libc::SYS_capget, &raw mut header, data.as_mut_ptr()) })?;
        Ok(data)
    }

    pub fn capset_to(effective: u64, permitted: u64, inheritable: u64) -> io::Result<()> {
        let mut header = Header {
            version: VERSION_3,
            pid: 0,
        };
        let split = |m: u64| (m as u32, (m >> 32) as u32);
        let (e0, e1) = split(effective);
        let (p0, p1) = split(permitted);
        let (i0, i1) = split(inheritable);
        let data = [
            Data {
                effective: e0,
                permitted: p0,
                inheritable: i0,
            },
            Data {
                effective: e1,
                permitted: p1,
                inheritable: i1,
            },
        ];
        // SAFETY: as `capget`; `data` is only read by the kernel.
        cvt(unsafe { libc::syscall(libc::SYS_capset, &raw mut header, data.as_ptr()) })?;
        Ok(())
    }

    pub fn bounding_drop(cap: u8) -> io::Result<()> {
        // SAFETY: `prctl(PR_CAPBSET_DROP, cap)` takes integers only.
        cvt(
            unsafe { libc::prctl(libc::PR_CAPBSET_DROP, libc::c_ulong::from(cap), 0, 0, 0) }.into(),
        )?;
        Ok(())
    }

    pub fn bounding_has(cap: u8) -> io::Result<bool> {
        // SAFETY: `prctl(PR_CAPBSET_READ, cap)` takes integers only.
        let r =
            cvt(
                unsafe { libc::prctl(libc::PR_CAPBSET_READ, libc::c_ulong::from(cap), 0, 0, 0) }
                    .into(),
            )?;
        Ok(r != 0)
    }

    pub fn ambient_clear() -> io::Result<()> {
        // SAFETY: `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)` takes integers only.
        let r = unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
                0,
                0,
                0,
            )
        };
        if r < 0 {
            let e = io::Error::last_os_error();
            // A kernel without ambient capabilities has none to clear.
            if e.raw_os_error() == Some(libc::EINVAL) {
                return Ok(());
            }
            return Err(e);
        }
        Ok(())
    }

    extern "C" fn on_sigterm(_: libc::c_int) {
        // SAFETY: `_exit` is async-signal-safe.
        unsafe { libc::_exit(143) }
    }

    pub fn install_signals() -> io::Result<()> {
        // SAFETY: `signal` with `SIG_IGN` and `sigaction` with a zeroed, then filled, struct and a
        // handler that only calls `_exit`; both take valid pointers for the duration of the call.
        unsafe {
            if libc::signal(libc::SIGCHLD, libc::SIG_IGN) == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_sigterm as extern "C" fn(libc::c_int) as usize;
            libc::sigemptyset(&raw mut sa.sa_mask);
            if libc::sigaction(libc::SIGTERM, &raw const sa, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb::JobKind as K;

    const KINDS: [K; 8] = [
        K::Init,
        K::Backup,
        K::Snapshots,
        K::RestorePlan,
        K::Restore,
        K::ForgetPrune,
        K::Check,
        K::Keys,
    ];

    #[test]
    fn the_filters_build_for_every_kind_and_never_allow_the_forbidden_calls() {
        for kind in KINDS {
            program(kind, Mode::Enforce).unwrap();
            program(kind, Mode::Errno).unwrap();
            let names = allowed_names(kind);
            for forbidden in [
                "SYS_socket",
                "SYS_connect",
                "SYS_bind",
                "SYS_listen",
                "SYS_accept4",
                "SYS_execve",
                "SYS_execveat",
                "SYS_fork",
                "SYS_vfork",
                "SYS_ptrace",
                "SYS_mount",
                "SYS_umount2",
                "SYS_setns",
                "SYS_unshare",
                "SYS_chroot",
                "SYS_pivot_root",
                "SYS_bpf",
                "SYS_process_vm_readv",
                "SYS_kill",
                "SYS_setuid",
                "SYS_capset",
                "SYS_seccomp",
            ] {
                assert!(!names.contains(&forbidden), "{kind:?} allows {forbidden}");
            }
        }
    }

    #[test]
    fn only_restore_can_write_the_file_system_or_an_extended_attribute() {
        for kind in KINDS {
            let names = allowed_names(kind);
            for w in [
                "SYS_setxattr",
                "SYS_lsetxattr",
                "SYS_fsetxattr",
                "SYS_removexattr",
                "SYS_mkdirat",
                "SYS_unlinkat",
                "SYS_fchownat",
                "SYS_utimensat",
                "SYS_ftruncate",
                "SYS_pwrite64",
            ] {
                assert_eq!(names.contains(&w), kind == K::Restore, "{kind:?} and {w}");
            }
        }
    }

    #[test]
    fn the_capability_table_is_the_contracts() {
        assert_eq!(capabilities_for(K::Backup), &[Cap::DacReadSearch]);
        assert_eq!(
            mask(capabilities_for(K::Restore)),
            1 << 0 | 1 << 1 | 1 << 3 | 1 << 4 | 1 << 27 | 1 << 31
        );
        for kind in [
            K::Init,
            K::Snapshots,
            K::RestorePlan,
            K::ForgetPrune,
            K::Check,
            K::Keys,
        ] {
            assert!(capabilities_for(kind).is_empty(), "{kind:?}");
        }
    }
}
