//! Process hardening for `hx-gatewayd` (`docs/ipc.md` section 5.2 rule 4, architecture 8.5).
//!
//! Applied by the binary **after** start-up has opened everything that needs it (the public
//! sockets, the admin socket, the registry, the identity key), and before the first connection
//! is accepted:
//!
//! 1. [`process_limits`]: `PR_SET_DUMPABLE=0` (an unprivileged process cannot ptrace it or read
//!    its memory, and a crash writes no core), `RLIMIT_CORE=0`, and `mlockall(MCL_CURRENT |
//!    MCL_FUTURE)` so that nothing, a PIN in a decoder buffer included, is ever swapped. A
//!    failed lock is fatal; the unit sets `LimitMEMLOCK=infinity`.
//! 2. [`install_seccomp`]: a seccomp **allowlist** installed with `seccompiler` on every thread
//!    (`TSYNC`), `NO_NEW_PRIVS` set. A syscall outside the list kills the process
//!    (`mode = enforce`) or is logged (`mode = log`, for finding a missing entry in a new build
//!    without a crash loop). The unit adds a systemd `SystemCallFilter` as a second layer.
//! 3. [`install_panic_hook`]: a panic prints its location only, never its payload (which could
//!    hold a secret that an `unwrap` formatted).
//!
//! # The allowlist
//!
//! What a running gateway needs, derived from the syscalls an `strace -f` of the end-to-end
//! scenario shows (QUIC and WebSocket traffic, pairing, PIN login with Argon2id, privd and
//! admin sockets, registry writes) plus the runtime's housekeeping:
//!
//! | Group | Syscalls |
//! |---|---|
//! | memory | `brk mmap munmap mremap mprotect madvise` |
//! | threads, signals | `clone clone3 futex set_robust_list rseq sigaltstack rt_sigaction rt_sigprocmask rt_sigreturn prctl exit exit_group gettid tgkill sched_yield sched_getaffinity arch_prctl (x86_64)` |
//! | time, randomness | `clock_gettime clock_getres gettimeofday nanosleep clock_nanosleep getrandom` |
//! | descriptors | `read write readv writev pread64 pwrite64 close lseek dup dup3 fcntl pipe2 eventfd2 epoll_create1 epoll_ctl epoll_wait epoll_pwait poll ppoll ioctl` (**only** `FIONBIO FIONREAD FIOCLEX FIONCLEX`) |
//! | sockets | `socket` (**only** `AF_UNIX AF_INET AF_INET6`), `socketpair` (**only** `AF_UNIX`), `connect accept4 shutdown getsockname getpeername getsockopt setsockopt sendto recvfrom sendmsg recvmsg sendmmsg recvmmsg` |
//! | files (registry, verifiers) | `openat fstat newfstatat statx fsync fdatasync fchmod unlinkat renameat renameat2 flock readlinkat access faccessat faccessat2 ftruncate fallocate getdents64` |
//! | identity, limits | `getuid geteuid getgid getegid getpid getrlimit prlimit64 uname` |
//!
//! Deliberately **absent**: `execve execveat fork vfork ptrace mount umount2 setuid setgid
//! setns unshare chroot pivot_root bpf kexec_load init_module finit_module open_by_handle_at
//! process_vm_readv process_vm_writev perf_event_open keyctl socket families other than the
//! three above`, and every call that creates a listening socket after start-up (`bind` and
//! `listen`). The gateway never spawns a process.

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::collections::BTreeMap;

use super::config::SeccompMode;

/// Why hardening failed.
#[derive(Debug, thiserror::Error)]
pub enum HardenError {
    /// A process limit or `mlockall` failed.
    #[error("{0}")]
    Limits(String),
    /// The seccomp filter could not be built or installed.
    #[error("seccomp: {0}")]
    Seccomp(String),
}

/// No core dumps, not ptrace-able, and (if `mlock`) all memory locked (ipc.md 5.2).
pub fn process_limits(mlock: bool) -> Result<(), HardenError> {
    use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|e| HardenError::Limits(format!("PR_SET_DUMPABLE: {e}")))?;
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|e| HardenError::Limits(format!("RLIMIT_CORE: {e}")))?;
    if mlock {
        use rustix::mm::{MlockAllFlags, mlockall};
        mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE)
            .map_err(|e| HardenError::Limits(format!("mlockall (LimitMEMLOCK too low?): {e}")))?;
    }
    Ok(())
}

/// Replaces the panic hook with one that prints only where the panic happened.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".into());
        // Not the payload: it may contain text derived from a secret.
        tracing::error!(location = %loc, "panic (message withheld)");
    }));
}

macro_rules! syscalls {
    ($($name:ident),* $(,)?) => { [$((libc::$name, stringify!($name))),*] };
}

/// Syscalls allowed without argument checks, by number and name.
fn plain() -> Vec<(i64, &'static str)> {
    let mut v: Vec<(i64, &'static str)> = Vec::new();
    v.extend(syscalls![
        SYS_brk,
        SYS_mmap,
        SYS_munmap,
        SYS_mremap,
        SYS_mprotect,
        SYS_madvise,
        SYS_clone,
        SYS_clone3,
        SYS_futex,
        SYS_set_robust_list,
        SYS_rseq,
        SYS_sigaltstack,
        SYS_rt_sigaction,
        SYS_rt_sigprocmask,
        SYS_rt_sigreturn,
        SYS_prctl,
        SYS_exit,
        SYS_exit_group,
        SYS_gettid,
        SYS_tgkill,
        SYS_sched_yield,
        SYS_sched_getaffinity,
        SYS_clock_gettime,
        SYS_clock_getres,
        SYS_gettimeofday,
        SYS_nanosleep,
        SYS_clock_nanosleep,
        SYS_getrandom,
        SYS_read,
        SYS_write,
        SYS_readv,
        SYS_writev,
        SYS_pread64,
        SYS_pwrite64,
        SYS_close,
        SYS_lseek,
        SYS_dup,
        SYS_dup3,
        SYS_fcntl,
        SYS_pipe2,
        SYS_eventfd2,
        SYS_epoll_create1,
        SYS_epoll_ctl,
        SYS_epoll_pwait,
        SYS_ppoll,
        SYS_connect,
        SYS_accept4,
        SYS_shutdown,
        SYS_getsockname,
        SYS_getpeername,
        SYS_getsockopt,
        SYS_setsockopt,
        SYS_sendto,
        SYS_recvfrom,
        SYS_sendmsg,
        SYS_recvmsg,
        SYS_sendmmsg,
        SYS_recvmmsg,
        SYS_openat,
        SYS_fstat,
        SYS_newfstatat,
        SYS_statx,
        SYS_fsync,
        SYS_fdatasync,
        SYS_fchmod,
        SYS_unlinkat,
        SYS_renameat,
        SYS_renameat2,
        SYS_flock,
        SYS_readlinkat,
        SYS_faccessat,
        SYS_faccessat2,
        SYS_ftruncate,
        SYS_fallocate,
        SYS_getdents64,
        SYS_getuid,
        SYS_geteuid,
        SYS_getgid,
        SYS_getegid,
        SYS_getpid,
        SYS_prlimit64,
        SYS_uname,
    ]);
    // Legacy calls that exist only on x86_64 (aarch64 has the `*at` forms only).
    #[cfg(target_arch = "x86_64")]
    v.extend(syscalls![
        SYS_arch_prctl,
        SYS_epoll_wait,
        SYS_poll,
        SYS_access,
        SYS_getrlimit,
    ]);
    #[cfg(not(target_arch = "x86_64"))]
    v.extend(syscalls![SYS_getrlimit]);
    v
}

/// Names of every syscall the filter allows (for the documentation and tests).
pub fn allowed_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = plain().into_iter().map(|(_, n)| n).collect();
    names.extend(["SYS_ioctl", "SYS_socket", "SYS_socketpair"]);
    names.sort_unstable();
    names
}

fn eq(arg: u8, value: u64) -> Result<SeccompRule, HardenError> {
    SeccompCondition::new(arg, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, value)
        .and_then(|c| SeccompRule::new(vec![c]))
        .map_err(|e| HardenError::Seccomp(e.to_string()))
}

/// Builds the BPF program of the allowlist for `mode`.
pub fn build_filter(mode: SeccompMode) -> Result<BpfProgram, HardenError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for (nr, _) in plain() {
        rules.insert(nr, vec![]);
    }
    // ioctl: only the non-blocking, close-on-exec and readable-bytes requests tokio and std use.
    const FIONBIO: u64 = 0x5421;
    const FIONREAD: u64 = 0x541B;
    const FIOCLEX: u64 = 0x5451;
    const FIONCLEX: u64 = 0x5450;
    rules.insert(
        libc::SYS_ioctl,
        vec![eq(1, FIONBIO)?, eq(1, FIONREAD)?, eq(1, FIOCLEX)?, eq(1, FIONCLEX)?],
    );
    // socket: only the three families the unit's RestrictAddressFamilies allows.
    rules.insert(
        libc::SYS_socket,
        vec![
            eq(0, libc::AF_UNIX as u64)?,
            eq(0, libc::AF_INET as u64)?,
            eq(0, libc::AF_INET6 as u64)?,
        ],
    );
    // socketpair: tokio's signal handling and wake-ups; unix sockets only.
    rules.insert(libc::SYS_socketpair, vec![eq(0, libc::AF_UNIX as u64)?]);
    let arch = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|e| HardenError::Seccomp(format!("unsupported architecture: {e}")))?;
    let mismatch = match mode {
        SeccompMode::Enforce => SeccompAction::KillProcess,
        SeccompMode::Log => SeccompAction::Log,
    };
    let filter = SeccompFilter::new(rules, mismatch, SeccompAction::Allow, arch)
        .map_err(|e| HardenError::Seccomp(e.to_string()))?;
    filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| HardenError::Seccomp(e.to_string()))
}

/// Installs the allowlist on every thread of the process (`TSYNC`). Irreversible.
pub fn install_seccomp(mode: SeccompMode) -> Result<(), HardenError> {
    let program = build_filter(mode)?;
    seccompiler::apply_filter_all_threads(&program)
        .map_err(|e| HardenError::Seccomp(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filter_builds_and_never_lists_dangerous_calls() {
        build_filter(SeccompMode::Enforce).unwrap();
        build_filter(SeccompMode::Log).unwrap();
        let names = allowed_names();
        for forbidden in [
            "SYS_execve",
            "SYS_execveat",
            "SYS_fork",
            "SYS_vfork",
            "SYS_ptrace",
            "SYS_mount",
            "SYS_setuid",
            "SYS_bind",
            "SYS_listen",
            "SYS_bpf",
            "SYS_unshare",
            "SYS_process_vm_readv",
        ] {
            assert!(!names.contains(&forbidden), "{forbidden} must not be allowed");
        }
        let mut sorted = names.clone();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "no duplicate entries");
    }
}
