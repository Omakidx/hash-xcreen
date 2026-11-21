//! Process hardening required by ipc.md 5.2: no core dumps, not ptrace-able or readable through
//! `/proc/<pid>/mem`, and no swap.
//!
//! All three are safe calls in `rustix`; no `unsafe` is needed.

use std::io;

use rustix::mm::{MlockAllFlags, mlockall};
use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};

/// `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0`: a crash writes no core and an unprivileged process
/// cannot read this process's memory. Called before anything holds a secret.
pub fn disable_dumps() -> io::Result<()> {
    set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    Ok(())
}

/// `mlockall(MCL_CURRENT | MCL_FUTURE)`: nothing this process holds is ever swapped out. The unit
/// sets `LimitMEMLOCK=infinity`. A failure is fatal for the daemon (ipc.md 5.2): a secret that
/// could reach swap is worse than not running.
pub fn lock_memory() -> io::Result<()> {
    mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE)?;
    Ok(())
}

/// Applies everything; the daemon binary calls this first and exits on error.
pub fn apply() -> io::Result<()> {
    disable_dumps()?;
    lock_memory()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::process::{dumpable_behavior, getrlimit};

    #[test]
    fn dumps_are_disabled() {
        // Each nextest test runs in its own process, so changing these is harmless.
        disable_dumps().unwrap();
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
        let r = getrlimit(Resource::Core);
        assert_eq!((r.current, r.maximum), (Some(0), Some(0)));
    }
}
