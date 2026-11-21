//! The stage table (design D3): ids in order, what each applies to, and its done-check and run.
//!
//! A stage is **skipped** only when the state records it as finished *and* its done-check still
//! passes; otherwise it converges. Three stages are never skipped on resume, because a token or a
//! code must be fresh: `pairing-token`, `pairing` and `finish`. `setup-window`'s and `host`'s
//! checks always send the command to privd, which converges.

pub mod creds;
pub mod files;
pub mod incus;
pub mod packages;
pub mod port;
pub mod release;
pub mod setup;

use super::ctx::Ctx;
use super::error::Result;
use super::options::Mode;
use super::preflight;

/// How a stage ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Done.
    Done,
    /// Done, but a step is left to the operator (`firewall-port` on firewalld or iptables).
    Manual,
    /// Recorded for later (`backup`).
    Deferred,
    /// Nothing to do for this run.
    Skipped,
}

/// One row of the table.
pub struct Stage {
    /// The id.
    pub id: &'static str,
    /// Runs in this mode.
    pub applies: fn(Mode) -> bool,
    /// Never skipped on resume.
    pub always: bool,
    /// The done-check (`true`: nothing to do).
    pub check: fn(&mut Ctx<'_>) -> Result<bool>,
    /// The work.
    pub run: fn(&mut Ctx<'_>) -> Result<Outcome>,
}

fn all(_: Mode) -> bool {
    true
}
fn builds(m: Mode) -> bool {
    m.builds_desktop()
}
fn one_liner(m: Mode) -> bool {
    matches!(m, Mode::Pair | Mode::Token)
}
fn never(_: &mut Ctx<'_>) -> Result<bool> {
    Ok(false)
}
fn finished(_: &mut Ctx<'_>) -> Result<bool> {
    Ok(true)
}

fn preflight_run(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    preflight::host_checks(ctx)?;
    if ctx.mode == Mode::Interactive && !ctx.gathered {
        crate::install::interactive::gather(ctx)?;
    }
    if ctx.mode == Mode::Pair && ctx.secrets.token.is_none() {
        crate::install::interactive::ask_token(ctx)?;
    }
    preflight::option_checks(ctx)?;
    Ok(Outcome::Done)
}

/// `owner-key` is skipped on resume unless the app sent a key this time and none was enrolled.
fn owner_key_check(ctx: &mut Ctx<'_>) -> Result<bool> {
    Ok(ctx.secrets.owner_key.is_none() || ctx.state.is_done("owner-key"))
}

fn done_run(_: &mut Ctx<'_>) -> Result<Outcome> {
    Ok(Outcome::Done)
}

/// The stages, in order. [`crate::install::state::STAGES`] lists the same ids.
pub const TABLE: &[Stage] = &[
    Stage {
        id: "preflight",
        applies: all,
        always: true,
        check: never,
        run: preflight_run,
    },
    Stage {
        id: "packages",
        applies: all,
        always: false,
        check: packages::check,
        run: packages::run,
    },
    Stage {
        id: "incus",
        applies: all,
        always: false,
        check: incus::check,
        run: incus::run,
    },
    Stage {
        id: "release",
        applies: all,
        always: false,
        check: release::check,
        run: release::run,
    },
    Stage {
        id: "system-files",
        applies: all,
        always: false,
        check: files::system_files_check,
        run: files::system_files_run,
    },
    Stage {
        id: "credentials",
        applies: all,
        always: false,
        check: creds::check,
        run: creds::run,
    },
    Stage {
        id: "config",
        applies: all,
        always: false,
        check: files::config_check,
        run: files::config_run,
    },
    Stage {
        id: "units",
        applies: all,
        always: false,
        check: files::units_check,
        run: files::units_run,
    },
    Stage {
        id: "setup-window",
        applies: all,
        always: false,
        check: setup::window_check,
        run: setup::window_run,
    },
    Stage {
        id: "host",
        applies: all,
        // SetupHost converges in privd: it is sent on every run.
        always: true,
        check: never,
        run: setup::host_run,
    },
    Stage {
        id: "firewall-port",
        applies: all,
        always: false,
        check: port::check,
        run: port::run_stage,
    },
    Stage {
        id: "pairing-token",
        applies: one_liner,
        always: true,
        check: never,
        run: setup::token_run,
    },
    Stage {
        id: "desktop",
        applies: builds,
        always: false,
        check: setup::desktop_check,
        run: setup::desktop_run,
    },
    Stage {
        id: "verifiers",
        applies: builds,
        always: false,
        check: finished,
        run: setup::verifiers_run,
    },
    Stage {
        id: "owner-key",
        applies: builds,
        always: false,
        check: owner_key_check,
        run: setup::owner_key_run,
    },
    Stage {
        id: "backup",
        applies: all,
        always: true,
        check: never,
        run: setup::backup_run,
    },
    Stage {
        id: "pairing",
        applies: builds,
        always: true,
        check: never,
        run: setup::pairing_run,
    },
    Stage {
        id: "finish",
        applies: builds,
        always: true,
        check: never,
        run: setup::finish_run,
    },
    Stage {
        id: "done",
        applies: all,
        always: true,
        check: never,
        run: done_run,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_matches_the_documented_stage_ids() {
        let ids: Vec<&str> = TABLE.iter().map(|s| s.id).collect();
        assert_eq!(ids, crate::install::state::STAGES);
    }

    #[test]
    fn pairing_token_pairing_and_finish_are_never_skipped_on_resume() {
        for id in ["pairing-token", "pairing", "finish"] {
            assert!(TABLE.iter().find(|s| s.id == id).unwrap().always, "{id}");
        }
    }

    #[test]
    fn the_one_liner_modes_stop_after_the_token() {
        for m in [Mode::Pair, Mode::Token] {
            let ran: Vec<&str> = TABLE
                .iter()
                .filter(|s| (s.applies)(m))
                .map(|s| s.id)
                .collect();
            assert!(ran.contains(&"pairing-token"));
            for id in ["desktop", "verifiers", "owner-key", "pairing", "finish"] {
                assert!(!ran.contains(&id), "{m:?} must not run {id}");
            }
        }
        for m in [Mode::Ssh, Mode::Interactive] {
            let ran: Vec<&str> = TABLE
                .iter()
                .filter(|s| (s.applies)(m))
                .map(|s| s.id)
                .collect();
            assert!(!ran.contains(&"pairing-token"));
            assert!(ran.contains(&"desktop") && ran.contains(&"finish"));
        }
    }
}
