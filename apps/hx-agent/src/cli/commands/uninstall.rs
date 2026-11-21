//! `uninstall`: the guided front end of the uninstall (`docs/ipc.md` 6.13, design D6).
//!
//! The flow asks whether to keep the desktop (never defaulting to deleting it), asks for a typed
//! confirmation, then runs [`crate::install::uninstall`]: privd's `Uninstall` removes what privd
//! created, and the CLI removes the rest (units, files, the port rule, the `hx-gatewayd` user) in
//! the order U1 to U8. Where privd answers `UNIMPLEMENTED` (an old privd), or cannot be reached
//! and cannot be started, the CLI prints the manual steps instead and exits 6. **In that case the
//! CLI does not run those steps itself**: they are text for the operator to read and run.
//!
//! A non-production configuration (sockets elsewhere than `/run/hx`, as in the tests) works in a
//! directory next to its sockets and runs no host-level command.

use std::cell::RefCell;

use serde_json::json;

use super::confirm;
use crate::cli::error::{CliError, exit};
use crate::cli::privd::ProgressLine;
use crate::cli::text::scrub_output;
use crate::cli::{Env, Outcome};
use crate::install::daemons::SocketDaemons;
use crate::install::error::InstallError;
use crate::install::paths::Paths;
use crate::install::runner::{DenyRunner, RealRunner, Runner};
use crate::install::uninstall::{self as engine, SelfExecCleaner, UninstallDeps, UninstallError};

/// The manual steps, as lines of text. Unit names are those of `apps/hx-agent/systemd`, object
/// names those of `Naming::production()` and desktop id `main`.
pub fn manual_steps(keep_desktop: bool) -> Vec<String> {
    let mut s: Vec<String> = vec![
        "1. Stop and disable the agent units:".into(),
        "     systemctl disable --now hx-gatewayd.service hx-gatewayd-admin.socket hx-gatewayd-public.socket hx-privd.service hx-privd.socket".into(),
        "2. Remove the unit files the installer wrote for them (/usr/local/lib/systemd/system/hx-*), the sysusers and tmpfiles snippets and the logrotate snippet (hx-audit), then: systemctl daemon-reload".into(),
    ];
    if keep_desktop {
        s.push("3. Remove the agent's files and data (this does not touch the desktop):".into());
        s.push(
            "     rm -rf /usr/lib/hx /usr/lib/hx-rescue /var/lib/hx /var/lib/hx-gatewayd /var/log/hx /run/hx".into(),
        );
        s.push("     rm -rf /etc/hx/gatewayd.toml /etc/hx/privd.toml /etc/hx/creds   (keep /etc/hx/host-firewall.nft: it still protects the desktop)".into());
        s.push("4. Optionally remove the proxy device that links the agent to the desktop:".into());
        s.push("     incus config device remove hx-main hx-link".into());
        s.push("5. The desktop, its pool (hx-pool), bridge (hxbr0), ACL (hx-isolate), profiles, the host firewall unit (hx-host-firewall.service) and the sysctl file (/etc/sysctl.d/90-hx-incus.conf) stay. To remove them later, follow the steps for deleting the desktop below.".into());
    } else {
        s.push("3. DELETE THE DESKTOP AND ITS DATA (permanent):".into());
        s.push("     incus delete --force hx-main".into());
        s.push("4. Remove the objects hash-xcreen created in Incus (check each is ours before deleting):".into());
        s.push(
            "     incus profile delete hx-desktop; incus profile delete hx-compat-debian13".into(),
        );
        s.push("     incus network delete hxbr0; incus network acl delete hx-isolate".into());
        s.push("     incus storage delete hx-pool".into());
        s.push("5. Remove the host firewall table and units, and the sysctl file:".into());
        s.push("     systemctl disable --now hx-host-firewall.service hx-docker-user.service; nft delete table inet hx".into());
        s.push("     rm -f /etc/hx/host-firewall.nft /etc/sysctl.d/90-hx-incus.conf".into());
        s.push("6. Remove the agent's files and data:".into());
        s.push(
            "     rm -rf /usr/lib/hx /usr/lib/hx-rescue /var/lib/hx /var/lib/hx-gatewayd /var/log/hx /run/hx /etc/hx"
                .into(),
        );
    }
    s.push("7. The port rule the installer added (ufw: ufw delete allow <port>/tcp and /udp; nftables: delete the rule with the comment hx-agent-port; disable hx-agent-port.service) and the gateway user: userdel hx-gatewayd".into());
    s.push(
        "Incus itself (and the Zabbly repository, if the installer added it) is left alone.".into(),
    );
    s
}

fn manual_outcome(keep_desktop: bool, why: &str, implemented: bool) -> Outcome {
    let steps = manual_steps(keep_desktop);
    let mut text = format!(
        "{why} Nothing was changed.\nDo it by hand, as root, reading each step first (hx-agent runs none of these):\n"
    );
    for l in &steps {
        text.push_str(l);
        text.push('\n');
    }
    Outcome {
        text,
        data: json!({
            "uninstalled": false,
            "implemented": implemented,
            "keep_desktop": keep_desktop,
            "manual_steps": steps,
        }),
        exit: exit::UNIMPLEMENTED,
    }
}

pub(super) fn run(
    env: &mut Env<'_>,
    keep_flag: Option<bool>,
    yes: bool,
) -> Result<Outcome, CliError> {
    let keep_desktop = match keep_flag {
        Some(k) => k,
        None if yes => {
            return Err(CliError::Usage(
                "--yes needs --keep-desktop or --destroy-desktop: deleting a desktop is never the default".into(),
            ));
        }
        None => {
            let a = env
                .prompt
                .line("Uninstall the hash-xcreen agent. Keep the desktop and its data? [Y/n]: ")?;
            !matches!(a.to_ascii_lowercase().as_str(), "n" | "no")
        }
    };
    if keep_desktop {
        confirm(
            env,
            "This removes the agent: its units, sockets, binaries, credentials, device registry and the port rule. The desktop, its data, the host firewall and the sysctl file stay, so the desktop keeps running but nothing can connect to it any more.",
            "uninstall",
            yes,
        )?;
    } else {
        confirm(
            env,
            "This removes the agent AND PERMANENTLY DELETES the desktop, all its snapshots and everything in it, then the pool, network and firewall objects hash-xcreen created. It cannot be undone.",
            "destroy",
            yes,
        )?;
    }

    let production = crate::install::is_production(&env.config);
    let paths = if production {
        Paths::system()
    } else {
        Paths::under(crate::install::dev_root(&env.config))
    };
    let mut real = RealRunner;
    let mut deny = DenyRunner;
    let runner: &mut dyn Runner = if production { &mut real } else { &mut deny };
    let mut daemons = SocketDaemons {
        privd_socket: env.config.privd_socket.clone(),
        admin_socket: env.config.admin_socket.clone(),
        expected_uid: env.config.expected_peer_uid,
    };
    let mut cleaner = SelfExecCleaner::new();
    let json_mode = env.json;
    let euid = env.euid;
    let now = env.now;
    let err = RefCell::new(&mut *env.err);
    let mut on_progress = |p: &ProgressLine| {
        if json_mode {
            return;
        }
        let pct = p.percent.map(|x| format!(" {x}%")).unwrap_or_default();
        let line = format!(
            "  [{}] {}/{}{} {}\n",
            p.stage.to_lowercase(),
            p.index,
            p.total,
            pct,
            p.step
        );
        let _ = err.borrow_mut().write_all(scrub_output(&line).as_bytes());
    };
    let mut say = |s: &str| {
        if !json_mode {
            let _ = err.borrow_mut().write_all(scrub_output(s).as_bytes());
        }
    };
    let result = engine::run(
        keep_desktop,
        UninstallDeps {
            paths,
            runner,
            daemons: &mut daemons,
            cleaner: &mut cleaner,
            now,
            sleep: std::thread::sleep,
            host: production,
            euid,
        },
        &mut on_progress,
        &mut say,
    );
    match result {
        Ok(r) => {
            let mut text = format!(
                "the agent is uninstalled{}\n",
                if keep_desktop {
                    "; the desktop, its pool and the host firewall were kept"
                } else {
                    "; the desktop and its objects were deleted"
                }
            );
            for n in r.notes.iter().chain(r.summary.warnings.iter()) {
                text.push_str(n);
                text.push('\n');
            }
            Ok(Outcome::ok(
                text,
                json!({
                    "uninstalled": true,
                    "keep_desktop": keep_desktop,
                    "removed": r.summary.removed,
                    "kept": r.summary.kept,
                    "warnings": r.summary.warnings,
                    "steps": r.ran,
                    "notes": r.notes,
                }),
            ))
        }
        Err(UninstallError::Unimplemented) => Ok(manual_outcome(
            keep_desktop,
            "this release of hx-privd cannot uninstall by itself yet (Uninstall is not implemented).",
            false,
        )),
        Err(UninstallError::PrivdUnreachable) => Ok(manual_outcome(
            keep_desktop,
            "hx-privd cannot be reached and could not be started, so its part of the uninstall cannot be done by it.",
            true,
        )),
        Err(UninstallError::Failed(e)) => outcome_for_error(e, keep_desktop),
    }
}

/// The lock (11) and conflict (12) refusals are results with their own exit codes; everything
/// else is an ordinary CLI error.
fn outcome_for_error(e: InstallError, keep_desktop: bool) -> Result<Outcome, CliError> {
    use crate::install::error::codes;
    if matches!(e.exit, codes::LOCKED | codes::CONFLICT) {
        return Ok(Outcome {
            text: format!("{}\n", e.message),
            data: json!({
                "uninstalled": false,
                "keep_desktop": keep_desktop,
                "error": {"code": e.code.name(), "message": e.message},
            }),
            exit: e.exit,
        });
    }
    Err(match e.exit {
        exit::USAGE => CliError::Usage(e.message),
        exit::UNAVAILABLE => CliError::Unavailable(e.message),
        exit::NOT_ROOT => CliError::NotRoot,
        exit::UNIMPLEMENTED => CliError::Unimplemented(e.message),
        _ => CliError::Failed(e.message),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manual_steps_say_what_survives() {
        let keep = manual_steps(true).join("\n");
        assert!(keep.contains("hx-main hx-link"));
        assert!(
            !keep.contains("incus delete --force"),
            "keep must never delete the desktop"
        );
        assert!(keep.contains("host-firewall.nft: it still protects"));
        let all = manual_steps(false).join("\n");
        assert!(all.contains("incus delete --force hx-main"));
        assert!(all.contains("nft delete table inet hx"));
    }
}
