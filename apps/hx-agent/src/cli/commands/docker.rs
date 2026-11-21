//! `docker enable | disable`.
//!
//! Calls: privd `EnableDocker` (class S: Admin only once setup is over) and `DisableDocker`.
//! Enabling lowers the container's isolation, so it asks for a typed confirmation (or `--yes`)
//! and sends `acknowledged_isolation_warning` only after getting it. The `DockerOutcome` is a
//! normal answer, not an error; all text in it (the hint, the output tail) came out of the
//! container and is sanitized.

use hx_ipc::privd::pb::{self, request::Command, response::Result as R};
use serde_json::json;

use super::{confirm, enum_name, privd, progress_printer};
use crate::cli::error::{CliError, exit};
use crate::cli::privd::unexpected;
use crate::cli::text::peer;
use crate::cli::{Env, Outcome};

const ISOLATION_WARNING: &str = "Docker inside the desktop needs container nesting and syscall interception. \
That LOWERS the isolation between the desktop and this host: anyone who controls the desktop user's session \
has a much larger attack surface (a user in the docker group is root inside the desktop). Enable it only if \
you accept that. It is also not what a default install does.";

fn fallbacks(f: &[i32]) -> Vec<&'static str> {
    f.iter()
        .map(|x| enum_name!(pb::DockerFallback, *x, "DOCKER_FALLBACK_"))
        .collect()
}

pub(super) fn enable(env: &mut Env<'_>, id: &str, yes: bool) -> Result<Outcome, CliError> {
    confirm(env, ISOLATION_WARNING, "yes", yes)?;
    let mut p = privd(env)?;
    let json_mode = env.json;
    let mut progress = progress_printer(json_mode, env.err);
    let outcome = match p.call(
        Command::EnableDocker(pb::EnableDockerRequest {
            desktop_id: id.to_owned(),
            acknowledged_isolation_warning: true,
            mode: pb::DockerMode::Standard as i32,
        }),
        &[],
        &mut progress,
    )? {
        R::EnableDocker(r) => r.outcome.unwrap_or_default(),
        _ => return Err(unexpected("EnableDocker")),
    };
    use pb::docker_outcome::Outcome as O;
    match outcome.outcome {
        Some(O::Enabled(e)) => {
            let v = peer(&e.docker_version, 64);
            Ok(Outcome::ok(
                format!("Docker {v} is enabled in desktop {id}\n"),
                json!({"desktop": id, "outcome": "ENABLED", "docker_version": v}),
            ))
        }
        Some(O::UnsupportedIncus(u)) => {
            let fb = fallbacks(&u.fallbacks);
            Ok(Outcome {
                text: format!(
                    "Docker was NOT enabled: Incus {} is older than the {} that is required. Nothing was changed.\nfallbacks: {}\n",
                    peer(&u.found, 32),
                    peer(&u.required, 32),
                    if fb.is_empty() {
                        "none".into()
                    } else {
                        fb.join(", ").to_lowercase()
                    }
                ),
                data: json!({
                    "desktop": id,
                    "outcome": "UNSUPPORTED_INCUS",
                    "found": peer(&u.found, 32),
                    "required": peer(&u.required, 32),
                    "fallbacks": fb,
                }),
                exit: exit::REFUSED,
            })
        }
        Some(O::SelfTestFailed(f)) => {
            let fb = fallbacks(&f.fallbacks);
            let mut text = format!(
                "Docker was NOT enabled: its self-test failed.\nhint: {}\n",
                peer(&f.hint, 512)
            );
            let tail = peer(&f.output_tail, 2048);
            if !tail.is_empty() {
                text.push_str(&format!("output (from the container, untrusted): {tail}\n"));
            }
            if f.isolation_restored {
                text.push_str("the desktop's isolation was restored\n");
            } else {
                text.push_str(
                    "WARNING: the isolation was NOT restored. privd has stopped the desktop and refuses to let the gateway start it; run: hx-agent desktop start (it retries the rollback)\n",
                );
            }
            Ok(Outcome {
                text,
                data: json!({
                    "desktop": id,
                    "outcome": "SELF_TEST_FAILED",
                    "isolation_restored": f.isolation_restored,
                    "hint": peer(&f.hint, 512),
                    "output_tail": tail,
                    "fallbacks": fb,
                }),
                exit: exit::FAILED,
            })
        }
        None => Err(CliError::failed("hx-privd sent an empty Docker outcome")),
    }
}

pub(super) fn disable(env: &mut Env<'_>, id: &str) -> Result<Outcome, CliError> {
    let mut p = privd(env)?;
    let restarted = match p.simple(Command::DisableDocker(pb::DisableDockerRequest {
        desktop_id: id.to_owned(),
    }))? {
        R::DisableDocker(r) => r.restarted,
        _ => return Err(unexpected("DisableDocker")),
    };
    Ok(Outcome::ok(
        format!(
            "Docker is disabled in desktop {id}{}\n",
            if restarted {
                "; the desktop was restarted, so its open applications closed"
            } else {
                ""
            }
        ),
        json!({"desktop": id, "docker": "OFF", "restarted": restarted}),
    ))
}
