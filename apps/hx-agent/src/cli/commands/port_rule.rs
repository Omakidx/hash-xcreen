//! `port-rule apply`: re-applies the nftables accept rule for the agent's public port.
//!
//! Run by `hx-agent-port.service` after nftables loads its ruleset (a reload with
//! `flush ruleset` removes the rule). It reads the port and backend that the installer recorded in
//! `/var/lib/hx/install-state.json`; only the `nft` backend has anything to do (ufw keeps its own
//! rules, and the other backends are manual or none). Idempotent: it removes a rule of ours for
//! another port and adds nothing if the rule is in place. Tools run through the installer's closed
//! tool set, with a cleared environment.

use serde_json::json;

use crate::cli::error::CliError;
use crate::cli::{Env, Outcome};
use crate::install::paths::{self, Paths};
use crate::install::runner::{DenyRunner, RealRunner, Runner};
use crate::install::stages::port;
use crate::install::state;

pub(super) fn run(env: &mut Env<'_>) -> Result<Outcome, CliError> {
    let production = crate::install::is_production(&env.config);
    let p = if production {
        Paths::system()
    } else {
        Paths::under(crate::install::dev_root(&env.config))
    };
    let st = state::load(&p.at(paths::STATE_FILE))
        .map_err(|e| CliError::failed(format!("cannot read the install state: {e}")))?
        .ok_or_else(|| CliError::failed("there is no install state: nothing to apply"))?;
    let Some(rec) = st.created.port_rule else {
        return Ok(Outcome::ok(
            "no port rule was recorded; nothing to do\n",
            json!({"applied": false, "backend": "none"}),
        ));
    };
    if rec.backend != "nft" {
        return Ok(Outcome::ok(
            format!(
                "the port rule backend is {}; nothing to re-apply\n",
                rec.backend
            ),
            json!({"applied": false, "backend": rec.backend}),
        ));
    }
    let mut real = RealRunner;
    let mut deny = DenyRunner;
    let runner: &mut dyn Runner = if production { &mut real } else { &mut deny };
    let present = port::apply_nft(runner, rec.port)?;
    Ok(Outcome::ok(
        if present {
            format!("the nftables rule for port {} is in place\n", rec.port)
        } else {
            "no input chain blocks traffic now; nothing to add\n".to_owned()
        },
        json!({"applied": present, "backend": "nft", "port": rec.port}),
    ))
}
