//! The stage engine (design D3): runs [`stages::TABLE`] in order, skips what is done and still
//! holds, converges the rest, saves the state after every stage, and reports in C3 form.
//!
//! * A stage that **fails** is recorded (`failed`, a code, a sanitized message, `retryable`), a
//!   `result` line is written, and the exit code is the failure's. The next run of the same
//!   command resumes there: completed stages are skipped after their done-check passes.
//! * A failing **preflight** records nothing (nothing was changed).
//! * `--test-fail-after <stage>` (feature `install-test-hooks`) stops with exit 1 after that stage
//!   has finished, to test resume at every stage.

use super::ctx::Ctx;
use super::error::InstallError;
use super::progress::ResultOk;
use super::stages::{self, Outcome, TABLE};
use super::state::StageError;

fn fail(ctx: &mut Ctx<'_>, id: &str, n: usize, of: usize, ms: u64, e: &InstallError) -> u8 {
    let now = (ctx.now)();
    if id != "preflight" {
        ctx.state.record(
            id,
            "failed",
            now,
            Some(StageError {
                code: e.code.name().to_owned(),
                message: e.message.clone(),
                retryable: e.retryable,
            }),
        );
        ctx.state.complete = false;
        let _ = ctx.save_state();
    }
    ctx.log.line(
        now,
        &format!("stage {id} failed: {} {}", e.code.name(), e.message),
    );
    ctx.progress.stage(id, n, of, "fail", ms);
    let human = if id == "preflight" || e.code == super::error::Code::Usage {
        format!("hx-agent: error: {}\n", e.message)
    } else {
        format!(
            "hx-agent: stage '{id}' failed: {}; run the same command again; completed stages are skipped\n",
            e.message
        )
    };
    ctx.progress.human(&human);
    ctx.progress
        .result_err(e.exit, id, e.code.name(), &e.message, e.retryable);
    e.exit
}

/// Runs every stage. Returns the process exit code.
pub fn execute(ctx: &mut Ctx<'_>) -> u8 {
    let of = TABLE.len();
    let mut worked = 0usize;
    for (i, st) in TABLE.iter().enumerate() {
        let n = i + 1;
        let t0 = ctx.progress.elapsed_ms();
        if !(st.applies)(ctx.mode) {
            ctx.progress.stage(st.id, n, of, "skip", 0);
            continue;
        }
        let skip = ctx.state.finished(st.id) && !st.always && (st.check)(ctx).unwrap_or(false);
        if skip {
            ctx.progress.stage(st.id, n, of, "skip", 0);
            continue;
        }
        ctx.progress.stage(st.id, n, of, "start", 0);
        match (st.run)(ctx) {
            Ok(outcome) => {
                let now = (ctx.now)();
                let (recorded, shown) = match outcome {
                    Outcome::Done => ("done", "done"),
                    Outcome::Manual => ("manual", "manual"),
                    Outcome::Deferred => ("deferred", "deferred"),
                    Outcome::Skipped => ("skipped", "skip"),
                };
                if st.id == "done" {
                    ctx.state.complete = true;
                }
                ctx.state.record(st.id, recorded, now, None);
                if let Err(e) = ctx.save_state() {
                    let ms = ctx.progress.elapsed_ms().saturating_sub(t0);
                    return fail(ctx, st.id, n, of, ms, &e);
                }
                if outcome != Outcome::Skipped && !st.always {
                    worked += 1;
                }
                let ms = ctx.progress.elapsed_ms().saturating_sub(t0);
                ctx.log
                    .line(now, &format!("stage {} {recorded} in {ms} ms", st.id));
                ctx.progress.stage(st.id, n, of, shown, ms);
                if ctx.hooks.fail_after.as_deref() == Some(st.id) {
                    let e = InstallError::test_hook(st.id);
                    return fail(ctx, st.id, n, of, ms, &e);
                }
            }
            Err(e) => {
                let ms = ctx.progress.elapsed_ms().saturating_sub(t0);
                return fail(ctx, st.id, n, of, ms, &e);
            }
        }
    }
    finish(ctx, worked)
}

fn finish(ctx: &mut Ctx<'_>, worked: usize) -> u8 {
    if ctx.report.addresses.is_empty() {
        ctx.report.addresses = stages::setup::addresses(ctx);
    }
    let port_rule = ctx
        .state
        .created
        .port_rule
        .as_ref()
        .map_or_else(|| "none".to_owned(), |p| p.backend.clone());
    let r = ResultOk {
        v: 1,
        t: "result",
        ok: true,
        exit: 0,
        install_id: ctx.state.install_id.clone(),
        agent_version: ctx.state.agent_version.clone(),
        server_public_key: ctx.state.server_public_key.clone(),
        addresses: ctx.report.addresses.clone(),
        port: ctx.opts.port,
        desktop: ctx.report.desktop.clone().or_else(|| {
            ctx.state
                .desktop
                .as_ref()
                .map(|d| super::progress::DesktopOut {
                    id: d.id.clone(),
                    path_taken: d.path_taken.clone(),
                    reason: d.reason.clone(),
                    warnings: d.warnings.clone(),
                })
        }),
        pairing: ctx.report.pairing.clone(),
        port_rule,
    };
    ctx.progress.result_ok(&r);
    let msg = if worked == 0 && ctx.mode.builds_desktop() {
        "hash-xcreen is already installed; everything was verified and nothing needed to change\n"
            .to_owned()
    } else if ctx.mode.builds_desktop() {
        format!("hash-xcreen is installed (port {}).\n", ctx.opts.port)
    } else {
        format!(
            "the agent is installed (port {}) and the pairing token is installed; the setup window stays open for the app (close it with: hx-agent setup finish)\n",
            ctx.opts.port
        )
    };
    ctx.progress.human_out(&msg);
    0
}
