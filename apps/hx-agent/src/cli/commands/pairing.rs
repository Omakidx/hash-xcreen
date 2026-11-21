//! `pairing code` and `pairing token`.
//!
//! Calls: gatewayd `CreatePairingCode`, `CreatePairingToken`.
//!
//! The token is a secret (decision 14, `docs/ipc.md` 5.2). It is read from a hidden prompt on the
//! terminal (default), or generated here and shown once (`--generate`), or taken from argv
//! (`--token`, with a warning that it is weaker). Wherever it comes from it is held in `Zeroizing`
//! memory and goes to gatewayd only as a kind-2 secret frame, never in a protobuf field, a file or
//! the environment.

use hx_crypto::PairingToken;
use hx_ipc::admin::pb::{self, request::Command, response::Result as R};
use hx_ipc::privd::MAX_SECRET_BYTES;
use serde_json::json;
use zeroize::Zeroizing;

use super::admin;
use crate::cli::args::TokenSource;
use crate::cli::error::CliError;
use crate::cli::gatewayd::{unexpected, wipe_code};
use crate::cli::text::{peer, time};
use crate::cli::{Env, Outcome};

/// Longest token the admin socket accepts.
const MAX_TOKEN: usize = hx_ipc::admin::MAX_PAIRING_TOKEN_BYTES;

pub(super) fn code(env: &mut Env<'_>, ttl_s: u32) -> Result<Outcome, CliError> {
    let mut c = admin(env)?;
    let mut r = match c.call(
        Command::CreatePairingCode(pb::CreatePairingCodeRequest {
            expires_in_s: ttl_s,
        }),
        None,
    )? {
        R::CreatePairingCode(r) => r,
        _ => return Err(unexpected("CreatePairingCode")),
    };
    // The code is for the operator's eyes: it is printed once and the reply's copy is wiped.
    let shown = peer(&r.code, 32);
    let expires = r.expires_at_unix_s;
    wipe_code(&mut r);
    let text = format!(
        "pairing code: {shown}\nvalid until {} (about {} minutes), single use\nenter it in the app; it is not stored anywhere else\n",
        time(expires),
        (expires.saturating_sub((env.now)()) / 60).max(1)
    );
    Ok(Outcome::ok(
        text,
        json!({"code": shown, "expires_at_unix_s": expires}),
    ))
}

const ARGV_WARNING: &str = "warning: --token is the WEAKER way to give a token. It is visible in the process list \
(/proc/<pid>/cmdline) while this runs, it stays in your shell history, and under sudo it is written to the \
auth log and the journal. A token is single use and expires, which limits that exposure but does not remove \
it. Run without --token to type it at a hidden prompt instead.";

pub(super) fn token(
    env: &mut Env<'_>,
    source: TokenSource,
    ttl_s: u32,
) -> Result<Outcome, CliError> {
    // The text of the token, in zeroizing memory, and whether to show it afterwards.
    let (text, show): (Zeroizing<Vec<u8>>, bool) = match source {
        TokenSource::Prompt => {
            let typed = env.prompt.secret(
                "Pairing token (input hidden): ",
                MAX_TOKEN.min(MAX_SECRET_BYTES),
            )?;
            (typed, false)
        }
        TokenSource::Generate => {
            let t = PairingToken::generate()
                .map_err(|e| CliError::failed(format!("cannot generate a token: {e}")))?;
            (Zeroizing::new(t.to_text().as_bytes().to_vec()), true)
        }
        TokenSource::Argv(t) => {
            let _ = env.err.write_all(ARGV_WARNING.as_bytes());
            let _ = env.err.write_all(b"\n");
            (Zeroizing::new(t.into_bytes()), false)
        }
    };
    // Checked here so that a typo is explained before anything is sent (gatewayd checks too).
    let token_str = std::str::from_utf8(&text)
        .map_err(|_| CliError::Usage("that is not a pairing token (not text)".into()))?;
    let trimmed = token_str.trim();
    PairingToken::parse(trimmed)
        .map_err(|_| CliError::Usage("that is not a pairing token (expected hxt1-...)".into()))?;
    let mut c = admin(env)?;
    let expires = match c.call(
        Command::CreatePairingToken(pb::CreatePairingTokenRequest {
            expires_in_s: ttl_s,
        }),
        Some(trimmed.as_bytes()),
    )? {
        R::CreatePairingToken(r) => r.expires_at_unix_s,
        _ => return Err(unexpected("CreatePairingToken")),
    };
    let mut out = format!(
        "pairing token installed; valid until {}, single use\n",
        time(expires)
    );
    let mut data = json!({"installed": true, "expires_at_unix_s": expires});
    if show {
        out.push_str(&format!(
            "token (shown once, not stored by hx-agent):\n{trimmed}\n"
        ));
        data["token"] = json!(trimmed);
    }
    Ok(Outcome::ok(out, data))
}
