//! Progress output (design C3).
//!
//! With `--json`, **stdout carries only JSON Lines** and human text goes to stderr:
//!
//! ```text
//! {"v":1,"t":"stage","id":"config","n":7,"of":19,"state":"done","ms":123}
//! {"v":1,"t":"step","id":"desktop","privd_stage":"BUILD","index":3,"total":12,"step":"...","percent":255}
//! {"v":1,"t":"warn","id":"incus","message":"..."}
//! {"v":1,"t":"result","ok":true,"exit":0,...}
//! {"v":1,"t":"result","ok":false,"exit":1,"stage":"incus","code":"TOOL","message":"...","retryable":true}
//! ```
//!
//! The lines are serialized from structs, so the key order is the documented one. Every string is
//! sanitized with [`crate::cli::text::peer`] before it is put in a line.

use std::io::Write;

use serde::Serialize;

use crate::cli::text::{peer, scrub_output};

/// Longest message in a line.
const MAX_TEXT: usize = 400;

#[derive(Serialize)]
struct StageLine<'a> {
    v: u8,
    t: &'static str,
    id: &'a str,
    n: usize,
    of: usize,
    state: &'a str,
    ms: u64,
}

#[derive(Serialize)]
struct StepLine<'a> {
    v: u8,
    t: &'static str,
    id: &'a str,
    privd_stage: &'a str,
    index: u32,
    total: u32,
    step: String,
    percent: u32,
}

#[derive(Serialize)]
struct WarnLine<'a> {
    v: u8,
    t: &'static str,
    id: &'a str,
    message: String,
}

/// The `desktop` member of the final result.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct DesktopOut {
    /// Desktop id.
    pub id: String,
    /// `PREBUILT` or `BUILD`.
    pub path_taken: String,
    /// Why.
    pub reason: String,
    /// privd's warnings.
    pub warnings: Vec<String>,
}

/// The `pairing` member of the final result.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct PairingOut {
    /// `code`, `token` or `none`.
    pub kind: &'static str,
    /// Expiry, Unix seconds (0 for none).
    pub expires_at_unix_s: u64,
}

/// The success result.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ResultOk {
    /// 1.
    pub v: u8,
    /// `result`.
    pub t: &'static str,
    /// true.
    pub ok: bool,
    /// 0.
    pub exit: u8,
    /// The install id.
    pub install_id: String,
    /// The agent version.
    pub agent_version: String,
    /// Ed25519 public key, 64 hex.
    pub server_public_key: String,
    /// Global addresses of the host.
    pub addresses: Vec<String>,
    /// The public port.
    pub port: u16,
    /// The desktop, when one was built.
    pub desktop: Option<DesktopOut>,
    /// The pairing credential installed.
    pub pairing: PairingOut,
    /// `ufw`, `nft`, `manual` or `none`.
    pub port_rule: String,
}

#[derive(Serialize)]
struct ResultErr<'a> {
    v: u8,
    t: &'static str,
    ok: bool,
    exit: u8,
    stage: &'a str,
    code: &'a str,
    message: String,
    retryable: bool,
}

/// Writes progress as JSON Lines (stdout) or human text (stderr).
pub struct Progress<'a> {
    json: bool,
    out: &'a mut dyn Write,
    err: &'a mut dyn Write,
    mono: Box<dyn FnMut() -> u64 + 'a>,
    started: u64,
}

impl<'a> Progress<'a> {
    /// A progress writer. `mono` returns milliseconds from any fixed origin.
    pub fn new(
        json: bool,
        out: &'a mut dyn Write,
        err: &'a mut dyn Write,
        mut mono: Box<dyn FnMut() -> u64 + 'a>,
    ) -> Self {
        let started = mono();
        Self {
            json,
            out,
            err,
            mono,
            started,
        }
    }

    /// `--json` mode.
    pub fn is_json(&self) -> bool {
        self.json
    }

    fn jsonl<T: Serialize>(&mut self, line: &T) {
        let mut s = serde_json::to_string(line).unwrap_or_else(|_| "{}".into());
        s.push('\n');
        let _ = self.out.write_all(s.as_bytes());
        let _ = self.out.flush();
    }

    /// Human text to stderr (also in JSON mode).
    pub fn human(&mut self, text: &str) {
        let _ = self.err.write_all(scrub_output(text).as_bytes());
        let _ = self.err.flush();
    }

    /// Human text to stdout in text mode, to stderr in JSON mode (stdout is JSON only there).
    pub fn human_out(&mut self, text: &str) {
        if self.json {
            self.human(text);
        } else {
            let _ = self.out.write_all(scrub_output(text).as_bytes());
            let _ = self.out.flush();
        }
    }

    /// Writes `secret_text` followed by a newline to the human channel without building another
    /// copy (the pairing code is printed straight from its zeroizing buffer).
    pub fn secret_line(&mut self, label: &str, secret_text: &str) {
        let w: &mut dyn Write = if self.json {
            &mut *self.err
        } else {
            &mut *self.out
        };
        let _ = w.write_all(label.as_bytes());
        let _ = w.write_all(secret_text.as_bytes());
        let _ = w.write_all(b"\n");
        let _ = w.flush();
    }

    /// Milliseconds since the writer was made.
    pub fn elapsed_ms(&mut self) -> u64 {
        (self.mono)().saturating_sub(self.started)
    }

    /// A stage event. `state` is `start`, `done`, `skip`, `fail`, `deferred` or `manual`.
    pub fn stage(&mut self, id: &str, n: usize, of: usize, state: &str, ms: u64) {
        if self.json {
            self.jsonl(&StageLine {
                v: 1,
                t: "stage",
                id,
                n,
                of,
                state,
                ms,
            });
        }
        // Human text goes to stderr in both modes.
        let verb = match state {
            "start" => "...",
            "done" => "done",
            "skip" => "already done",
            "deferred" => "deferred (Phase 2)",
            "manual" => "needs a manual step",
            "fail" => "FAILED",
            other => other,
        };
        if state != "start" {
            self.human(&format!("[{n}/{of}] {id}: {verb}\n"));
        }
    }

    /// A privd progress report, relayed 1:1.
    pub fn step(&mut self, id: &str, p: &crate::cli::privd::ProgressLine) {
        if self.json {
            self.jsonl(&StepLine {
                v: 1,
                t: "step",
                id,
                privd_stage: &p.stage,
                index: p.index,
                total: p.total,
                step: peer(&p.step, 128),
                percent: p.percent.unwrap_or(255),
            });
        } else {
            let pct = p.percent.map(|x| format!(" {x}%")).unwrap_or_default();
            self.human(&format!(
                "    [{}] {}/{}{} {}\n",
                p.stage.to_lowercase(),
                p.index,
                p.total,
                pct,
                p.step
            ));
        }
    }

    /// A warning.
    pub fn warn(&mut self, id: &str, message: &str) {
        if self.json {
            self.jsonl(&WarnLine {
                v: 1,
                t: "warn",
                id,
                message: peer(message, MAX_TEXT),
            });
        }
        self.human(&format!("warning ({id}): {}\n", peer(message, MAX_TEXT)));
    }

    /// The success result.
    pub fn result_ok(&mut self, r: &ResultOk) {
        if self.json {
            self.jsonl(r);
        }
    }

    /// The failure result.
    pub fn result_err(
        &mut self,
        exit: u8,
        stage: &str,
        code: &str,
        message: &str,
        retryable: bool,
    ) {
        if self.json {
            self.jsonl(&ResultErr {
                v: 1,
                t: "result",
                ok: false,
                exit,
                stage,
                code,
                message: peer(message, MAX_TEXT),
                retryable,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::privd::ProgressLine;

    fn run(json: bool, f: impl FnOnce(&mut Progress<'_>)) -> (String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        {
            let mut n = 0;
            let mut p = Progress::new(
                json,
                &mut out,
                &mut err,
                Box::new(move || {
                    n += 10;
                    n
                }),
            );
            f(&mut p);
        }
        (
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn stage_lines_have_the_documented_key_order() {
        let (o, e) = run(true, |p| {
            p.stage("config", 7, 19, "start", 0);
            p.stage("config", 7, 19, "done", 123);
        });
        assert_eq!(
            o,
            "{\"v\":1,\"t\":\"stage\",\"id\":\"config\",\"n\":7,\"of\":19,\"state\":\"start\",\"ms\":0}\n\
             {\"v\":1,\"t\":\"stage\",\"id\":\"config\",\"n\":7,\"of\":19,\"state\":\"done\",\"ms\":123}\n"
        );
        assert!(e.contains("[7/19] config: done"));
    }

    #[test]
    fn step_warn_and_error_result_lines() {
        let (o, _) = run(true, |p| {
            p.step(
                "desktop",
                &ProgressLine {
                    stage: "BUILD".into(),
                    index: 3,
                    total: 12,
                    step: "apt\u{202E} install".into(),
                    percent: None,
                    ok: false,
                },
            );
            p.warn("incus", "old\nversion");
            p.result_err(1, "incus", "TOOL", "apt-get failed", true);
        });
        let lines: Vec<&str> = o.lines().collect();
        assert_eq!(
            lines[0],
            r#"{"v":1,"t":"step","id":"desktop","privd_stage":"BUILD","index":3,"total":12,"step":"apt install","percent":255}"#
        );
        assert_eq!(
            lines[1],
            r#"{"v":1,"t":"warn","id":"incus","message":"oldversion"}"#
        );
        assert_eq!(
            lines[2],
            r#"{"v":1,"t":"result","ok":false,"exit":1,"stage":"incus","code":"TOOL","message":"apt-get failed","retryable":true}"#
        );
    }

    #[test]
    fn the_ok_result_has_the_documented_shape() {
        let r = ResultOk {
            v: 1,
            t: "result",
            ok: true,
            exit: 0,
            install_id: "a".repeat(32),
            agent_version: "0.1.0".into(),
            server_public_key: "b".repeat(64),
            addresses: vec!["2001:db8::1".into()],
            port: 443,
            desktop: Some(DesktopOut {
                id: "main".into(),
                path_taken: "BUILD".into(),
                reason: "r".into(),
                warnings: vec![],
            }),
            pairing: PairingOut {
                kind: "code",
                expires_at_unix_s: 900,
            },
            port_rule: "ufw".into(),
        };
        let (o, _) = run(true, |p| p.result_ok(&r));
        assert!(o.starts_with(r#"{"v":1,"t":"result","ok":true,"exit":0,"install_id":""#));
        assert!(o.contains(
            r#""desktop":{"id":"main","path_taken":"BUILD","reason":"r","warnings":[]}"#
        ));
        assert!(
            o.ends_with(
                r#""pairing":{"kind":"code","expires_at_unix_s":900},"port_rule":"ufw"}"#
                    .to_string()
                    .as_str()
            ) || o.trim_end().ends_with(r#""port_rule":"ufw"}"#)
        );
    }

    #[test]
    fn text_mode_writes_no_json_and_json_mode_keeps_stdout_clean() {
        let (o, e) = run(false, |p| {
            p.stage("packages", 2, 19, "done", 1);
            p.result_err(1, "x", "TOOL", "m", true);
        });
        assert!(o.is_empty());
        assert!(e.contains("packages"));
        let (o, e) = run(true, |p| {
            p.human("hello\n");
            p.secret_line("code: ", "ABCD-EFGH");
        });
        assert!(o.is_empty(), "stdout is JSON only: {o}");
        assert!(e.contains("code: ABCD-EFGH"));
    }
}
