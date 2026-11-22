//! The installer's JSON Lines progress (design C3, architecture 5.8), parsed.
//!
//! stdout carries only these lines (human text is on stderr). Parsing is tolerant: an unknown
//! line type or extra keys are ignored (the contract may grow), a line that is not JSON becomes a
//! log line, and every string is sanitized because it came from a remote machine.

use serde_json::Value;

use crate::error::InstallerFailure;
use crate::text::sanitize;

const MAX_ID: usize = 64;
const MAX_MESSAGE: usize = 400;

/// The state of a stage line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageState {
    /// The stage started.
    Start,
    /// The stage finished.
    Done,
    /// The stage was already done by an earlier run (a resume).
    Skip,
    /// The stage failed.
    Fail,
    /// Not in this release (Phase 2 backups).
    Deferred,
    /// Needs a manual step.
    Manual,
    /// A state this version does not know.
    Other(String),
}

impl StageState {
    fn parse(s: &str) -> Self {
        match s {
            "start" => Self::Start,
            "done" => Self::Done,
            "skip" => Self::Skip,
            "fail" => Self::Fail,
            "deferred" => Self::Deferred,
            "manual" => Self::Manual,
            other => Self::Other(sanitize(other, 32)),
        }
    }

    /// True for the states that end a stage (everything but `Start`).
    pub fn is_final(&self) -> bool {
        !matches!(self, Self::Start)
    }
}

/// Where a log line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStream {
    /// The installer's stderr (human text).
    Stderr,
    /// A stdout line that was not valid progress JSON (the contract says there are none).
    Stdout,
}

/// The local steps of the engine, before and around the installer's own stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Checking the sudo password.
    SudoCheck,
    /// Uploading `install.sh`.
    Upload,
    /// Starting the installer; its own stage lines follow.
    Run,
    /// Removing the uploaded script.
    Cleanup,
}

/// One progress event for the app's live view and log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallEvent {
    /// A step of this engine (not of the installer).
    Phase(Phase),
    /// A stage line. `n`, `of` and `ms` are absent on the `bootstrap-*` lines of `install.sh`.
    Stage {
        /// Stage id.
        id: String,
        /// Position (1-based).
        n: Option<u32>,
        /// Number of stages.
        of: Option<u32>,
        /// State.
        state: StageState,
        /// Milliseconds the stage took (on its final line).
        ms: Option<u64>,
    },
    /// A privd progress step inside a stage (the desktop build).
    Step {
        /// Stage id.
        id: String,
        /// privd's stage name (`BUILD`, ...).
        privd_stage: String,
        /// Step index.
        index: u32,
        /// Number of steps.
        total: u32,
        /// What is being done.
        step: String,
        /// 0 to 100, or `None` when unknown (the wire value 255).
        percent: Option<u8>,
    },
    /// A warning (for example "the prebuilt image could not be used").
    Warn {
        /// Stage id.
        id: String,
        /// The message.
        message: String,
    },
    /// A line of text for the expandable log.
    Log {
        /// Which stream.
        stream: LogStream,
        /// The sanitized line.
        text: String,
    },
}

/// The pairing credential the installer left in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingKind {
    /// A one-time code (`XXXX-XXXX`) to show to the user.
    Code,
    /// The token the app supplied; pair with it now.
    Token,
    /// None.
    None,
}

/// The desktop the installer built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopInfo {
    /// Desktop id.
    pub id: String,
    /// `PREBUILT` or `BUILD`.
    pub path_taken: String,
    /// Why that path.
    pub reason: String,
    /// privd's warnings.
    pub warnings: Vec<String>,
}

/// A successful install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallResult {
    /// The install id (32 hex).
    pub install_id: String,
    /// The agent version.
    pub agent_version: String,
    /// The server's Ed25519 identity key, 64 hex digits. Cross-check it against the key seen
    /// while pairing ([`crate::pair`]).
    pub server_public_key: String,
    /// Global addresses of the host.
    pub addresses: Vec<String>,
    /// The public port.
    pub port: u16,
    /// The desktop that was built.
    pub desktop: Option<DesktopInfo>,
    /// The pairing credential in place.
    pub pairing: PairingKind,
    /// Pairing expiry, Unix seconds (0 for none).
    pub pairing_expires_at_unix_s: u64,
    /// `ufw`, `nft`, `manual` or `none`.
    pub port_rule: String,
    /// Every `warn` line of the run plus the desktop's own warnings.
    pub warnings: Vec<String>,
}

/// A parsed stdout line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// Show it.
    Event(InstallEvent),
    /// The final success line.
    Ok(Box<InstallResult>),
    /// The final failure line.
    Failed(InstallerFailure),
    /// Valid JSON of a kind (or version) this crate does not use.
    Ignored,
}

fn s(v: &Value, key: &str, max: usize) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(|x| sanitize(x, max))
}

fn u(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(Value::as_u64)
}

fn is_hex64(x: &str) -> bool {
    x.len() == 64 && x.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parses one stdout line.
pub fn parse_line(raw: &str) -> Line {
    let raw = raw.trim_end_matches(['\r', '\n']);
    let Ok(v) = serde_json::from_str::<Value>(raw) else {
        return Line::Event(InstallEvent::Log {
            stream: LogStream::Stdout,
            text: sanitize(raw, MAX_MESSAGE),
        });
    };
    if !v.is_object() || u(&v, "v") != Some(1) {
        return Line::Ignored;
    }
    match v.get("t").and_then(Value::as_str) {
        Some("stage") => {
            let Some(id) = s(&v, "id", MAX_ID) else {
                return Line::Ignored;
            };
            let state = StageState::parse(v.get("state").and_then(Value::as_str).unwrap_or(""));
            Line::Event(InstallEvent::Stage {
                id,
                n: u(&v, "n").and_then(|x| u32::try_from(x).ok()),
                of: u(&v, "of").and_then(|x| u32::try_from(x).ok()),
                state,
                ms: u(&v, "ms"),
            })
        }
        Some("step") => {
            let (Some(id), Some(step)) = (s(&v, "id", MAX_ID), s(&v, "step", MAX_MESSAGE)) else {
                return Line::Ignored;
            };
            let percent = u(&v, "percent").and_then(|p| u8::try_from(p).ok());
            Line::Event(InstallEvent::Step {
                id,
                privd_stage: s(&v, "privd_stage", MAX_ID).unwrap_or_default(),
                index: u(&v, "index")
                    .and_then(|x| u32::try_from(x).ok())
                    .unwrap_or(0),
                total: u(&v, "total")
                    .and_then(|x| u32::try_from(x).ok())
                    .unwrap_or(0),
                step,
                percent: percent.filter(|p| *p <= 100),
            })
        }
        Some("warn") => Line::Event(InstallEvent::Warn {
            id: s(&v, "id", MAX_ID).unwrap_or_default(),
            message: s(&v, "message", MAX_MESSAGE).unwrap_or_default(),
        }),
        Some("result") => parse_result(&v),
        _ => Line::Ignored,
    }
}

fn parse_result(v: &Value) -> Line {
    let exit = u(v, "exit")
        .and_then(|x| u32::try_from(x).ok())
        .unwrap_or(1);
    if v.get("ok").and_then(Value::as_bool) == Some(false) {
        let code = s(v, "code", 32).unwrap_or_else(|| "UNKNOWN".into());
        let retryable = v.get("retryable").and_then(Value::as_bool).unwrap_or(false)
            || code == "LOCKED"
            || exit == 11;
        return Line::Failed(InstallerFailure {
            stage: s(v, "stage", MAX_ID).unwrap_or_else(|| "unknown".into()),
            code,
            message: s(v, "message", MAX_MESSAGE).unwrap_or_default(),
            retryable,
            exit,
        });
    }
    if v.get("ok").and_then(Value::as_bool) != Some(true) {
        return Line::Ignored;
    }
    let Some(key) = v
        .get("server_public_key")
        .and_then(Value::as_str)
        .filter(|k| is_hex64(k))
    else {
        // A success without a usable key is not a success this app can pair with.
        return Line::Failed(InstallerFailure {
            stage: "finish".into(),
            code: "PROTOCOL".into(),
            message: "the installer reported no valid server key".into(),
            retryable: false,
            exit,
        });
    };
    let addresses = v
        .get("addresses")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .take(32)
                .map(|x| sanitize(x, 64))
                .collect()
        })
        .unwrap_or_default();
    let desktop = v
        .get("desktop")
        .filter(|d| d.is_object())
        .map(|d| DesktopInfo {
            id: s(d, "id", MAX_ID).unwrap_or_default(),
            path_taken: s(d, "path_taken", 16).unwrap_or_default(),
            reason: s(d, "reason", MAX_MESSAGE).unwrap_or_default(),
            warnings: d
                .get("warnings")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .take(32)
                        .map(|x| sanitize(x, MAX_MESSAGE))
                        .collect()
                })
                .unwrap_or_default(),
        });
    let pairing_obj = v.get("pairing");
    let pairing = match pairing_obj
        .and_then(|p| p.get("kind"))
        .and_then(Value::as_str)
    {
        Some("code") => PairingKind::Code,
        Some("token") => PairingKind::Token,
        _ => PairingKind::None,
    };
    Line::Ok(Box::new(InstallResult {
        install_id: s(v, "install_id", 64).unwrap_or_default(),
        agent_version: s(v, "agent_version", 32).unwrap_or_default(),
        server_public_key: key.to_ascii_lowercase(),
        addresses,
        port: u(v, "port")
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(0),
        pairing,
        pairing_expires_at_unix_s: pairing_obj
            .and_then(|p| u(p, "expires_at_unix_s"))
            .unwrap_or(0),
        port_rule: s(v, "port_rule", 16).unwrap_or_default(),
        warnings: desktop
            .as_ref()
            .map(|d| d.warnings.clone())
            .unwrap_or_default(),
        desktop,
    }))
}

/// Splits a byte stream into lines, with a bound on the line length. A longer line is cut: its
/// head is delivered and the rest dropped up to the next newline.
#[derive(Default)]
pub struct LineSplitter {
    buf: Vec<u8>,
    dropping: bool,
}

/// Longest line kept.
pub const MAX_LINE: usize = 64 * 1024;

impl LineSplitter {
    /// Feeds `data`; `out` gets every completed line (lossy UTF-8, no newline).
    pub fn push(&mut self, data: &[u8], mut out: impl FnMut(String)) {
        for &b in data {
            if b == b'\n' {
                let line = String::from_utf8_lossy(&self.buf).into_owned();
                self.buf.clear();
                self.dropping = false;
                out(line);
            } else if self.buf.len() < MAX_LINE {
                self.buf.push(b);
            } else {
                self.dropping = true;
            }
        }
    }

    /// The unterminated rest at the end of the stream, if any.
    pub fn finish(&mut self) -> Option<String> {
        if self.buf.is_empty() {
            return None;
        }
        let line = String::from_utf8_lossy(&self.buf).into_owned();
        self.buf.clear();
        Some(line)
    }

    /// True when the current line was cut.
    pub fn truncated(&self) -> bool {
        self.dropping
    }
}

/// The ten rows of the progress screen (mockup `progress.html`), each holding the installer
/// stage ids it covers.
pub const GROUPS: [(&str, &[&str]); 10] = [
    (
        "Check the server",
        &[
            "bootstrap-preflight",
            "bootstrap-download",
            "bootstrap-verify",
            "preflight",
        ],
    ),
    ("Install system packages", &["packages"]),
    ("Install Incus (the container manager)", &["incus"]),
    (
        "Install the agent",
        &["release", "system-files", "credentials", "config", "units"],
    ),
    (
        "Prepare the host",
        &["setup-window", "host", "firewall-port"],
    ),
    ("Build the desktop", &["desktop"]),
    (
        "Secure access: password and PIN",
        &["verifiers", "owner-key"],
    ),
    ("Backups", &["backup"]),
    ("Pair this device", &["pairing-token", "pairing"]),
    ("Finish", &["finish", "done"]),
];

/// The 0-based row of a stage id in [`GROUPS`], `None` for an id this version does not know.
pub fn group_of(stage_id: &str) -> Option<usize> {
    GROUPS.iter().position(|(_, ids)| ids.contains(&stage_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_installer_stage_is_in_a_group() {
        for id in [
            "preflight",
            "packages",
            "incus",
            "release",
            "system-files",
            "credentials",
            "config",
            "units",
            "setup-window",
            "host",
            "firewall-port",
            "pairing-token",
            "desktop",
            "verifiers",
            "owner-key",
            "backup",
            "pairing",
            "finish",
            "done",
        ] {
            assert!(group_of(id).is_some(), "{id}");
        }
        assert_eq!(group_of("bootstrap-verify"), Some(0));
        assert_eq!(group_of("nonsense"), None);
    }

    #[test]
    fn splitter_handles_partial_and_overlong_lines() {
        let mut sp = LineSplitter::default();
        let mut got = Vec::new();
        sp.push(b"ab", |l| got.push(l));
        sp.push(b"c\nde", |l| got.push(l));
        assert_eq!(got, ["abc"]);
        assert_eq!(sp.finish().as_deref(), Some("de"));
        let big = vec![b'x'; MAX_LINE + 10];
        sp.push(&big, |_| panic!("no line yet"));
        assert!(sp.truncated());
        sp.push(b"\n", |l| got.push(l));
        assert_eq!(got[1].len(), MAX_LINE);
    }
}
