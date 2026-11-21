//! The command line: a small hand-written parser (no crate), so the accepted surface is exactly
//! what is written here.
//!
//! Rules:
//!
//! * `--json` and `-h`/`--help` are accepted anywhere;
//! * `--flag value` and `--flag=value` both work, `--` ends the options;
//! * **a secret is never an argument.** `--password` and `--pin` are refused with an explanation;
//!   `pairing token --token <t>` exists only for unattended use and is documented as weaker.

use std::collections::{HashMap, HashSet};

use hx_ipc::privd::pb::LockoutPurpose;

use super::error::CliError;

/// Where `pairing token` gets the token from.
#[derive(Debug, PartialEq, Eq)]
pub enum TokenSource {
    /// A hidden prompt on `/dev/tty` (the default; decision 14).
    Prompt,
    /// Generate one and print it once.
    Generate,
    /// `--token <t>` in argv (weaker: process list, shell history, auth log).
    Argv(String),
}

/// A parsed command.
#[derive(Debug, PartialEq, Eq)]
pub enum Cmd {
    /// `help [topic]`, `--help`.
    Help(Option<String>),
    /// `--version`.
    Version,
    /// `status`.
    Status,
    /// `devices list`.
    DevicesList,
    /// `devices revoke <id-prefix>`.
    DevicesRevoke { prefix: String },
    /// `devices reinstate <id-prefix>`.
    DevicesReinstate { prefix: String },
    /// `pairing code`.
    PairingCode { ttl_s: u32 },
    /// `pairing token`.
    PairingToken { source: TokenSource, ttl_s: u32 },
    /// `pin set`.
    PinSet { device: Option<String> },
    /// `pin reset-lockout`.
    PinResetLockout { purpose: LockoutPurpose, yes: bool },
    /// `setup begin`.
    SetupBegin { secs: u32 },
    /// `setup extend`.
    SetupExtend { secs: u32 },
    /// `setup finish`.
    SetupFinish { force: bool },
    /// `desktop start|stop|restart`.
    DesktopPower {
        action: Power,
        id: String,
        force: bool,
    },
    /// `desktop limits`.
    DesktopLimits {
        id: String,
        cpu: Option<u32>,
        memory_mib: Option<u64>,
        disk_gib: Option<u64>,
    },
    /// `desktop password`.
    DesktopPassword { id: String, verifier_only: bool },
    /// `docker enable`.
    DockerEnable { id: String, yes: bool },
    /// `docker disable`.
    DockerDisable { id: String },
    /// `snapshots list`.
    SnapshotsList { id: String },
    /// `snapshots create`.
    SnapshotsCreate { id: String },
    /// `snapshots delete <name>`.
    SnapshotsDelete { id: String, name: String },
    /// `logs`.
    Logs {
        follow: bool,
        lines: u32,
        journal: bool,
        audit: bool,
    },
    /// `update check`.
    UpdateCheck,
    /// `update apply [version]`.
    UpdateApply { version: Option<String>, yes: bool },
    /// `update rollback`.
    UpdateRollback { yes: bool },
    /// `uninstall`.
    Uninstall {
        keep_desktop: Option<bool>,
        yes: bool,
    },
}

/// `desktop start|stop|restart`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Power {
    /// `StartDesktop`.
    Start,
    /// `StopDesktop`.
    Stop,
    /// `RestartDesktop`.
    Restart,
}

/// A parsed command line.
#[derive(Debug, PartialEq, Eq)]
pub struct Parsed {
    /// `--json` was given.
    pub json: bool,
    /// The command.
    pub cmd: Cmd,
}

/// The default desktop id (v1 has exactly one).
pub const DEFAULT_DESKTOP: &str = "main";
/// Default and longest pairing credential lifetime, seconds.
const PAIR_TTL_DEFAULT: u32 = 900;
/// Default `log` line count.
const DEFAULT_LINES: u32 = 100;
/// Most lines `logs` shows per source.
const MAX_LINES: u32 = 10_000;

fn usage(m: impl Into<String>) -> CliError {
    CliError::Usage(m.into())
}

#[derive(Default)]
struct Opts {
    flags: HashSet<&'static str>,
    values: HashMap<&'static str, String>,
    pos: Vec<String>,
}

impl Opts {
    fn flag(&self, n: &str) -> bool {
        self.flags.contains(n)
    }
    fn value(&self, n: &str) -> Option<&str> {
        self.values.get(n).map(String::as_str)
    }
    /// Exactly `n` positional arguments.
    fn positionals(&self, n: usize, names: &str) -> Result<&[String], CliError> {
        if self.pos.len() == n {
            Ok(&self.pos)
        } else if self.pos.len() < n {
            Err(usage(format!("missing {names}")))
        } else {
            Err(usage(format!(
                "unexpected argument {:?}",
                super::text::peer(&self.pos[n], 64)
            )))
        }
    }
}

fn refuse_secret_flag(a: &str) -> Result<(), CliError> {
    let name = a.split('=').next().unwrap_or(a);
    if matches!(
        name,
        "--password" | "--pin" | "--secret" | "--passphrase" | "--new-password" | "--new-pin"
    ) {
        return Err(usage(format!(
            "{name} does not exist: hx-agent never takes a secret from the command line (it would sit in the process list and shell history); it asks on the terminal with echo off"
        )));
    }
    Ok(())
}

/// Parses `args` against the flags (`booleans`) and value options (`valued`) a command knows.
fn opts(
    args: &[String],
    booleans: &[&'static str],
    valued: &[&'static str],
) -> Result<Opts, CliError> {
    let mut o = Opts::default();
    let mut it = args.iter();
    let mut only_positional = false;
    while let Some(a) = it.next() {
        if only_positional || !a.starts_with('-') || a == "-" {
            o.pos.push(a.clone());
            continue;
        }
        if a == "--" {
            only_positional = true;
            continue;
        }
        refuse_secret_flag(a)?;
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v.to_owned())),
            _ => (a.as_str(), None),
        };
        if let Some(b) = booleans.iter().find(|b| **b == name) {
            if inline.is_some() {
                return Err(usage(format!("{name} takes no value")));
            }
            o.flags.insert(b);
        } else if let Some(v) = valued.iter().find(|v| **v == name) {
            let value = match inline {
                Some(v) => v,
                None => it
                    .next()
                    .cloned()
                    .ok_or_else(|| usage(format!("{name} needs a value")))?,
            };
            if o.values.insert(v, value).is_some() {
                return Err(usage(format!("{name} given twice")));
            }
        } else {
            return Err(usage(format!(
                "unknown option {:?}",
                super::text::peer(name, 64)
            )));
        }
    }
    Ok(o)
}

/// `90`, `90s`, `15m`, `2h`.
pub fn parse_secs(s: &str) -> Result<u32, CliError> {
    let bad = || {
        usage(format!(
            "bad duration {:?} (use 90, 15m or 2h)",
            super::text::peer(s, 32)
        ))
    };
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1u64),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some(c) if c.is_ascii_digit() => (s, 1),
        _ => return Err(bad()),
    };
    let n: u64 = num.parse().map_err(|_| bad())?;
    u32::try_from(n.checked_mul(mult).ok_or_else(bad)?).map_err(|_| bad())
}

fn desktop_id(o: &Opts) -> Result<String, CliError> {
    let id = o.value("--desktop").unwrap_or(DEFAULT_DESKTOP);
    if hx_ipc::privd::is_valid_desktop_id(id) {
        Ok(id.to_owned())
    } else {
        Err(usage("--desktop must match ^[a-z][a-z0-9]{0,11}$"))
    }
}

fn ttl(o: &Opts) -> Result<u32, CliError> {
    match o.value("--ttl") {
        None => Ok(PAIR_TTL_DEFAULT),
        Some(v) => {
            let n = parse_secs(v)?;
            if (60..=900).contains(&n) {
                Ok(n)
            } else {
                Err(usage("--ttl must be between 60 s and 15 m"))
            }
        }
    }
}

fn unsigned<T: std::str::FromStr + PartialOrd + Default>(
    o: &Opts,
    name: &str,
) -> Result<Option<T>, CliError> {
    match o.value(name) {
        None => Ok(None),
        Some(v) => match v.parse::<T>() {
            Ok(n) if n > T::default() => Ok(Some(n)),
            _ => Err(usage(format!("{name} must be a positive whole number"))),
        },
    }
}

/// Parses the arguments after the program name.
pub fn parse(all: &[String]) -> Result<Parsed, CliError> {
    let json = all.iter().any(|a| a == "--json");
    let args: Vec<String> = all.iter().filter(|a| *a != "--json").cloned().collect();
    let help = args.iter().any(|a| a == "-h" || a == "--help");
    let cmd = parse_cmd(&args, help)?;
    Ok(Parsed { json, cmd })
}

fn parse_cmd(args: &[String], help: bool) -> Result<Cmd, CliError> {
    let args_no_help: Vec<String> = args
        .iter()
        .filter(|a| *a != "-h" && *a != "--help")
        .cloned()
        .collect();
    let Some(verb) = args_no_help.first().map(String::as_str) else {
        return Ok(Cmd::Help(None));
    };
    if help {
        return Ok(Cmd::Help(Some(verb.to_owned())));
    }
    let rest = &args_no_help[1..];
    let group = |names: &[&str]| -> Result<(String, Vec<String>), CliError> {
        match rest.first() {
            Some(sub) if names.contains(&sub.as_str()) => Ok((sub.clone(), rest[1..].to_vec())),
            Some(sub) => Err(usage(format!(
                "unknown {verb} command {:?} (expected one of: {})",
                super::text::peer(sub, 32),
                names.join(", ")
            ))),
            None => Err(usage(format!(
                "{verb} needs a command (one of: {})",
                names.join(", ")
            ))),
        }
    };
    match verb {
        "help" => Ok(Cmd::Help(rest.first().cloned())),
        "version" => Ok(Cmd::Version),
        "--version" | "-V" => Ok(Cmd::Version),
        "status" => {
            opts(rest, &[], &[])?.positionals(0, "")?;
            Ok(Cmd::Status)
        }
        "devices" => {
            let (sub, r) = group(&["list", "revoke", "reinstate"])?;
            let o = opts(&r, &[], &[])?;
            match sub.as_str() {
                "list" => {
                    o.positionals(0, "")?;
                    Ok(Cmd::DevicesList)
                }
                "revoke" => Ok(Cmd::DevicesRevoke {
                    prefix: o.positionals(1, "the device id (or an unambiguous prefix)")?[0]
                        .clone(),
                }),
                _ => Ok(Cmd::DevicesReinstate {
                    prefix: o.positionals(1, "the device id (or an unambiguous prefix)")?[0]
                        .clone(),
                }),
            }
        }
        "pairing" => {
            let (sub, r) = group(&["code", "token"])?;
            match sub.as_str() {
                "code" => {
                    let o = opts(&r, &[], &["--ttl"])?;
                    o.positionals(0, "")?;
                    Ok(Cmd::PairingCode { ttl_s: ttl(&o)? })
                }
                _ => {
                    let o = opts(&r, &["--generate"], &["--ttl", "--token"])?;
                    o.positionals(0, "")?;
                    if o.flag("--generate") && o.value("--token").is_some() {
                        return Err(usage("--generate and --token cannot be combined"));
                    }
                    let source = if o.flag("--generate") {
                        TokenSource::Generate
                    } else if let Some(t) = o.value("--token") {
                        TokenSource::Argv(t.to_owned())
                    } else {
                        TokenSource::Prompt
                    };
                    Ok(Cmd::PairingToken {
                        source,
                        ttl_s: ttl(&o)?,
                    })
                }
            }
        }
        "pin" => {
            let (sub, r) = group(&["set", "reset-lockout"])?;
            match sub.as_str() {
                "set" => {
                    let o = opts(&r, &[], &["--device"])?;
                    o.positionals(0, "")?;
                    Ok(Cmd::PinSet {
                        device: o.value("--device").map(str::to_owned),
                    })
                }
                _ => {
                    let o = opts(&r, &["--yes"], &["--purpose"])?;
                    o.positionals(0, "")?;
                    let purpose = match o.value("--purpose").unwrap_or("pin") {
                        "pin" => LockoutPurpose::Pin,
                        "password" => LockoutPurpose::Password,
                        _ => return Err(usage("--purpose must be pin or password")),
                    };
                    Ok(Cmd::PinResetLockout {
                        purpose,
                        yes: o.flag("--yes"),
                    })
                }
            }
        }
        "setup" => {
            let (sub, r) = group(&["begin", "extend", "finish"])?;
            match sub.as_str() {
                "begin" => {
                    let o = opts(&r, &[], &["--for"])?;
                    o.positionals(0, "")?;
                    let secs = o
                        .value("--for")
                        .map(parse_secs)
                        .transpose()?
                        .unwrap_or(7200);
                    if !(60..=86_400).contains(&secs) {
                        return Err(usage("--for must be between 60 s and 24 h"));
                    }
                    Ok(Cmd::SetupBegin { secs })
                }
                "extend" => {
                    let o = opts(&r, &[], &[])?;
                    let secs =
                        parse_secs(&o.positionals(1, "the time to add (for example 1h)")?[0])?;
                    if !(60..=86_400).contains(&secs) {
                        return Err(usage("the extension must be between 60 s and 24 h"));
                    }
                    Ok(Cmd::SetupExtend { secs })
                }
                _ => {
                    let o = opts(&r, &["--force"], &[])?;
                    o.positionals(0, "")?;
                    Ok(Cmd::SetupFinish {
                        force: o.flag("--force"),
                    })
                }
            }
        }
        "desktop" => {
            let (sub, r) = group(&["start", "stop", "restart", "limits", "password"])?;
            match sub.as_str() {
                "start" | "stop" | "restart" => {
                    let o = opts(&r, &["--force"], &["--desktop"])?;
                    o.positionals(0, "")?;
                    let action = match sub.as_str() {
                        "start" => Power::Start,
                        "stop" => Power::Stop,
                        _ => Power::Restart,
                    };
                    if o.flag("--force") && action == Power::Start {
                        return Err(usage("--force applies to stop and restart only"));
                    }
                    Ok(Cmd::DesktopPower {
                        action,
                        id: desktop_id(&o)?,
                        force: o.flag("--force"),
                    })
                }
                "limits" => {
                    let o = opts(
                        &r,
                        &[],
                        &["--desktop", "--cpu", "--memory-mib", "--disk-gib"],
                    )?;
                    o.positionals(0, "")?;
                    Ok(Cmd::DesktopLimits {
                        id: desktop_id(&o)?,
                        cpu: unsigned(&o, "--cpu")?,
                        memory_mib: unsigned(&o, "--memory-mib")?,
                        disk_gib: unsigned(&o, "--disk-gib")?,
                    })
                }
                _ => {
                    let o = opts(&r, &["--verifier-only"], &["--desktop"])?;
                    o.positionals(0, "")?;
                    Ok(Cmd::DesktopPassword {
                        id: desktop_id(&o)?,
                        verifier_only: o.flag("--verifier-only"),
                    })
                }
            }
        }
        "docker" => {
            let (sub, r) = group(&["enable", "disable"])?;
            let o = opts(&r, &["--yes"], &["--desktop"])?;
            o.positionals(0, "")?;
            let id = desktop_id(&o)?;
            if sub == "enable" {
                Ok(Cmd::DockerEnable {
                    id,
                    yes: o.flag("--yes"),
                })
            } else if o.flag("--yes") {
                Err(usage("docker disable asks nothing; --yes does not apply"))
            } else {
                Ok(Cmd::DockerDisable { id })
            }
        }
        "snapshots" => {
            let (sub, r) = group(&["list", "create", "delete"])?;
            let o = opts(&r, &[], &["--desktop"])?;
            let id = desktop_id(&o)?;
            match sub.as_str() {
                "list" => {
                    o.positionals(0, "")?;
                    Ok(Cmd::SnapshotsList { id })
                }
                "create" => {
                    o.positionals(0, "")?;
                    Ok(Cmd::SnapshotsCreate { id })
                }
                _ => {
                    let name = o.positionals(1, "the snapshot name")?[0].clone();
                    if !hx_ipc::privd::is_valid_snapshot_name(&name) {
                        return Err(usage(
                            "the snapshot name must look like hx-manual-20261121T101500Z-ab12",
                        ));
                    }
                    Ok(Cmd::SnapshotsDelete { id, name })
                }
            }
        }
        "logs" => {
            let o = opts(
                rest,
                &["--follow", "-f", "--journal", "--audit"],
                &["--lines", "-n"],
            )?;
            o.positionals(0, "")?;
            let lines = match o.value("--lines").or(o.value("-n")) {
                None => DEFAULT_LINES,
                Some(v) => match v.parse::<u32>() {
                    Ok(n) if (1..=MAX_LINES).contains(&n) => n,
                    _ => return Err(usage(format!("--lines must be 1 to {MAX_LINES}"))),
                },
            };
            let (j, a) = (o.flag("--journal"), o.flag("--audit"));
            Ok(Cmd::Logs {
                follow: o.flag("--follow") || o.flag("-f"),
                lines,
                // Neither flag: both sources.
                journal: j || !a,
                audit: a || !j,
            })
        }
        "update" => {
            let (sub, r) = group(&["check", "apply", "rollback"])?;
            let o = opts(&r, &["--yes"], &[])?;
            match sub.as_str() {
                "check" => {
                    o.positionals(0, "")?;
                    if o.flag("--yes") {
                        return Err(usage("update check asks nothing; --yes does not apply"));
                    }
                    Ok(Cmd::UpdateCheck)
                }
                "apply" => {
                    if o.pos.len() > 1 {
                        return Err(usage("update apply takes at most one version"));
                    }
                    let version = o.pos.first().cloned();
                    if let Some(v) = &version
                        && !hx_ipc::privd::is_valid_update_version(v)
                    {
                        return Err(usage("the version must look like 1.2.3 or 1.2.3-rc.1"));
                    }
                    Ok(Cmd::UpdateApply {
                        version,
                        yes: o.flag("--yes"),
                    })
                }
                _ => {
                    o.positionals(0, "")?;
                    Ok(Cmd::UpdateRollback {
                        yes: o.flag("--yes"),
                    })
                }
            }
        }
        "uninstall" => {
            let o = opts(rest, &["--yes", "--keep-desktop", "--destroy-desktop"], &[])?;
            o.positionals(0, "")?;
            let keep = match (o.flag("--keep-desktop"), o.flag("--destroy-desktop")) {
                (true, true) => {
                    return Err(usage(
                        "--keep-desktop and --destroy-desktop cannot be combined",
                    ));
                }
                (true, false) => Some(true),
                (false, true) => Some(false),
                (false, false) => None,
            };
            Ok(Cmd::Uninstall {
                keep_desktop: keep,
                yes: o.flag("--yes"),
            })
        }
        other => Err(usage(format!(
            "unknown command {:?} (try: hx-agent help)",
            super::text::peer(other, 32)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(a: &[&str]) -> Result<Parsed, CliError> {
        parse(&a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn json_and_help_are_global() {
        assert!(p(&["status", "--json"]).unwrap().json);
        assert!(p(&["--json", "devices", "list"]).unwrap().json);
        assert_eq!(p(&[]).unwrap().cmd, Cmd::Help(None));
        assert_eq!(
            p(&["devices", "--help"]).unwrap().cmd,
            Cmd::Help(Some("devices".into()))
        );
    }

    #[test]
    fn secrets_are_never_arguments() {
        for flag in ["--password", "--pin=123456", "--secret", "--new-password"] {
            let e = p(&["desktop", "password", flag, "x"]).unwrap_err();
            assert!(e.message().contains("never takes a secret"), "{flag}: {e}");
        }
        let e = p(&["pin", "set", "--pin", "123456"]).unwrap_err();
        assert_eq!(e.exit_code(), super::super::error::exit::USAGE);
    }

    #[test]
    fn durations() {
        assert_eq!(parse_secs("90").unwrap(), 90);
        assert_eq!(parse_secs("15m").unwrap(), 900);
        assert_eq!(parse_secs("2h").unwrap(), 7200);
        assert!(parse_secs("").is_err());
        assert!(parse_secs("h").is_err());
        assert!(parse_secs("-5").is_err());
        assert!(parse_secs("99999999999999999999h").is_err());
    }

    #[test]
    fn pairing_token_sources() {
        assert_eq!(
            p(&["pairing", "token"]).unwrap().cmd,
            Cmd::PairingToken {
                source: TokenSource::Prompt,
                ttl_s: 900
            }
        );
        assert!(matches!(
            p(&["pairing", "token", "--generate", "--ttl", "5m"])
                .unwrap()
                .cmd,
            Cmd::PairingToken {
                source: TokenSource::Generate,
                ttl_s: 300
            }
        ));
        assert!(matches!(
            p(&["pairing", "token", "--token=abc"]).unwrap().cmd,
            Cmd::PairingToken {
                source: TokenSource::Argv(_),
                ..
            }
        ));
        assert!(p(&["pairing", "token", "--generate", "--token", "x"]).is_err());
        assert!(p(&["pairing", "code", "--ttl", "10"]).is_err());
        assert!(p(&["pairing", "code", "--ttl", "20m"]).is_err());
    }

    #[test]
    fn desktop_ids_and_snapshot_names_are_validated_at_the_boundary() {
        assert!(p(&["desktop", "stop", "--desktop", "Main"]).is_err());
        assert!(p(&["desktop", "stop", "--desktop", "main; rm"]).is_err());
        assert!(p(&["snapshots", "delete", "../x"]).is_err());
        assert!(p(&["snapshots", "delete", "hx-manual-20261121T101500Z-ab12"]).is_ok());
        assert!(p(&["desktop", "start", "--force"]).is_err());
        assert!(p(&["desktop", "limits", "--cpu", "0"]).is_err());
    }

    #[test]
    fn logs_defaults_to_both_sources() {
        let Cmd::Logs {
            journal,
            audit,
            lines,
            follow,
        } = p(&["logs"]).unwrap().cmd
        else {
            panic!()
        };
        assert!(journal && audit && !follow);
        assert_eq!(lines, 100);
        let Cmd::Logs { journal, audit, .. } = p(&["logs", "--audit"]).unwrap().cmd else {
            panic!()
        };
        assert!(audit && !journal);
        assert!(p(&["logs", "-n", "0"]).is_err());
    }

    #[test]
    fn unknown_things_are_usage_errors() {
        assert!(p(&["frobnicate"]).is_err());
        assert!(p(&["devices"]).is_err());
        assert!(p(&["devices", "list", "extra"]).is_err());
        assert!(p(&["devices", "revoke"]).is_err());
        assert!(p(&["status", "--bogus"]).is_err());
        assert!(p(&["uninstall", "--keep-desktop", "--destroy-desktop"]).is_err());
        assert!(p(&["update", "apply", "1.2"]).is_err());
    }
}
