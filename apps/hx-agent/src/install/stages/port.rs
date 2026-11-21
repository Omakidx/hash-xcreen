//! Stage `firewall-port` and the `port-rule` command (design D-Port): open the agent's port.
//!
//! Decision order:
//!
//! 1. **ufw** is active: `ufw allow <p>/tcp` and `<p>/udp`, comment `hash-xcreen`.
//! 2. A native **nftables** input base chain drops (policy `drop`, or a drop/reject rule without an
//!    interface qualifier; the tables `inet hx`, `inet incus` and Docker's are ignored): insert at
//!    the top of that chain `meta l4proto { tcp, udp } th dport <p> accept comment "hx-agent-port"`.
//!    `hx-agent-port.service` (`PartOf=nftables.service`) re-applies it with
//!    `hx-agent port-rule apply`. A ruleset **reload** drops the rule until that unit runs again.
//! 3. **firewalld** is active, or an `iptables` INPUT chain drops: the stage is `manual` and the
//!    exact commands are printed.
//! 4. Otherwise: `none`.
//!
//! Everything goes through the closed tool set. Names that came out of `nft -j list ruleset` are
//! checked against a strict charset before they are used as arguments.

use serde_json::Value;

use super::Outcome;
use crate::install::ctx::Ctx;
use crate::install::error::{InstallError, Result};
use crate::install::runner::{Call, Output, Runner, Tool};
use crate::install::state::PortRule;

/// The nft rule comment.
pub const COMMENT: &str = "hx-agent-port";
/// The ufw rule comment.
pub const UFW_COMMENT: &str = "hash-xcreen";

/// One input chain that blocks, and our rules in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropChain {
    /// `inet`, `ip`, `ip6`.
    pub family: String,
    /// The table.
    pub table: String,
    /// The chain.
    pub chain: String,
    /// Our rules: handle and the port they accept.
    pub ours: Vec<(u64, Option<u16>)>,
}

fn name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn ignored_table(family: &str, table: &str) -> bool {
    (family == "inet" && table == "hx") || table.starts_with("incus") || table.starts_with("docker")
}

fn has_iface_match(expr: &[Value]) -> bool {
    expr.iter().any(|e| {
        e.get("match")
            .and_then(|m| m.get("left"))
            .and_then(|l| l.get("meta"))
            .and_then(|m| m.get("key"))
            .and_then(Value::as_str)
            .is_some_and(|k| matches!(k, "iifname" | "iif" | "iiftype"))
    })
}

fn is_drop(expr: &[Value]) -> bool {
    expr.iter()
        .any(|e| e.get("drop").is_some() || e.get("reject").is_some())
}

fn dport_of(expr: &[Value]) -> Option<u16> {
    expr.iter().find_map(|e| {
        let m = e.get("match")?;
        let f = m.get("left")?.get("payload")?.get("field")?.as_str()?;
        if f != "dport" {
            return None;
        }
        m.get("right")?.as_u64().and_then(|n| u16::try_from(n).ok())
    })
}

/// Reads `nft -j list ruleset` and returns the input base chains that block inbound traffic.
pub fn analyze_nft(json: &str) -> Vec<DropChain> {
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let Some(items) = v.get("nftables").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut chains: Vec<(DropChain, bool)> = Vec::new();
    for it in items {
        if let Some(c) = it.get("chain") {
            let fam = c.get("family").and_then(Value::as_str).unwrap_or("");
            let tab = c.get("table").and_then(Value::as_str).unwrap_or("");
            let name = c.get("name").and_then(Value::as_str).unwrap_or("");
            if c.get("hook").and_then(Value::as_str) != Some("input") || ignored_table(fam, tab) {
                continue;
            }
            if !(name_ok(fam) && name_ok(tab) && name_ok(name)) {
                continue;
            }
            let policy_drop = c.get("policy").and_then(Value::as_str) == Some("drop");
            chains.push((
                DropChain {
                    family: fam.into(),
                    table: tab.into(),
                    chain: name.into(),
                    ours: Vec::new(),
                },
                policy_drop,
            ));
        }
    }
    for it in items {
        let Some(r) = it.get("rule") else { continue };
        let fam = r.get("family").and_then(Value::as_str).unwrap_or("");
        let tab = r.get("table").and_then(Value::as_str).unwrap_or("");
        let name = r.get("chain").and_then(Value::as_str).unwrap_or("");
        let Some((chain, blocks)) = chains
            .iter_mut()
            .find(|(c, _)| c.family == fam && c.table == tab && c.chain == name)
        else {
            continue;
        };
        let expr = r
            .get("expr")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if r.get("comment").and_then(Value::as_str) == Some(COMMENT) {
            if let Some(h) = r.get("handle").and_then(Value::as_u64) {
                chain.ours.push((h, dport_of(&expr)));
            }
            continue;
        }
        if is_drop(&expr) && !has_iface_match(&expr) {
            *blocks = true;
        }
    }
    chains
        .into_iter()
        .filter(|(_, b)| *b)
        .map(|(c, _)| c)
        .collect()
}

fn run(r: &mut dyn Runner, call: &Call) -> Option<Output> {
    r.run(call).ok()
}

/// ufw is installed and active.
pub fn ufw_active(r: &mut dyn Runner) -> bool {
    run(r, &Call::new(Tool::Ufw, &["status"]))
        .is_some_and(|o| o.ok() && o.out_text().contains("Status: active"))
}

fn fail(what: &str, o: Option<Output>) -> InstallError {
    let tail = o.map(|o| o.err_tail()).unwrap_or_default();
    InstallError::tool(format!(
        "{what} failed{}{tail}",
        if tail.is_empty() { "" } else { ": " }
    ))
}

/// Inserts (or keeps) the accept rule in every blocking input chain and removes our rule for
/// another port. Returns whether a blocking chain exists.
pub fn apply_nft(r: &mut dyn Runner, port: u16) -> Result<bool> {
    let Some(list) = run(r, &Call::new(Tool::Nft, &["-j", "list", "ruleset"])).filter(Output::ok)
    else {
        return Ok(false);
    };
    let chains = analyze_nft(&list.out_text());
    let p = port.to_string();
    for c in &chains {
        for (handle, rule_port) in &c.ours {
            if *rule_port != Some(port) {
                let o = run(
                    r,
                    &Call::owned(
                        Tool::Nft,
                        vec![
                            "delete".into(),
                            "rule".into(),
                            c.family.clone(),
                            c.table.clone(),
                            c.chain.clone(),
                            "handle".into(),
                            handle.to_string(),
                        ],
                    ),
                );
                if !o.as_ref().is_some_and(Output::ok) {
                    return Err(fail("removing the old port rule", o));
                }
            }
        }
        if !c.ours.iter().any(|(_, rp)| *rp == Some(port)) {
            let o = run(
                r,
                &Call::owned(
                    Tool::Nft,
                    [
                        "insert",
                        "rule",
                        &c.family,
                        &c.table,
                        &c.chain,
                        "meta",
                        "l4proto",
                        "{",
                        "tcp,",
                        "udp",
                        "}",
                        "th",
                        "dport",
                        &p,
                        "accept",
                        "comment",
                        "\"hx-agent-port\"",
                    ]
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect(),
                ),
            );
            if !o.as_ref().is_some_and(Output::ok) {
                return Err(fail("adding the nftables port rule", o));
            }
        }
    }
    Ok(!chains.is_empty())
}

/// Removes every nft rule of ours (uninstall).
pub fn remove_nft(r: &mut dyn Runner) -> Result<()> {
    let Some(list) = run(r, &Call::new(Tool::Nft, &["-j", "list", "ruleset"])).filter(Output::ok)
    else {
        return Ok(());
    };
    for c in analyze_nft(&list.out_text()) {
        for (handle, _) in &c.ours {
            let o = run(
                r,
                &Call::owned(
                    Tool::Nft,
                    vec![
                        "delete".into(),
                        "rule".into(),
                        c.family.clone(),
                        c.table.clone(),
                        c.chain.clone(),
                        "handle".into(),
                        handle.to_string(),
                    ],
                ),
            );
            if !o.as_ref().is_some_and(Output::ok) {
                return Err(fail("removing the nftables port rule", o));
            }
        }
    }
    Ok(())
}

fn ufw_rules(r: &mut dyn Runner, port: u16, add: bool) -> Result<()> {
    for proto in ["tcp", "udp"] {
        let spec = format!("{port}/{proto}");
        let call = if add {
            Call::owned(
                Tool::Ufw,
                vec!["allow".into(), spec, "comment".into(), UFW_COMMENT.into()],
            )
        } else {
            Call::owned(Tool::Ufw, vec!["delete".into(), "allow".into(), spec])
        };
        let o = run(r, &call);
        if !o.as_ref().is_some_and(Output::ok) {
            return Err(fail("ufw", o));
        }
    }
    Ok(())
}

/// Removes the port rule recorded in the state (uninstall U4).
pub fn remove(r: &mut dyn Runner, rec: &PortRule) -> Result<()> {
    match rec.backend.as_str() {
        "ufw" => ufw_rules(r, rec.port, false),
        "nft" => remove_nft(r),
        _ => Ok(()),
    }
}

fn manual_hint(r: &mut dyn Runner, port: u16) -> Option<String> {
    let firewalld = run(
        r,
        &Call::new(Tool::Systemctl, &["is-active", "--quiet", "firewalld"]),
    )
    .is_some_and(|o| o.ok());
    if firewalld {
        return Some(format!(
            "firewalld is active: run: firewall-cmd --permanent --add-port={port}/tcp --add-port={port}/udp && firewall-cmd --reload"
        ));
    }
    let ipt = run(r, &Call::new(Tool::Iptables, &["-S", "INPUT"])).filter(Output::ok)?;
    let t = ipt.out_text();
    let blocks = t.lines().any(|l| {
        l.starts_with("-P INPUT DROP")
            || ((l.contains("-j DROP") || l.contains("-j REJECT")) && !l.contains(" -i "))
    });
    blocks.then(|| {
        format!(
            "iptables drops inbound traffic: run: iptables -I INPUT -p tcp --dport {port} -j ACCEPT; iptables -I INPUT -p udp --dport {port} -j ACCEPT (and save the rules the way your distribution does)"
        )
    })
}

/// What the stage decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortOutcome {
    /// `ufw`, `nft`, `manual` or `none`.
    pub backend: String,
    /// The commands to run by hand (`manual`).
    pub hint: Option<String>,
}

/// Opens `port`, moving a rule from `previous` if the port changed.
pub fn apply(r: &mut dyn Runner, port: u16, previous: Option<&PortRule>) -> Result<PortOutcome> {
    if ufw_active(r) {
        if let Some(p) = previous
            && p.backend == "ufw"
            && p.port != port
        {
            ufw_rules(r, p.port, false)?;
        }
        ufw_rules(r, port, true)?;
        return Ok(PortOutcome {
            backend: "ufw".into(),
            hint: None,
        });
    }
    if apply_nft(r, port)? {
        return Ok(PortOutcome {
            backend: "nft".into(),
            hint: None,
        });
    }
    if let Some(h) = manual_hint(r, port) {
        return Ok(PortOutcome {
            backend: "manual".into(),
            hint: Some(h),
        });
    }
    Ok(PortOutcome {
        backend: "none".into(),
        hint: None,
    })
}

// ----- the stage ------------------------------------------------------------------------------

/// Done-check: the recorded rule is for this port and still in place (nft re-checked live).
pub fn check(ctx: &mut Ctx<'_>) -> Result<bool> {
    let Some(rec) = ctx.state.created.port_rule.clone() else {
        return Ok(false);
    };
    if rec.port != ctx.opts.port {
        return Ok(false);
    }
    Ok(match rec.backend.as_str() {
        "ufw" => ufw_active(ctx.runner),
        "nft" => {
            // Still there? A reload of the ruleset drops it.
            let Some(list) = run(
                ctx.runner,
                &Call::new(Tool::Nft, &["-j", "list", "ruleset"]),
            )
            .filter(Output::ok) else {
                return Ok(false);
            };
            let chains = analyze_nft(&list.out_text());
            !chains.is_empty()
                && chains
                    .iter()
                    .all(|c| c.ours.iter().any(|(_, p)| *p == Some(rec.port)))
        }
        // Nothing to verify for these.
        _ => true,
    })
}

/// Opens the port and records how.
pub fn run_stage(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    let previous = ctx.state.created.port_rule.clone();
    let out = apply(ctx.runner, ctx.opts.port, previous.as_ref())?;
    ctx.state.created.port_rule = Some(PortRule {
        backend: out.backend.clone(),
        port: ctx.opts.port,
    });
    ctx.log
        .line((ctx.now)(), &format!("port rule: {}", out.backend));
    if out.backend == "nft" {
        // Bring the rule back whenever nftables loads its ruleset again.
        ctx.run_ok(Call::new(
            Tool::Systemctl,
            &["enable", "--now", "hx-agent-port.service"],
        ))?;
    } else if previous.as_ref().is_some_and(|p| p.backend == "nft") {
        let _ = ctx.run(Call::new(
            Tool::Systemctl,
            &["disable", "--now", "hx-agent-port.service"],
        ));
    }
    match out.hint {
        Some(h) => {
            ctx.warn("firewall-port", &h);
            Ok(Outcome::Manual)
        }
        None => Ok(Outcome::Done),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn chain(fam: &str, table: &str, name: &str, hook: &str, policy: &str) -> Value {
        json!({"chain": {"family": fam, "table": table, "name": name, "handle": 1,
                         "type": "filter", "hook": hook, "prio": 0, "policy": policy}})
    }

    fn rule(
        fam: &str,
        table: &str,
        chain: &str,
        handle: u64,
        comment: Option<&str>,
        expr: Value,
    ) -> Value {
        let mut r =
            json!({"family": fam, "table": table, "chain": chain, "handle": handle, "expr": expr});
        if let Some(c) = comment {
            r["comment"] = json!(c);
        }
        json!({"rule": r})
    }

    fn rs(items: Vec<Value>) -> String {
        let mut v = vec![json!({"metainfo": {"version": "1.0.9"}})];
        v.extend(items);
        json!({"nftables": v}).to_string()
    }

    #[test]
    fn a_policy_drop_input_chain_is_found() {
        let j = rs(vec![chain("inet", "filter", "input", "input", "drop")]);
        let c = analyze_nft(&j);
        assert_eq!(c.len(), 1);
        assert_eq!(
            (
                c[0].family.as_str(),
                c[0].table.as_str(),
                c[0].chain.as_str()
            ),
            ("inet", "filter", "input")
        );
    }

    #[test]
    fn an_accepting_chain_without_a_drop_rule_is_not_blocking() {
        let j = rs(vec![
            chain("inet", "filter", "input", "input", "accept"),
            rule(
                "inet",
                "filter",
                "input",
                3,
                None,
                json!([{"match": {"left": {"meta": {"key": "iifname"}}, "op": "==", "right": "lo"}}, {"accept": null}]),
            ),
        ]);
        assert!(analyze_nft(&j).is_empty());
    }

    #[test]
    fn a_drop_rule_blocks_unless_it_names_an_interface() {
        let drop_all = rs(vec![
            chain("ip", "filter", "INPUT", "input", "accept"),
            rule(
                "ip",
                "filter",
                "INPUT",
                4,
                None,
                json!([{"counter": {}}, {"drop": null}]),
            ),
        ]);
        assert_eq!(analyze_nft(&drop_all).len(), 1);
        let reject_all = rs(vec![
            chain("ip", "filter", "INPUT", "input", "accept"),
            rule(
                "ip",
                "filter",
                "INPUT",
                4,
                None,
                json!([{"reject": {"type": "icmp"}}]),
            ),
        ]);
        assert_eq!(analyze_nft(&reject_all).len(), 1);
        let drop_iface = rs(vec![
            chain("ip", "filter", "INPUT", "input", "accept"),
            rule(
                "ip",
                "filter",
                "INPUT",
                4,
                None,
                json!([{"match": {"left": {"meta": {"key": "iifname"}}, "op": "==", "right": "eth9"}}, {"drop": null}]),
            ),
        ]);
        assert!(analyze_nft(&drop_iface).is_empty());
    }

    #[test]
    fn our_tables_and_dockers_are_ignored() {
        let j = rs(vec![
            chain("inet", "hx", "input", "input", "drop"),
            chain("inet", "incus", "in.hxbr0", "input", "drop"),
            chain("ip", "docker-bridges", "x", "input", "drop"),
            chain("inet", "filter", "forward", "forward", "drop"),
        ]);
        assert!(analyze_nft(&j).is_empty());
    }

    #[test]
    fn our_rules_are_recognised_with_their_port() {
        let j = rs(vec![
            chain("inet", "filter", "input", "input", "drop"),
            rule(
                "inet",
                "filter",
                "input",
                7,
                Some(COMMENT),
                json!([
                {"match": {"left": {"meta": {"key": "l4proto"}}, "op": "==", "right": {"set": ["tcp", "udp"]}}},
                {"match": {"left": {"payload": {"protocol": "th", "field": "dport"}}, "op": "==", "right": 8443}},
                {"accept": null}]),
            ),
        ]);
        let c = analyze_nft(&j);
        assert_eq!(c[0].ours, vec![(7, Some(8443))]);
    }

    #[test]
    fn hostile_names_are_never_used() {
        let j = rs(vec![chain("inet", "fil ter;rm", "input", "input", "drop")]);
        assert!(analyze_nft(&j).is_empty());
        assert!(analyze_nft("not json").is_empty());
        assert!(analyze_nft("{}").is_empty());
    }
}
