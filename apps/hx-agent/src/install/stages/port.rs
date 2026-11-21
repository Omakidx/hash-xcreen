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
//! **Where the nft rule goes.** The rule is inserted at the TOP of the blocking input chain
//! (`nft insert`), before every other rule, so that the chain's own drop rules cannot shadow it. The
//! consequence is that it also comes before anything the administrator put at the top on purpose
//! (a fail2ban or geo-blocking rule): for this one port, tcp and udp, traffic from every source is
//! accepted ahead of them. That is the intended meaning of "open the agent's port"; an operator who
//! wants source restrictions uses `--port` with their own rules, or the `manual` path.
//!
//! **Bookkeeping.** The planned rule is recorded in the state before it is inserted, so that a
//! failure half way is still removed by uninstall. At removal our comment is searched in EVERY input
//! chain (not only the chains that still drop), and an unreadable state falls back to searching nft
//! by comment and ufw by its comment. A ufw rule that already existed (`ufw` answers "Skipping
//! adding existing rule") is `adopted`: it was the administrator's, and uninstall does not delete it.
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

/// Reads `nft -j list ruleset`: every input base chain (outside the tables we ignore), whether it
/// blocks inbound traffic, and our rules in it.
fn analyze_all(json: &str) -> Vec<(DropChain, bool)> {
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
}

/// The input base chains that block inbound traffic.
pub fn analyze_nft(json: &str) -> Vec<DropChain> {
    analyze_all(json)
        .into_iter()
        .filter(|(_, blocks)| *blocks)
        .map(|(c, _)| c)
        .collect()
}

/// Every input base chain that holds a rule of ours, blocking or not.
pub fn analyze_ours(json: &str) -> Vec<DropChain> {
    analyze_all(json)
        .into_iter()
        .filter(|(c, _)| !c.ours.is_empty())
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

fn delete_rule(r: &mut dyn Runner, c: &DropChain, handle: u64) -> Result<()> {
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
    if o.as_ref().is_some_and(Output::ok) {
        Ok(())
    } else {
        Err(fail("removing the nftables port rule", o))
    }
}

/// Inserts (or keeps) the accept rule at the top of every blocking input chain and removes our rule
/// for another port, and our rules in chains that no longer block. Returns whether a blocking
/// chain exists.
pub fn apply_nft(r: &mut dyn Runner, port: u16) -> Result<bool> {
    let Some(list) = run(r, &Call::new(Tool::Nft, &["-j", "list", "ruleset"])).filter(Output::ok)
    else {
        return Ok(false);
    };
    let chains = analyze_all(&list.out_text());
    let p = port.to_string();
    let mut any_blocking = false;
    for (c, blocks) in &chains {
        if !*blocks {
            // The chain stopped dropping: a rule of ours in it is stale.
            for (handle, _) in &c.ours {
                delete_rule(r, c, *handle)?;
            }
            continue;
        }
        any_blocking = true;
        for (handle, rule_port) in &c.ours {
            if *rule_port != Some(port) {
                delete_rule(r, c, *handle)?;
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
    Ok(any_blocking)
}

/// Removes every nft rule of ours, in every input chain whether it still drops or not.
pub fn remove_nft(r: &mut dyn Runner) -> Result<()> {
    let Some(list) = run(r, &Call::new(Tool::Nft, &["-j", "list", "ruleset"])).filter(Output::ok)
    else {
        return Ok(());
    };
    for c in analyze_ours(&list.out_text()) {
        for (handle, _) in &c.ours {
            delete_rule(r, &c, *handle)?;
        }
    }
    Ok(())
}

const PROTOS: [&str; 2] = ["tcp", "udp"];

/// `ufw allow <port>/<proto> comment hash-xcreen`. Returns true when the rule already existed
/// ("Skipping adding existing rule").
fn ufw_add(r: &mut dyn Runner, port: u16, proto: &str) -> Result<bool> {
    let o = run(
        r,
        &Call::owned(
            Tool::Ufw,
            vec![
                "allow".into(),
                format!("{port}/{proto}"),
                "comment".into(),
                UFW_COMMENT.into(),
            ],
        ),
    );
    match o {
        Some(o) if o.ok() => Ok(o.out_text().contains("Skipping adding existing rule")),
        o => Err(fail("ufw", o)),
    }
}

fn ufw_delete(r: &mut dyn Runner, port: u16, proto: &str) -> Result<()> {
    let o = run(
        r,
        &Call::owned(
            Tool::Ufw,
            vec!["delete".into(), "allow".into(), format!("{port}/{proto}")],
        ),
    );
    if o.as_ref().is_some_and(Output::ok) {
        Ok(())
    } else {
        Err(fail("ufw", o))
    }
}

/// Removes the port rule recorded in the state (uninstall U4). A ufw protocol that was `adopted`
/// is left alone: it was the administrator's rule.
pub fn remove(r: &mut dyn Runner, rec: &PortRule) -> Result<()> {
    match rec.backend.as_str() {
        "ufw" => {
            for proto in PROTOS {
                if !rec.adopted.iter().any(|a| a == proto) {
                    ufw_delete(r, rec.port, proto)?;
                }
            }
            Ok(())
        }
        "nft" => remove_nft(r),
        _ => Ok(()),
    }
}

/// With no readable state: our nft rules by their comment, and the ufw rules that carry our
/// comment (`ufw show added` lists them as `ufw allow 443/tcp comment 'hash-xcreen'`). A ufw rule
/// without our comment is never touched.
pub fn remove_fallback(r: &mut dyn Runner) -> Result<()> {
    remove_nft(r)?;
    let Some(o) = run(r, &Call::new(Tool::Ufw, &["show", "added"])).filter(Output::ok) else {
        return Ok(());
    };
    for line in o.out_text().lines() {
        let l = line.trim();
        let Some(rest) = l.strip_prefix("ufw ") else {
            continue;
        };
        let Some((spec, tail)) = rest.split_once(" comment ") else {
            continue;
        };
        if tail.trim().trim_matches('\'') != UFW_COMMENT {
            continue;
        }
        let words: Vec<&str> = spec.split_whitespace().collect();
        let plain = words.len() == 2
            && words[0] == "allow"
            && words[1]
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'/' || b.is_ascii_lowercase());
        if plain {
            let o = run(
                r,
                &Call::owned(
                    Tool::Ufw,
                    vec!["delete".into(), "allow".into(), words[1].to_owned()],
                ),
            );
            if !o.as_ref().is_some_and(Output::ok) {
                return Err(fail("ufw", o));
            }
        }
    }
    Ok(())
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

/// What the stage decided, before it does anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// ufw is active.
    Ufw,
    /// A native nftables input chain drops.
    Nft,
    /// firewalld or iptables blocks: the commands for the operator.
    Manual(String),
    /// Nothing blocks.
    Nothing,
}

impl Plan {
    /// The backend name recorded in the state.
    pub fn backend(&self) -> &'static str {
        match self {
            Self::Ufw => "ufw",
            Self::Nft => "nft",
            Self::Manual(_) => "manual",
            Self::Nothing => "none",
        }
    }
}

/// Reads the firewall (no change) and decides.
pub fn plan(r: &mut dyn Runner, port: u16) -> Plan {
    if ufw_active(r) {
        return Plan::Ufw;
    }
    let blocking = run(r, &Call::new(Tool::Nft, &["-j", "list", "ruleset"]))
        .filter(Output::ok)
        .is_some_and(|l| !analyze_nft(&l.out_text()).is_empty());
    if blocking {
        return Plan::Nft;
    }
    match manual_hint(r, port) {
        Some(h) => Plan::Manual(h),
        None => Plan::Nothing,
    }
}

/// What the stage did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortOutcome {
    /// `ufw`, `nft`, `manual` or `none`.
    pub backend: String,
    /// The commands to run by hand (`manual`).
    pub hint: Option<String>,
    /// ufw protocols whose rule already existed (not ours to delete).
    pub adopted: Vec<String>,
}

/// Carries out `plan` for `port`, moving a rule from `previous` if the port or backend changed.
/// `checkpoint` is called with the rule as recorded so far after every step that changes the host,
/// so that the caller can persist it.
pub fn execute(
    r: &mut dyn Runner,
    plan: &Plan,
    port: u16,
    previous: Option<&PortRule>,
    checkpoint: &mut dyn FnMut(&PortRule),
) -> Result<PortOutcome> {
    // A rule of another backend or port is ours to move, never an adopted one.
    if let Some(p) = previous
        && (p.backend != plan.backend() || p.port != port)
    {
        remove(r, p)?;
    }
    let same = previous.filter(|p| p.backend == plan.backend() && p.port == port);
    let mut adopted = same.map(|p| p.adopted.clone()).unwrap_or_default();
    match plan {
        Plan::Ufw => {
            for proto in PROTOS {
                let existed = ufw_add(r, port, proto)?;
                // First sight of a rule that was already there: the administrator's.
                if existed && same.is_none() && !adopted.iter().any(|a| a == proto) {
                    adopted.push(proto.to_owned());
                }
                checkpoint(&PortRule {
                    backend: "ufw".into(),
                    port,
                    adopted: adopted.clone(),
                });
            }
        }
        Plan::Nft => {
            apply_nft(r, port)?;
        }
        Plan::Manual(_) | Plan::Nothing => {}
    }
    Ok(PortOutcome {
        backend: plan.backend().to_owned(),
        hint: match plan {
            Plan::Manual(h) => Some(h.clone()),
            _ => None,
        },
        adopted,
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
    let port = ctx.opts.port;
    let previous = ctx.state.created.port_rule.clone();
    let plan = plan(ctx.runner, port);
    // Record the planned rule BEFORE touching the firewall, so that a failure half way is still
    // found (and removed) by uninstall.
    let same = previous
        .as_ref()
        .filter(|p| p.backend == plan.backend() && p.port == port);
    ctx.state.created.port_rule = Some(PortRule {
        backend: plan.backend().to_owned(),
        port,
        adopted: same.map(|p| p.adopted.clone()).unwrap_or_default(),
    });
    ctx.save_state()?;
    let out = {
        let path = ctx.paths.at(crate::install::paths::STATE_FILE);
        let state = &mut ctx.state;
        let runner = &mut *ctx.runner;
        let mut checkpoint = |rule: &PortRule| {
            state.created.port_rule = Some(rule.clone());
            let _ = crate::install::state::save(&path, state);
        };
        execute(runner, &plan, port, previous.as_ref(), &mut checkpoint)?
    };
    ctx.state.created.port_rule = Some(PortRule {
        backend: out.backend.clone(),
        port,
        adopted: out.adopted.clone(),
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
