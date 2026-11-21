//! Usage text. `README.md` carries the long form; this is what `hx-agent help` prints.

const HEAD: &str = "\
hx-agent: local administration of a hash-xcreen server (run as root)

usage: hx-agent [--json] <command> [options]

";

const BLOCKS: &[(&str, &str)] = &[
    (
        "status",
        "\
  status                          Versions, setup phase and window, desktop state, needs-attention
                                  flags, lockouts, device counts.
",
    ),
    (
        "devices",
        "\
  devices list                    The paired devices.
  devices revoke <id-prefix>      Revoke a device and close its live sessions.
  devices reinstate <id-prefix> [--yes]
                                  Lift a revocation (asks first) or a PIN lockout of one device.
",
    ),
    (
        "pairing",
        "\
  pairing code [--ttl 15m]        A short pairing code, printed once.
  pairing token [--ttl 15m] [--generate | --token <t>]
                                  Install a pairing token. Default: a hidden prompt on the
                                  terminal. --generate makes one and prints it once. --token puts
                                  the token on the command line: WEAKER (process list, shell
                                  history, auth log); for unattended installs only.
",
    ),
    (
        "pin",
        "\
  pin set [--device <id-prefix>]  Set the PIN (hidden prompt) for every device or one.
  pin reset-lockout [--purpose pin|password] [--yes]
                                  Clear the WHOLE failure history of a purpose. Audited; asks you
                                  to confirm unless --yes.
",
    ),
    (
        "setup",
        "\
  setup begin [--for 2h] [--yes]  Open the setup window (privd and gatewayd); asks first.
  setup extend <time>             Extend it (24 h in total at most).
  setup finish [--force]          Close it.
",
    ),
    (
        "desktop",
        "\
  desktop start|stop|restart [--force] [--desktop main]
  desktop limits [--cpu N] [--memory-mib N] [--disk-gib N] [--desktop main]
                                  Show or change the resource limits.
  desktop password [--verifier-only] [--desktop main]
                                  Change the Linux password (hidden prompt) and refresh the
                                  gateway's password verifier.
",
    ),
    (
        "docker",
        "\
  docker enable [--yes] [--desktop main]   Turn Docker on in the desktop (lowers isolation).
  docker disable [--desktop main]          Turn it off (restarts the desktop).
",
    ),
    (
        "snapshots",
        "\
  snapshots list|create [--desktop main]
  snapshots delete <name> [--desktop main]
",
    ),
    (
        "logs",
        "\
  logs [-f|--follow] [-n <lines>] [--journal] [--audit]
                                  The journal of the hx units and the audit log.
",
    ),
    (
        "update",
        "\
  update check
  update apply [<version>] [--yes]
  update rollback [--yes]
",
    ),
    (
        "uninstall",
        "\
  uninstall [--keep-desktop | --destroy-desktop] [--yes]
                                  Remove the agent (units, files, port rule, gateway user) and,
                                  with --destroy-desktop, the desktop; with a guided confirmation.
",
    ),
    (
        "install",
        "\
  install --interactive | --pair | --ssh | --token <t>  [options]
                                  Install and set up the server (normally run by install.sh).
                                  --interactive  ask every question on the terminal
                                  --pair         the one-liner: type the pairing token at a hidden
                                                 prompt; stops after installing it
                                  --ssh          secrets on stdin (framed), JSON Lines on stdout
                                  --token <t>    like --pair, but the token is on the command line:
                                                 WEAKER (process list, shell history, auth log)
                                  Run again to resume or to re-verify; a finished install says so.
  options: --distro ubuntu-24.04|ubuntu-26.04|debian-12|debian-13  --desktop xfce
           --user <name>  --hostname <h>  --timezone <tz>  --locale <l>  --keyboard <k>
           --apps basic|developer  --docker  --cpu <n>  --memory <MiB|NG>  --disk <GiB>
           --storage-device /dev/<disk>  --image auto|build  --port <1-65535, not 22 or 80>
           --domain <fqdn>  --backup off|12h|24h  --backup-keep <n>  --channel stable|beta
           --allow-private-networks  --bootstrap-dir <dir>  --lock-fd <n>
  port-rule apply                 Re-apply the nftables rule for the public port (a unit runs it).
",
    ),
];

const TAIL: &str = "
options:
  --json        Machine-readable output: one JSON object on stdout.
  -h, --help    This text.   --version   The version.

exit codes: 0 ok, 1 failed, 2 usage, 3 a daemon is unavailable, 4 refused by the server,
5 not found or ambiguous, 6 not implemented in this release, 7 not root, 8 declined.
install and uninstall also use: 9 preflight failed (nothing changed), 10 verification failed,
11 another install or uninstall is running, 12 the options conflict with the existing install.
";

/// The usage text, for one verb (`status`, `devices`, ...) or the whole thing.
pub fn text(topic: Option<&str>) -> String {
    let mut s = String::from(HEAD);
    match topic.and_then(|t| BLOCKS.iter().find(|(n, _)| *n == t)) {
        Some((_, b)) => s.push_str(b),
        None => {
            for (_, b) in BLOCKS {
                s.push_str(b);
            }
        }
    }
    s.push_str(TAIL);
    s
}
