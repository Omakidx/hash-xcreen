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
  setup begin [--for 2h]          Open the setup window (privd and gatewayd).
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
                                  Remove the agent, with a guided confirmation.
",
    ),
];

const TAIL: &str = "
options:
  --json        Machine-readable output: one JSON object on stdout.
  -h, --help    This text.   --version   The version.

exit codes: 0 ok, 1 failed, 2 usage, 3 a daemon is unavailable, 4 refused by the server,
5 not found or ambiguous, 6 not implemented in this release, 7 not root, 8 declined.
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
