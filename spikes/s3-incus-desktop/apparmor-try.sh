#!/usr/bin/env bash
# Try narrow raw.apparmor snippets on an existing container and report whether the guest's systemd reaches
# "running" (used for Debian 13 on an Ubuntu 26.04 host, where the default non-nesting profile hangs systemd 257).
# Usage: apparmor-try.sh <container>   (run as root; the container is stopped at the end, raw.apparmor unset)
c=${1:-s3-dbg}
incus stop -f "$c" 2>/dev/null; incus config set "$c" security.nesting=false
try() {
  incus stop -f "$c" 2>/dev/null
  incus config set "$c" raw.apparmor="$2"
  incus start "$c"; sleep 20
  echo "$1: $(incus exec "$c" -- systemctl is-system-running 2>&1 | head -1)"
}
try ptrace "ptrace,"
try signal "signal,"
try ptrace+signal $'ptrace,\nsignal,'
incus stop -f "$c"; incus config unset "$c" raw.apparmor
