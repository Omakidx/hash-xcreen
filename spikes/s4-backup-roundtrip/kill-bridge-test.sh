#!/usr/bin/env bash
# Interrupted-upload experiment against Drive: start a backup through the bridge, then after N seconds SIGKILL the
# bridge (cuts the in-flight Drive upload at TCP level, like a crash or a lost link) and the worker's backup process.
# Afterwards restart the bridge and run `s4ctl.sh backup` again (with `repair index`, the default) or with
# `--no-repair-index` to compare. usage: kill-bridge-test.sh <seconds> [s4ctl backup args...]
# Needs S4_REPO_URL (see drive-bridge.sh url) and the bridge listening on S4_BRIDGE_LISTEN.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
N=${1:-55}; shift || true
LISTEN=${S4_BRIDGE_LISTEN:-10.36.142.1:8765}
"$HERE/drive-bridge.sh" stats > "${TMPDIR:-/tmp}/s4-stats-before-kill.json"
"$HERE/s4ctl.sh" backup drive "$@" > "${TMPDIR:-/tmp}/s4-kill-backup.log" 2>&1 &
BP=$!
sleep "$N"
"$HERE/drive-bridge.sh" stats > "${TMPDIR:-/tmp}/s4-stats-at-kill.json"
pkill -9 -f "serve --listen $LISTEN"
sg incus-admin -c 'incus exec s4-worker -- pkill -9 -x s4'
wait $BP; echo "backup driver exit: $?"
