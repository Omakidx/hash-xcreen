#!/usr/bin/env bash
# Step 6: start a backup with a large new data set, SIGKILL the worker mid-run, then retry two
# ways from identical post-kill repository copies:
#   A) retry WITHOUT `repair index` (what a naive rerun does)
#   B) retry WITH `repair index` first (this spike's resume procedure)
# usage: interrupt-test.sh <repo> <kill-after-seconds>
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=${1:?}; kill_after=${2:-10}
inc() { sg incus-admin -c "incus $*"; }
W=s4-worker
sz() { inc "exec $W -- sh -c 'du -sb /repos/$1 | cut -f1; ls /repos/$1/data/*/ 2>/dev/null | grep -vc :; ls /repos/$1/index 2>/dev/null | wc -l'" | paste -sd' '; }

echo "before: bytes,packs,indexfiles = $(sz "$repo")"
( "$here/s4ctl.sh" backup "$repo" --tag bulk-interrupted > /tmp/claude-1000/s4-interrupted.out 2>&1 || true ) &
bgpid=$!
sleep "$kill_after"
inc "exec $W -- pkill -9 -f 'repos/$repo backup'" || true
wait "$bgpid" || true
echo "after kill: bytes,packs,indexfiles = $(sz "$repo")  (snapshots: $(inc "exec $W -- s4 --repo /repos/$repo snapshots" | wc -l))"
# leftover host-side objects from the killed run must be cleaned by the supervisor
inc "snapshot list s4-desktop -f csv" | grep s4-bk || echo "no leftover snapshot (trap cleaned it)"
inc "config device list $W" | tr '\n' ' '; echo

inc "exec $W -- sh -c 'rm -rf /repos/$repo-A /repos/$repo-B; cp -a --reflink=auto /repos/$repo /repos/$repo-A; cp -a --reflink=auto /repos/$repo /repos/$repo-B'"
echo "== A: retry without repair-index"
b0=$(inc "exec $W -- du -sb /repos/$repo-A" | cut -f1)
"$here/s4ctl.sh" backup "$repo-A" --no-repair-index --tag bulk-retry-A 2>&1 | tail -3
echo "A growth bytes: $(( $(inc "exec $W -- du -sb /repos/$repo-A" | cut -f1) - b0 ))  final: $(sz "$repo-A")"
echo "== B: retry with repair-index"
b0=$(inc "exec $W -- du -sb /repos/$repo-B" | cut -f1)
"$here/s4ctl.sh" backup "$repo-B" --tag bulk-retry-B 2>&1 | tail -3
echo "B growth bytes: $(( $(inc "exec $W -- du -sb /repos/$repo-B" | cut -f1) - b0 ))  final: $(sz "$repo-B")"
