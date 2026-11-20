#!/usr/bin/env bash
# Host-side driver for the S4 spike. Every incus call goes through `sg incus-admin` because the
# login session does not have the group active. Production equivalent: hx-privd (root) does the
# snapshot + read-only mount, a sandboxed worker runs the backup, then the snapshot is deleted.
#
#   s4ctl.sh backup  <repo-name> [extra s4 backup args...]   # snapshot -> ro mount -> backup -> cleanup
#   s4ctl.sh init    <repo-name> <zstd-level>
#   s4ctl.sh w       <args...>                                # run `s4` in the worker with --repo /repos/<name>
#   s4ctl.sh restore <repo-name> <container> [snapshot]       # restore into an (empty) container's rootfs
set -euo pipefail
SRC=${S4_SRC:-s4-desktop}
WORKER=${S4_WORKER:-s4-worker}
POOL=/var/lib/incus/storage-pools/default
S4_REPOS=${S4_REPOS:-/tmp/claude-1000/-home-z11-desktop--claude-spares-spare-UB6ukz/edb16c05-ab51-4f18-98dc-0c91687db632/scratchpad/repos}
inc() { sg incus-admin -c "incus $*"; }
# S4_REPO_URL (for example rest:http://s4:<bridge-password>@10.36.142.1:8765/) replaces the local /repos/<name>
# repository: the worker then talks to the host-side Drive bridge (`s4 serve`) and never holds Google credentials.
repo_arg() { if [ -n "${S4_REPO_URL:-}" ]; then printf %s "--repo $S4_REPO_URL"; else printf %s "--repo /repos/$1"; fi; }

cmd=${1:?}; shift
case "$cmd" in
  init)
    repo=$1; lvl=$2
    inc "exec $WORKER -- s4 $(repo_arg $repo) init --compression $lvl" ;;
  w)
    repo=$1; shift
    inc "exec $WORKER -- s4 $(repo_arg $repo) $*" ;;
  backup)
    repo=$1; shift
    snap=s4-bk-$(date +%s)
    t0=$(date +%s.%N)
    inc "snapshot create $SRC $snap"
    t1=$(date +%s.%N)
    inc "config device add $WORKER src disk source=$POOL/containers-snapshots/$SRC/$snap path=/src readonly=true shift=true" >/dev/null
    trap 'inc "config device remove $WORKER src" >/dev/null 2>&1 || true; inc "snapshot delete $SRC $snap" >/dev/null 2>&1 || true' EXIT
    echo "{\"snapshot_create_s\": $(awk "BEGIN{print $t1 - $t0}")}"
    # tree root of the snapshot is /src/rootfs; /src/backup.yaml holds the container config
    inc "exec $WORKER -- cat /src/backup.yaml" > "/tmp/claude-1000/s4-${snap}-backup.yaml" 2>/dev/null || true
    inc "file push $(dirname "$0")/manifest.py $WORKER/usr/local/bin/manifest.py --mode 755" >/dev/null 2>&1
    inc "exec $WORKER -- sh -c 'python3 /usr/local/bin/manifest.py > /tmp/manifest.json'"
    if [ -n "${S4_SUM:-}" ]; then   # source-of-truth tree description of this exact snapshot
      inc "file push $(dirname "$0")/treesum.py $WORKER/usr/local/bin/treesum.py --mode 755" >/dev/null 2>&1
      inc "exec $WORKER -- sh -c 'mkdir -p /repos/_sums && s4 --repo /x excludes --source /src/rootfs > /repos/_sums/$S4_SUM.excl && python3 /usr/local/bin/treesum.py /src/rootfs /repos/_sums/$S4_SUM.excl > /repos/_sums/$S4_SUM.src.txt'"
    fi
    # $repo may be a comma-separated list: every repository is backed up from the SAME snapshot
    for r in ${repo//,/ }; do
      echo "== repo $r"
      inc "exec $WORKER -- nice -n 19 ionice -c3 s4 $(repo_arg $r) backup --source /src/rootfs --description-file /tmp/manifest.json $*"
      [ -z "${S4_REPO_URL:-}" ] && du -sb "$S4_REPOS/$r" 2>/dev/null | awk '{print "{\"repo_bytes_after\":" $1 "}"}'
    done
    ;;
  restore)
    repo=$1; ct=$2; snap=${3:-latest}
    inc "config device add $WORKER target disk source=$POOL/containers/$ct path=/target shift=true" >/dev/null
    trap 'inc "config device remove $WORKER target" >/dev/null 2>&1 || true' EXIT
    inc "exec $WORKER -- s4 $(repo_arg $repo) restore --snapshot $snap --dest /target/rootfs --sparse"
    ;;
  *) echo "unknown $cmd"; exit 2 ;;
esac
