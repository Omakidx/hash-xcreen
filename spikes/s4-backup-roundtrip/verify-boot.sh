#!/usr/bin/env bash
# Step 7 (boot half): start the restored container and check it is a working desktop.
# usage: verify-boot.sh <container>
set -uo pipefail
ct=${1:-s4-restored}
here=$(cd "$(dirname "$0")" && pwd)
inc() { sg incus-admin -c "incus $*"; }

t0=$(date +%s)
inc "start $ct" 2>&1 | tail -2
st=""
for _ in $(seq 1 60); do
  st=$(inc "exec $ct -- systemctl is-system-running" 2>/dev/null || true)
  [ "$st" = running ] || [ "$st" = degraded ] && break
  sleep 2
done
echo "boot: systemd is-system-running=$st after $(( $(date +%s) - t0 ))s"
inc "exec $ct -- systemctl --failed --no-legend" | head -5
echo "--- hostname / users / uid of alice files"
inc "exec $ct -- sh -c 'hostname; id alice; stat -c \"%U:%G %a %n\" /home/alice/.claude/.credentials.json /home/alice/.codex/auth.json'"
echo "--- AI data present"
inc "exec $ct -- sh -c 'ls /home/alice/.claude/projects/*/*.jsonl | wc -l; ls /home/alice/.codex/sessions/*/*/*/*.jsonl | wc -l; cat /home/alice/.claude/settings.json /home/alice/.claude.json'"
echo "--- excluded caches absent"
inc "exec $ct -- sh -c 'ls -d /home/alice/.cache \"/home/alice/.config/SlackLike/Cache\" \"/home/alice/.config/SlackLike/Code Cache\" /home/alice/.config/SlackLike/GPUCache /home/alice/.config/SlackLike/DawnCache /var/cache/apt 2>&1 | sed s/^/  /; ls /tmp /var/tmp | wc -l'"
echo "--- sqlite (live DB, crash-consistent snapshot)"
inc "exec $ct -- sh -c 'cd /home/alice/.local/share/db && sqlite3 live.sqlite \"pragma integrity_check; select count(*), max(id) from ev; pragma journal_mode;\"'"
echo "--- browser profile DBs"
inc "exec $ct -- sh -c 'for d in History Cookies \"Login Data\" \"Web Data\"; do echo \"\$d: \$(sqlite3 \"/home/alice/.config/chromium/Default/\$d\" \"pragma integrity_check; select count(*) from t\" | paste -sd\" \")\"; done'"
echo "--- package db / apt"
inc "exec $ct -- sh -c 'dpkg --audit | wc -l; dpkg -l | grep -c ^ii; which htop ncdu; dpkg -V 2>&1 | head -3'"
echo "--- XFCE / Xorg"
inc "file push $here/verify-x.sh $ct/root/verify-x.sh --mode 755" >/dev/null 2>&1
inc "exec $ct -- /root/verify-x.sh"
