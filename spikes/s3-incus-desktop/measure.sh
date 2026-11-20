#!/usr/bin/env bash
# Idle measurement of the desktop container: waits for Xorg + XFCE, takes a screenshot,
# then samples memory and CPU for a window. Prints key=value lines (parse with grep).
# Usage: measure.sh <container> <outdir> [settle_s=90] [window_s=60]
set -euo pipefail
c=$1 out=$2 settle=${3:-90} window=${4:-60}
mkdir -p "$out"
ix() { incus exec "$c" -- bash -c "$1"; }

echo "container=$c"
echo "loadavg_host $(cut -d' ' -f1-3 /proc/loadavg)"
ix 'for i in $(seq 1 90); do systemctl is-active --quiet hx-xorg && pgrep -u 1000 xfce4-panel >/dev/null && exit 0; sleep 1; done; exit 1' \
  && echo "desktop_up=yes" || { echo "desktop_up=NO"; ix 'systemctl status hx-xorg --no-pager | head -20; tail -20 /var/log/hx-xorg.log || true'; exit 1; }

# Tools for the screenshot only (not part of any recipe); installed before the idle window.
ix 'apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends scrot imagemagick >/dev/null 2>&1' || true
echo "settling ${settle}s"
sleep "$settle"

ix 'DISPLAY=:0 XAUTHORITY=/run/hx-xorg/Xauthority xdpyinfo | grep -E "dimensions|version number"' || true
ix 'DISPLAY=:0 XAUTHORITY=/run/hx-xorg/Xauthority scrot -o /tmp/shot.png && convert /tmp/shot.png -resize 1280x720 -colors 64 /tmp/shot-small.png' || echo "screenshot=FAILED"
incus file pull "$c/tmp/shot.png" "$out/screenshot-full.png" 2>/dev/null || true
incus file pull "$c/tmp/shot-small.png" "$out/screenshot.png" 2>/dev/null || true

# CPU: usage_usec delta over the window from the container's own cgroup.
cpu0=$(ix 'awk "/^usage_usec/{print \$2}" /sys/fs/cgroup/cpu.stat')
sleep "$window"
cpu1=$(ix 'awk "/^usage_usec/{print \$2}" /sys/fs/cgroup/cpu.stat')
echo "cpu_avg_cores=$(echo "scale=4; ($cpu1 - $cpu0) / ($window * 1000000)" | bc)"

ix 'lim=$(cat /sys/fs/cgroup/memory.max); cur=$(cat /sys/fs/cgroup/memory.current)
  st() { awk -v k="$1" "\$1==k{print \$2}" /sys/fs/cgroup/memory.stat; }
  anon=$(st anon); file=$(st file); shmem=$(st shmem); kern=$(st kernel); slab=$(st slab); inact=$(st inactive_file)
  mib() { echo $(( $1 / 1048576 )); }
  echo "mem_limit_mib=$(mib $lim)"
  echo "mem_current_mib=$(mib $cur)"
  echo "mem_anon_mib=$(mib $anon)"
  echo "mem_file_cache_mib=$(mib $file)"
  echo "mem_shmem_mib=$(mib $shmem)"
  echo "mem_kernel_mib=$(mib ${kern:-0})"
  # free_strict: limit minus everything charged (page cache counted as used, lower bound)
  echo "free_strict_mib=$(mib $((lim - cur)))"
  # free_reclaimable: limit minus anon, shmem and kernel memory (page cache is reclaimable)
  echo "free_reclaimable_mib=$(mib $((lim - anon - shmem - ${kern:-0})))"
  echo "--- free -m (lxcfs view)"; free -m
  echo "--- top RSS"; ps -eo rss,comm --sort=-rss | head -12
  echo "--- procs: $(ps -e --no-headers | wc -l)"'
