#!/usr/bin/env bash
# VPS matrix (second S3 run): build, host-overhead + idle measurement at the minimum spec and at the
# host's maximum, prebuilt path. Incus, the pool and the bridge must already exist (see run-on-vps.sh).
# Run as root:  HX_RECIPE=/path/to/hx-recipe ./vps-matrix.sh [distro-preset ...]
#   default combinations: ubuntu-24.04-basic ubuntu-24.04-developer debian-13-basic debian-13-developer
# Environment: MAX_CPU (default nproc), MAX_MEM (default host RAM - 1.5 GiB), OUT (results dir).
# Container names: s3-<distro>-<preset> with dots replaced by dashes. A container that already exists is not rebuilt.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd); cd "$here"
OUT=${OUT:-$here/res}; mkdir -p "$OUT"
export HX_RECIPE=${HX_RECIPE:-$here/hx-recipe}
cpus=$(nproc); mem_mib=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
MAX_CPU=${MAX_CPU:-$cpus}; MAX_MEM=${MAX_MEM:-$((mem_mib - 1536))MiB}
combos=${*:-"ubuntu-24.04-basic ubuntu-24.04-developer debian-13-basic debian-13-developer"}
mib() { echo $(( $1 / 1048576 )); }

host_snapshot() { # label -> key=value lines: host RAM seen from the host
  local used avail
  read -r used avail < <(free -m | awk '/^Mem:/{print $3, $7}')
  echo "host[$1] used_mib=$used available_mib=$avail loadavg=$(cut -d' ' -f1-3 /proc/loadavg) incusd_rss_mib=$(ps -C incusd -o rss= | awk '{s+=$1} END{print int(s/1024)}') steal=$(vmstat 1 2 | tail -1 | awk '{print $NF}')"
}
cg() { # container -> memory.current as charged to the host cgroup (MiB)
  mib "$(cat /sys/fs/cgroup/lxc.payload.$1/memory.current 2>/dev/null || cat /sys/fs/cgroup/lxc.payload.$1/../lxc.payload.$1/memory.current)"
}
quiet_host() { # stop every instance but $1 and let the host settle
  for i in $(incus list -c n -f csv); do [ "$i" = "$1" ] || incus stop "$i" 2>/dev/null; done
  sync; sleep 20
}
measure_spec() { # container tag cpu mem
  local n=$1 tag=$2 cpu=$3 mem=$4
  incus stop "$n" 2>/dev/null; quiet_host "$n"
  incus config set "$n" limits.cpu="$cpu" limits.memory="$mem"
  host_snapshot "$n-$tag-before-start" | tee -a "$OUT/host-$n-$tag.txt"
  incus start "$n"
  ./measure.sh "$n" "$OUT/$n-$tag" 90 60 2>&1 | tee "$OUT/measure-$n-$tag.log" | grep -E '^(desktop_up|cpu_avg|mem_|free_|dimensions|---|[ 0-9]+ .*Xorg)'
  host_snapshot "$n-$tag-after-settle" | tee -a "$OUT/host-$n-$tag.txt"
  echo "host-cgroup memory.current of $n: $(cg "$n") MiB (limit $mem)" | tee -a "$OUT/host-$n-$tag.txt"
  free -m | tee -a "$OUT/host-$n-$tag.txt"
}

for combo in $combos; do
  d=${combo%-*}; p=${combo##*-}
  n="s3-$combo"; n=${n//./-}
  echo; echo "######## $d / $p ($n)"
  if ! incus info "$n" >/dev/null 2>&1; then
    quiet_host none
    ./build.sh "recipes/$d-xfce-$p.toml" "$n" 2 4GiB 2>&1 | tee "$OUT/build-$n.log" | grep -E 'STAGE|TOTAL|LAUNCH|loadavg|rror'
  fi
  measure_spec "$n" 2c4g 2 4GiB
  measure_spec "$n" max "$MAX_CPU" "$MAX_MEM"
  incus config set "$n" limits.cpu=2 limits.memory=4GiB
  quiet_host none
  ./prebuilt.sh "$n" "recipes/$d-xfce-$p.toml" "$OUT/export-$n" 2 4GiB 2>&1 | tee "$OUT/prebuilt-$n.log" | grep -E '_s=|_mib=|bytes|TOTAL|loadavg'
  incus delete -f "s3-pre-${n#s3-}" 2>/dev/null
  incus image delete "s3-img-$n" 2>/dev/null
  ls -l "$OUT/export-$n" >> "$OUT/prebuilt-$n.log"
done
echo MATRIX_DONE
