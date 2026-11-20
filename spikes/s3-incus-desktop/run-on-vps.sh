#!/usr/bin/env bash
# Spike S3 on a real VPS: installs Incus on a fresh Ubuntu 24.04 / Debian 13 server and repeats
# the measurements from docs/spikes/s3-incus-desktop.md. Run as root on a THROWAWAY server.
#
#   scp -r spikes/s3-incus-desktop root@vps:/root/ && ssh root@vps /root/s3-incus-desktop/run-on-vps.sh
#
# Environment (all optional):
#   GUEST_DISTROS="ubuntu-24.04 debian-13"   which guests to build
#   PRESETS="basic developer"                which presets to build
#   POOL_GB=30                               btrfs loop-file pool size (GiB)
#   POOL_DEVICE=/dev/vdb                     use a spare block device instead of a loop file
#   HOST_RESERVE_MIB=512                     RAM left to the host; container limit = RAM - reserve
#   HX_RECIPE=/path/to/hx-recipe             prebuilt runner binary (skips the Rust toolchain install)
#   SKIP_DOCKER=1 / SKIP_NET=1               skip those parts
# Output: results-<hostname>-<date>/ with logs and summary.tsv. Nothing leaves the server.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
. /etc/os-release
case "$ID-$VERSION_ID" in
  ubuntu-24.04|debian-13) ;;
  *) echo "unsupported host $ID-$VERSION_ID (need Ubuntu 24.04 or Debian 13)"; exit 1 ;;
esac
GUEST_DISTROS=${GUEST_DISTROS:-"ubuntu-24.04 debian-13"}
PRESETS=${PRESETS:-"basic developer"}
POOL_GB=${POOL_GB:-30}
HOST_RESERVE_MIB=${HOST_RESERVE_MIB:-512}
res="$here/results-$(hostname)-$(date +%Y%m%d-%H%M)"
mkdir -p "$res"
exec > >(tee -a "$res/run.log") 2>&1
now() { date +%s.%N; }
span() { echo "scale=1; ($2 - $1)/1" | bc; }

echo "### host"
nproc; free -m | head -2; df -h / | tail -1; uname -r; echo "disk/network: $(curl -s -m 5 ifconfig.me >/dev/null && echo internet-ok || echo NO-INTERNET)"
cpus=$(nproc); mem_mib=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
cmem=$((mem_mib - HOST_RESERVE_MIB))
echo "container limits: cpu=$cpus memory=${cmem}MiB"
[ "$cpus" -ge 2 ] || echo "WARNING: below the 2 vCPU minimum"

echo "### packages"
t=$(now)
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq incus btrfs-progs bc curl ca-certificates gcc build-essential >/dev/null
echo "incus_install_s=$(span "$t" "$(now)")"
incus --version

echo "### host sysctls (Incus production settings)"
# All unprivileged containers are charged to ONE inotify budget (fs.inotify.max_user_instances,
# default 128, shared with root's own processes). An XFCE session uses dozens of instances,
# so with the default a second desktop, or Docker + dev tools, fails to boot ("Too many open files").
# Set RAISE_INOTIFY=0 to measure with the distro default instead.
echo "before: $(sysctl -n fs.inotify.max_user_instances) instances, $(sysctl -n fs.inotify.max_user_watches) watches"
if [ "${RAISE_INOTIFY:-1}" = 1 ]; then
  printf 'fs.inotify.max_queued_events = 1048576\nfs.inotify.max_user_instances = 1048576\nfs.inotify.max_user_watches = 1048576\nvm.max_map_count = 262144\n' > /etc/sysctl.d/90-hx-incus.conf
  sysctl --system >/dev/null
  echo "after: $(sysctl -n fs.inotify.max_user_instances) instances, $(sysctl -n fs.inotify.max_user_watches) watches"
fi

echo "### incus init (btrfs ${POOL_DEVICE:-loop file ${POOL_GB}GiB})"
if ! incus storage show default >/dev/null 2>&1; then
  if [ -n "${POOL_DEVICE:-}" ]; then
    incus admin init --auto --storage-backend btrfs --storage-create-device "$POOL_DEVICE"
  else
    incus admin init --auto --storage-backend btrfs --storage-create-loop "$POOL_GB"
  fi
fi
incus storage show default | grep -E 'driver|source'

echo "### recipe runner"
bin=${HX_RECIPE:-$here/runner/target/release/hx-recipe}
if [ ! -x "$bin" ]; then
  # Rust toolchain from rustup, pinned. This downloads and runs rustup's installer; fine on a throwaway VPS.
  [ -x "$HOME/.cargo/bin/cargo" ] || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.100.0 >/dev/null
  (. "$HOME/.cargo/env" && cd "$here/runner" && cargo build --release 2>&1 | tail -2)
fi
export HX_RECIPE=$bin

printf 'distro\tpreset\tspec\tbuild_s\tidle_cpu_cores\tfree_strict_mib\tfree_reclaimable_mib\timage_mib\tprebuilt_local_s\tdl_est_100mbps_s\tdl_est_1gbps_s\tdocker\n' > "$res/summary.tsv"

for d in $GUEST_DISTROS; do
  for p in $PRESETS; do
    n="s3-$d-$p"; n=${n//./-}
    r="recipes/$d-xfce-$p.toml"
    echo; echo "######## $d / $p"
    incus delete -f "$n" 2>/dev/null || true
    t=$(now)
    ./build.sh "$r" "$n" "$cpus" "${cmem}MiB" 2>&1 | tee "$res/build-$n.log" | grep -E 'STAGE|TOTAL|LAUNCH|loadavg|error|FAIL'
    build_s=$(grep TOTAL_BUILD "$res/build-$n.log" | awk '{print $2}' | tr -d s)
    ./measure.sh "$n" "$res/$n" 90 60 2>&1 | tee "$res/measure-$n.log" | grep -E '^(desktop_up|cpu_avg|mem_|free_|dimensions)'
    cpu=$(grep ^cpu_avg "$res/measure-$n.log" | cut -d= -f2); fs=$(grep ^free_strict "$res/measure-$n.log" | cut -d= -f2); fr=$(grep ^free_reclaimable "$res/measure-$n.log" | cut -d= -f2)

    ./snapshot-test.sh "$n" 2>&1 | tee "$res/snapshot-$n.log" | grep -E '_s=|_mib='

    ./prebuilt.sh "$n" "$r" "$res/export-$n" "$cpus" "${cmem}MiB" 2>&1 | tee "$res/prebuilt-$n.log" | grep -E '_s=|_mib=|bytes|TOTAL'
    img=$(grep ^image_bytes "$res/prebuilt-$n.log" | sed 's/.*image_mib=//')
    pl=$(grep PREBUILT_LOCAL "$res/prebuilt-$n.log" | sed 's/.*=\([0-9.]*\).*/\1/')
    d100=$(grep download_estimate_100mbps "$res/prebuilt-$n.log" | sed 's/.*=\([0-9.]*\) .*/\1/')
    d1g=$(grep download_estimate_1000mbps "$res/prebuilt-$n.log" | sed 's/.*=\([0-9.]*\) .*/\1/')
    pre="s3-pre-${n#s3-}"
    dk=skipped
    if [ -z "${SKIP_DOCKER:-}" ]; then
      "$bin" apply "$r" "$pre" --addon addons/docker.toml 2>&1 | tee "$res/docker-addon-$n.log" | grep -E 'STAGE|TOTAL|error'
      ./docker-test.sh "$pre" 2>&1 | tee "$res/docker-$n.log" | grep -E 'driver=|hello|persisted|rc='
      grep -q 'Hello from Docker' "$res/docker-$n.log" && dk=hello-world-ok || dk=FAILED
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$d" "$p" "${cpus}c/${cmem}M" "$build_s" "$cpu" "$fs" "$fr" "$img" "$pl" "$d100" "$d1g" "$dk" >> "$res/summary.tsv"
    incus delete -f "$n" "s3-pre-${n#s3-}" 2>/dev/null || true
    incus image delete "s3-img-$n" 2>/dev/null || true
    rm -rf "$res/export-$n"
  done
done

if [ -z "${SKIP_NET:-}" ]; then
  echo "### network isolation test"
  ./net-test.sh 2>&1 | tee "$res/net-test.log"
fi
echo; echo "### summary"; column -t -s$'\t' "$res/summary.tsv"
echo "pass criteria: free_reclaimable >= 1536 MiB on the 2 vCPU/4 GB spec; docker hello-world ok; build < 1200 s; prebuilt (local + estimated download) < 300 s"
echo "results in $res"
