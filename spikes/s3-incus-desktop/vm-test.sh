#!/usr/bin/env bash
# Incus VM desktop: launch an Ubuntu 24.04 VM, apply the basic recipe plus the Docker add-on, then measure.
# Needs /dev/kvm on the host. Run as root. Usage: vm-test.sh [name=s3-vm] [cpu=2] [mem=4GiB]
# Prints boot time (launch to agent ready), build time, Docker results and idle RAM/CPU as seen from inside the VM
# and from the host (the VM's QEMU process).
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
n=${1:-s3-vm} cpu=${2:-2} mem=${3:-4GiB}
bin=${HX_RECIPE:-$here/hx-recipe}
now() { date +%s.%N; }
span() { echo "scale=1; ($2 - $1)/1" | bc; }
ls -l /dev/kvm || { echo "no /dev/kvm"; exit 1; }
incus delete -f "$n" 2>/dev/null
t0=$(now)
incus launch --quiet images:ubuntu/24.04 "$n" --vm -c limits.cpu="$cpu" -c limits.memory="$mem" -c security.secureboot=false
t1=$(now); echo "vm_launch_cmd_s=$(span "$t0" "$t1")"
until incus exec "$n" -- true 2>/dev/null; do sleep 1; [ "$(echo "$(now) - $t0 > 300" | bc)" = 1 ] && { echo "vm agent never came up"; exit 1; }; done
t2=$(now); echo "vm_boot_to_agent_s=$(span "$t0" "$t2")  (launch command + first boot + incus-agent ready)"
"$bin" apply "$here/recipes/ubuntu-24.04-xfce-basic.toml" "$n" --addon "$here/addons/docker-vm.toml" 2>&1 | grep -E 'STAGE|TOTAL|rror'
t3=$(now); echo "vm_apply_s=$(span "$t2" "$t3")"
incus restart "$n"; t4=$(now)
until incus exec "$n" -- true 2>/dev/null; do sleep 1; done
echo "vm_reboot_to_agent_s=$(span "$t4" "$(now)")"
incus exec "$n" -- bash -c 'for i in $(seq 1 120); do systemctl is-active --quiet hx-xorg && pgrep -u 1000 xfce4-panel >/dev/null && exit 0; sleep 1; done; exit 1' \
  && echo "vm_desktop_up_s=$(span "$t4" "$(now)") (reboot to XFCE panel)" || echo "desktop_up=NO"
sleep 90
incus exec "$n" -- bash -c 'apt-get install -y -qq --no-install-recommends scrot imagemagick >/dev/null 2>&1; DISPLAY=:0 XAUTHORITY=/run/hx-xorg/Xauthority xdpyinfo | grep -E "dimensions"; DISPLAY=:0 XAUTHORITY=/run/hx-xorg/Xauthority scrot -o /tmp/shot.png && echo screenshot=ok; Xorg -version 2>&1 | head -2; pgrep -a Xorg | head -2'
c0=$(incus exec "$n" -- awk '/^cpu /{print $2+$3+$4+$7+$8, $5+$6}' /proc/stat)
sleep 60
c1=$(incus exec "$n" -- awk '/^cpu /{print $2+$3+$4+$7+$8, $5+$6}' /proc/stat)
echo "vm_cpu_busy_ticks_over_60s: $(echo "$c0 $c1" | awk '{b=$3-$1; i=$4-$2; printf "busy=%d idle=%d busy_pct=%.2f", b, i, 100*b/(b+i)}')"
incus exec "$n" -- bash -c 'free -m; echo; ps -eo rss,comm --sort=-rss | head -8; echo procs: $(ps -e --no-headers | wc -l)'
echo "host view (QEMU for $n):"
pid=$(pgrep -f "qemu.*$n" | head -1); [ -n "$pid" ] && ps -o rss=,pcpu= -p "$pid" | awk '{printf "qemu_rss_mib=%d qemu_pcpu_avg_since_start=%s\n", $1/1024, $2}'
free -m | sed -n 2p
echo "## docker in the VM (default bridge)"
incus exec "$n" -- runuser -l desk -c 'docker run --rm hello-world | head -4'
incus exec "$n" -- runuser -l desk -c 'docker info --format "driver={{.Driver}} cgroup={{.CgroupDriver}}"'
