#!/usr/bin/env bash
# Runs ON the VPS as root (sudo -n). Kills the spike's own processes inside the s2-* containers from the host side.
# Needed because on the VPS (Ubuntu 26.04, kernel 7.0, Incus 6.0.5) AppArmor denies signals between processes started by
# different `incus exec` sessions, so pkill inside the container fails with "Permission denied". Only processes that live in
# the cgroup of an s2-* container and whose comm is in the list below are touched; nothing else on the host is.
for C in s2-desktop s2-client; do
  d=/sys/fs/cgroup/lxc.payload.$C
  [ -d "$d" ] || continue
  for f in $(find "$d" -name cgroup.procs); do
    for p in $(cat "$f"); do
      case "$(cat /proc/$p/comm 2>/dev/null)" in
        s2-server|s2-client|mousepad|mpv|xdotool|scenario.sh|sleep|awk) kill -9 "$p" 2>/dev/null ;;
      esac
    done
  done
done
exit 0
