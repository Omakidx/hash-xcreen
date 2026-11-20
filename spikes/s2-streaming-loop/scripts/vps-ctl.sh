#!/usr/bin/env bash
# Runs ON the VPS. Configuration B plumbing: expose s2-server (UDP 4433 inside s2-desktop) on a high UDP port of the host
# through an Incus userspace proxy device (no firewall or network changes), and remove it again.
#   vps-ctl.sh proxy-add [port]   (default 47433)
#   vps-ctl.sh proxy-del
#   vps-ctl.sh cpu-shared | cpu-pinned
set -euo pipefail
inc() { sudo -n incus "$@"; }
case ${1:-} in
  proxy-add)
    port=${2:-47433}
    inc config device add s2-desktop s2proxy proxy "listen=udp:0.0.0.0:$port" connect=udp:127.0.0.1:4433
    echo "proxy udp/$port -> s2-desktop:4433" ;;
  proxy-del) inc config device remove s2-desktop s2proxy; echo removed ;;
  cpu-shared) inc config unset s2-desktop limits.cpu 2>/dev/null || true; inc config unset s2-client limits.cpu 2>/dev/null || true ;;
  cpu-pinned) inc config set s2-desktop limits.cpu 1-3; inc config set s2-client limits.cpu 0 ;;
  *) echo "usage: $0 proxy-add [port] | proxy-del | cpu-shared | cpu-pinned"; exit 2 ;;
esac
