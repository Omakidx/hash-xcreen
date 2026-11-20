#!/usr/bin/env bash
# Runs ON the VPS: push the spike binaries and scenario driver into the containers.
set -euo pipefail
S2=${S2:-$HOME/s2}
inc() { sudo -n incus "$@"; }
sudo -n bash "$S2/scripts/vps-kill.sh"
inc file push "$S2/bin/s2-server" s2-desktop/home/desk/s2-server --mode 755 >/dev/null 2>&1
inc file push "$S2/scripts/scenario.sh" s2-desktop/home/desk/scenario.sh --mode 755 >/dev/null 2>&1
inc exec s2-desktop -- chown desk /home/desk/s2-server /home/desk/scenario.sh
inc file push "$S2/bin/s2-client" s2-client/root/s2-client --mode 755 >/dev/null 2>&1
inc exec s2-client -- mkdir -p /tmp/c
echo deployed
