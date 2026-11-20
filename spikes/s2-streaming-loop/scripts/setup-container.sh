#!/usr/bin/env bash
# Reproducible setup of the s2-desktop Incus container. Run on the host (no sudo; needs incus-admin).
# Usage: scripts/setup-container.sh   (from anywhere)
set -euo pipefail
C=${C:-s2-desktop}
inc() { sg incus-admin -c "incus $*"; }
HERE=$(cd "$(dirname "$0")" && pwd)

if ! inc info "$C" >/dev/null 2>&1; then
  inc launch images:ubuntu/24.04 "$C" -c limits.cpu=12-15 -c limits.memory=8GiB
fi
inc config set "$C" limits.cpu 12-15
inc config set "$C" limits.memory 8GiB
until inc exec "$C" -- getent hosts archive.ubuntu.com >/dev/null 2>&1; do sleep 2; done

inc file push "$HERE/inside-setup.sh" "$C/root/inside-setup.sh"
inc exec "$C" -- bash /root/inside-setup.sh
inc file push "$HERE/xorg-dummy.conf" "$C/etc/X11/xorg-s2.conf"
inc file push "$HERE/start-desktop.sh" "$C/usr/local/bin/start-desktop.sh"
inc file push "$HERE/long-doc.sh" "$C/usr/local/bin/long-doc.sh"
inc exec "$C" -- chmod +x /usr/local/bin/start-desktop.sh /usr/local/bin/long-doc.sh
inc exec "$C" -- /usr/local/bin/long-doc.sh
echo "container ready; start with: incus exec $C -- start-desktop.sh"
