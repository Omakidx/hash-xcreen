#!/usr/bin/env bash
# Push the freshly built s2-server and scenario driver into the container (run on the host).
set -euo pipefail
C=${C:-s2-desktop}
SPIKE=$(cd "$(dirname "$0")/.." && pwd)
inc() { sg incus-admin -c "incus $*"; }
inc exec "$C" -- pkill s2-server >/dev/null 2>&1 || true
sleep 0.5
inc file push "$SPIKE/target/release/s2-server" "$C/home/desk/s2-server" --mode 755 >/dev/null 2>&1
inc file push "$SPIKE/scripts/scenario.sh" "$C/home/desk/scenario.sh" --mode 755 >/dev/null 2>&1
inc exec "$C" -- chown desk /home/desk/s2-server /home/desk/scenario.sh
echo deployed
