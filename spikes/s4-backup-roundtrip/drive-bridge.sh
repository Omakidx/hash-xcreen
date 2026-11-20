#!/usr/bin/env bash
# Start the host-side Drive bridge (REST protocol over the hx Drive backend) for the credential-free worker.
#
#   drive-bridge.sh start      # foreground; run it in its own terminal or with `&`
#   drive-bridge.sh url        # print the S4_REPO_URL that s4ctl.sh needs
#   drive-bridge.sh stats      # Drive call accounting (API calls, bytes, retries, real 4xx/5xx replies)
#
# The Google refresh token stays in the token file on the host (default
# ~/.config/hash-xcreen-spike/drive-token.json) and is read in-process by `s4 serve`. The worker only gets the
# bridge URL with a throw-away random password. Fault injection for demos: S4_FAULTS='upload.create:429:rateLimitExceeded:3'.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
STATE=${S4_STATE_DIR:-$HERE/.drive-state}          # holds bridge password and the repository password; git-ignored
BIN=${S4_BIN:-$HERE/target/release/s4-backup-roundtrip}
TOKEN=${S4_DRIVE_TOKEN:-$HOME/.config/hash-xcreen-spike/drive-token.json}
ROOT=${S4_DRIVE_ROOT:-/hash-xcreen-spike-s4}
LISTEN=${S4_BRIDGE_LISTEN:-10.36.142.1:8765}       # incusbr0 gateway: reachable from containers, not from outside
mkdir -p "$STATE"; chmod 700 "$STATE"
[ -s "$STATE/bridge-pw" ] || { head -c 18 /dev/urandom | base64 | tr -d '/+=' > "$STATE/bridge-pw"; chmod 600 "$STATE/bridge-pw"; }
[ -s "$STATE/repo-pw" ] || { head -c 24 /dev/urandom | base64 > "$STATE/repo-pw"; chmod 600 "$STATE/repo-pw"; }
case "${1:-}" in
  start)
    export S4_CACHE_DIR=${S4_CACHE_DIR:-$STATE/cache}; mkdir -p "$S4_CACHE_DIR"
    exec "$BIN" --repo "hxdrive:$ROOT" --drive-token-file "$TOKEN" --password-file "$STATE/repo-pw" \
      serve --listen "$LISTEN" --bridge-password-file "$STATE/bridge-pw" ;;
  url)   echo "rest:http://s4:$(cat "$STATE/bridge-pw")@$LISTEN/" ;;
  stats) curl -s -u "s4:$(cat "$STATE/bridge-pw")" "http://$LISTEN/_stats"; echo ;;
  *) echo "usage: $0 start|url|stats"; exit 2 ;;
esac
