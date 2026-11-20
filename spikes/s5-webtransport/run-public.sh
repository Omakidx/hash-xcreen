#!/usr/bin/env bash
# Usage: ./run-public.sh chrome|firefox SSH_TARGET URL [extra query string]
# Drives a local headless browser at the test page served by a PUBLIC server (see `serve --cert`)
# and fetches the browser's report from the server (the page POSTs it to /report, the server
# writes it to ~/hx-s5/out/report.json). No certificate flags are passed to the browser.
# Example: ./run-public.sh chrome administrator@85.190.123.74 https://85.190.123.74/ frames=300
set -u
cd "$(dirname "$0")"
browser=${1:-chrome}
target=${2:?ssh target}
url=${3:?page url}
query=${4:-frames=300}
tag=${TAG:-$browser}
mkdir -p out
rm -f "out/public-$tag.json"
ssh -o BatchMode=yes "$target" 'rm -f ~/hx-s5/out/report.json'
PROFILE=$(mktemp -d "$HOME/hx-profile.XXXXXX")   # Firefox snap needs a profile under $HOME
case "$browser" in
  chrome)
    google-chrome --headless=new --disable-gpu --no-first-run --user-data-dir="$PROFILE" \
      --enable-logging=stderr "$url?$query" >"out/public-$tag.log" 2>&1 &
    ;;
  firefox)
    firefox --headless --no-remote --profile "$PROFILE" "$url?$query" >"out/public-$tag.log" 2>&1 &
    ;;
esac
BROWSER=$!
for _ in $(seq 1 "${WAIT_S:-300}"); do
  if ssh -o BatchMode=yes "$target" 'test -s ~/hx-s5/out/report.json'; then
    sleep 1
    scp -q -o BatchMode=yes "$target:hx-s5/out/report.json" "out/public-$tag.json"
    break
  fi
  sleep 2
done
kill "$BROWSER" 2>/dev/null
pkill -f -- "$PROFILE" 2>/dev/null   # the snap Firefox wrapper leaves its child running
sleep 2
rm -rf "$PROFILE"
if [ -s "out/public-$tag.json" ]; then cat "out/public-$tag.json"; echo; else echo "NO REPORT"; fi
