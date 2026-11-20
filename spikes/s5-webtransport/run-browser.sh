#!/usr/bin/env bash
# Usage: ./run-browser.sh chrome|firefox [extra query string, e.g. "frames=300&hw=prefer-software"]
# Starts the release server, drives a headless browser at the test page, waits for the
# browser's report (POST /report) and prints it. Output goes to out/.
set -u
cd "$(dirname "$0")"
browser=${1:-chrome}
query=${2:-frames=300}
mkdir -p out
rm -f "out/report-$browser.json"
PROFILE=$(mktemp -d "$PWD/out/profile.XXXXXX")
target/release/s5-webtransport serve --port 4433 --http-port 8080 --report "out/report-$browser.json" \
  >"out/server-$browser.log" 2>&1 &
SERVER=$!
sleep 1
case "$browser" in
  chrome)
    google-chrome --headless=new --disable-gpu --no-first-run --user-data-dir="$PROFILE" \
      --enable-logging=stderr "http://127.0.0.1:8080/?$query" >"out/$browser.log" 2>&1 &
    ;;
  firefox)
    firefox --headless --no-remote --profile "$PROFILE" "http://127.0.0.1:8080/?$query" \
      >"out/$browser.log" 2>&1 &
    ;;
esac
BROWSER=$!
for _ in $(seq 1 "${WAIT_S:-300}"); do
  [ -s "out/report-$browser.json" ] && break
  sleep 1
done
kill "$BROWSER" 2>/dev/null
kill "$SERVER" 2>/dev/null
sleep 1
rm -rf "$PROFILE"
if [ -s "out/report-$browser.json" ]; then cat "out/report-$browser.json"; echo; else echo "NO REPORT"; fi
