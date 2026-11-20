#!/usr/bin/env bash
# GPU-less run (software GL / lavapipe) on a private Xvfb display. Results are NOT representative
# of GPU hardware; this only exercises the code paths and gives software-rendering baselines.
#
#   ./run-local-bench.sh [out_dir]
set -uo pipefail
cd "$(dirname "$0")"
OUT="${1:-results/vm}"
mkdir -p "$OUT"
BIN=target/release/s1-slint-video
[ -x "$BIN" ] || cargo build --release
[ -f clip-1080p60.mp4 ] || ./gen-clip.sh

DISP=":$((60 + RANDOM % 30))"
Xvfb "$DISP" -screen 0 1920x1080x24 +extension GLX >/dev/null 2>&1 &
XPID=$!
trap 'kill $XPID 2>/dev/null' EXIT
sleep 1

run() { # name, args...
  local name="$1"; shift
  echo "== $name (load $(cut -d' ' -f1-3 /proc/loadavg))"
  DISPLAY="$DISP" "$BIN" "$@" --allow-cpu-adapter --decode software --bench 15 --warmup 3 \
    --json-out "$OUT/$name.json" >/dev/null 2>"$OUT/$name.stderr" || true
  python3 - "$OUT/$name.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
if d.get("status") != "ok":
    print("   UNAVAILABLE:", d.get("reason")); sys.exit()
v = d["video"]
print("   presented %.1f fps | dropped %.1f%% | d2r p50/p95 %.1f/%.1f ms | interval sd %.1f ms | cpu %.1f cores | %s"
      % (v["presented_fps"], v["dropped_pct"], d["decode_to_render_ms"]["p50"], d["decode_to_render_ms"]["p95"],
         d["present_interval_ms"]["stddev"], (d.get("cpu") or {}).get("process_cores", -1), d["environment"]["presenter"][:60]))
EOF
}

for p in c b a; do
  run "${p}-sw-1080p-overlay"   --path "$p" --window 1920x1080
  run "${p}-sw-720p-overlay"    --path "$p" --window 1280x720
  run "${p}-sw-1080p-nooverlay" --path "$p" --window 1920x1080 --no-overlay
done
