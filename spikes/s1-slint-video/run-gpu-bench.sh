#!/usr/bin/env bash
# Run the S1 benchmark matrix on a Linux PC with an Intel/AMD GPU and collect the results into a
# single tarball to send back. See RUN_ON_GPU.md for prerequisites.
#
#   ./run-gpu-bench.sh [--secs 20] [--window 1920x1080] [--no-build] [--skip-clip]
#
# Run it from a real desktop session (Wayland recommended: Ubuntu 24.04 default), on AC power,
# with nothing else heavy running. Do not touch the mouse/keyboard while a case is running.
set -uo pipefail
cd "$(dirname "$0")"

SECS=20
WINDOW=1920x1080
BUILD=1
CLIP=1
while [ $# -gt 0 ]; do
  case "$1" in
    --secs) SECS="$2"; shift 2 ;;
    --window) WINDOW="$2"; shift 2 ;;
    --no-build) BUILD=0; shift ;;
    --skip-clip) CLIP=0; shift ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="results/gpu-$(hostname)-${STAMP}"
mkdir -p "$OUT"
BIN=target/release/s1-slint-video
LOG="$OUT/run.log"
exec > >(tee -a "$LOG") 2>&1

echo "== S1 GPU benchmark, $(date -Is) =="

# ---- system information -------------------------------------------------------------------
{
  echo "### uname";           uname -a
  echo "### os-release";      cat /etc/os-release
  echo "### session";         echo "XDG_SESSION_TYPE=${XDG_SESSION_TYPE:-} DISPLAY=${DISPLAY:-} WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-}"
  echo "### cpu";             lscpu | head -20
  echo "### gpu (lspci)";     lspci -nnk 2>/dev/null | grep -A3 -E "VGA|3D|Display"
  echo "### dri";             ls -l /dev/dri 2>&1
  echo "### loadavg";         cat /proc/loadavg
  echo "### power";           cat /sys/class/power_supply/*/online 2>/dev/null | tr '\n' ' '; echo
  echo "### cpu governor";    cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>&1
  echo "### vainfo";          vainfo 2>&1
  echo "### glxinfo/eglinfo"; (eglinfo -B 2>&1 | head -30) || true
  echo "### vulkaninfo";      (vulkaninfo --summary 2>&1 | head -40) || true
  echo "### ffmpeg";          ffmpeg -hide_banner -version | head -1
} > "$OUT/system-info.txt" 2>&1

# ---- pre-flight ---------------------------------------------------------------------------
if ! ls /dev/dri/renderD* >/dev/null 2>&1; then
  echo "ERROR: no /dev/dri/renderD* node: this machine does not expose a GPU render node." >&2
  echo "       Cases that need VAAPI will report 'unavailable'; results will not be GPU results." >&2
fi
if ! command -v vainfo >/dev/null; then
  echo "WARNING: vainfo not installed (apt install vainfo); see RUN_ON_GPU.md" >&2
fi
if [ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
  echo "ERROR: no DISPLAY / WAYLAND_DISPLAY: run this from a graphical session." >&2
  exit 1
fi
if [ "${XDG_SESSION_TYPE:-}" != "wayland" ]; then
  echo "NOTE: session is '${XDG_SESSION_TYPE:-unknown}', not Wayland. On X11 Slint creates a GLX context, so"
  echo "      path b cannot import DMA-BUFs (it needs EGL); it will fall back to reporting that." >&2
fi

# ---- build + clip -------------------------------------------------------------------------
if [ "$BUILD" = 1 ]; then
  echo "== cargo build --release =="
  cargo build --release || { echo "build failed"; exit 1; }
fi
if [ "$CLIP" = 1 ] && [ ! -f clip-1080p60.mp4 ]; then
  echo "== generating clip =="
  ./gen-clip.sh || { echo "clip generation failed"; exit 1; }
fi

"$BIN" --detect | tee "$OUT/detect.txt"

# ---- matrix -------------------------------------------------------------------------------
# name | args
CASES=(
  "c-sw|--path c --decode software"
  "c-vaapi-download|--path c --decode vaapi"
  "a-vaapi-dmabuf|--path a --decode vaapi"
  "a-vaapi-download|--path a --decode vaapi --no-dmabuf"
  "b-vaapi-dmabuf|--path b --decode vaapi"
  "b-vaapi-download|--path b --decode vaapi --no-dmabuf"
  "b-vaapi-dmabuf-gl33|--path b --decode vaapi --gl gl33"
  "a-vaapi-dmabuf-sync|--path a --decode vaapi --sync"
  "b-vaapi-dmabuf-sync|--path b --decode vaapi --sync"
  "c-vaapi-no-overlay|--path c --decode vaapi --no-overlay"
  "b-vaapi-dmabuf-no-overlay|--path b --decode vaapi --no-overlay"
)

for entry in "${CASES[@]}"; do
  name="${entry%%|*}"; args="${entry#*|}"
  echo
  echo "== case ${name}: ${args} (load: $(cut -d' ' -f1-3 /proc/loadavg)) =="
  # shellcheck disable=SC2086
  "$BIN" $args --bench "$SECS" --warmup 3 --window "$WINDOW" --json-out "$OUT/${name}.json" > "$OUT/${name}.stdout" 2> "$OUT/${name}.stderr"
  rc=$?
  echo "   exit code $rc; stderr tail:"; tail -n 4 "$OUT/${name}.stderr" | sed 's/^/   | /'
  if [ -f "$OUT/${name}.json" ] && command -v python3 >/dev/null; then
    python3 - "$OUT/${name}.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
if d.get("status") != "ok":
    print("   -> UNAVAILABLE:", d.get("reason"))
else:
    c = d["s1_criteria"]; v = d["video"]
    print("   -> fps %.1f  dropped %.2f%%  d2r p50/p95 %.2f/%.2f ms  interval sd %.2f ms  cpu %.2f cores"
          % (v["presented_fps"], v["dropped_pct"], d["decode_to_render_ms"]["p50"], d["decode_to_render_ms"]["p95"],
             d["present_interval_ms"]["stddev"], (d.get("cpu") or {}).get("process_cores", -1)))
    print("      representative_of_gpu_hardware =", d["representative_of_gpu_hardware"], "|", d["environment"]["presenter"])
    print("      fps:", c["sustained_60fps"], "| pacing:", c["even_frame_pacing"], "| d2p<=8ms:", c["decode_to_present_le_8ms"], "| ui:", c["ui_responsive"])
EOF
  fi
  sleep 2
done

tar czf "${OUT}.tar.gz" -C results "$(basename "$OUT")"
echo
echo "== done =="
echo "Send back: $(pwd)/${OUT}.tar.gz"
