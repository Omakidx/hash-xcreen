#!/usr/bin/env bash
# Generate the S1 test clip: 1920x1080, 60 fps, H.264 Main, no B-frames,
# desktop-like content (testsrc2 + scrolling text), x264 zerolatency like the
# real streaming pipeline. Output is git-ignored.
#
#   ./gen-clip.sh [output.mp4] [seconds]
set -euo pipefail
cd "$(dirname "$0")"

OUT="${1:-clip-1080p60.mp4}"
SECS="${2:-30}"

FONT="$(fc-match -f '%{file}' 'DejaVu Sans' 2>/dev/null || true)"
[ -n "$FONT" ] || FONT="$(fc-match -f '%{file}' sans)"

# Scrolling text bands at two speeds (like a terminal / ticker) over testsrc2.
TEXT1="drawtext=fontfile=${FONT}:text='hash-xcreen S1 slint video presentation test  1080p60  scrolling text ticker':fontsize=64:fontcolor=white:box=1:boxcolor=black@0.6:boxborderw=12:x=w-mod(t*420\,w+tw):y=h-160"
TEXT2="drawtext=fontfile=${FONT}:text='The quick brown fox jumps over the lazy dog 0123456789':fontsize=40:fontcolor=yellow:box=1:boxcolor=black@0.6:boxborderw=8:x=w-mod(t*160\,w+tw):y=120"
CLOCK="drawtext=fontfile=${FONT}:text='%{pts\:hms\:0\:3}':fontsize=48:fontcolor=cyan:box=1:boxcolor=black@0.6:boxborderw=8:x=40:y=40"

ffmpeg -hide_banner -y \
  -f lavfi -i "testsrc2=size=1920x1080:rate=60:duration=${SECS}" \
  -vf "${TEXT1},${TEXT2},${CLOCK},format=yuv420p" \
  -c:v libx264 -profile:v main -level 4.2 -preset veryfast -tune zerolatency \
  -bf 0 -g 120 -crf 23 -x264-params "keyint=120:min-keyint=120:scenecut=0" \
  -pix_fmt yuv420p -movflags +faststart -an "${OUT}"

ffprobe -v error -select_streams v:0 \
  -show_entries stream=codec_name,profile,width,height,r_frame_rate,nb_frames,has_b_frames \
  -of default=nw=1 "${OUT}"
ls -l "${OUT}"
