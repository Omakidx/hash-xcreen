#!/usr/bin/env bash
# VPS variant of setup-container.sh. Runs ON the VPS (not as root; uses sudo -n incus).
# Creates `s2-desktop` (XFCE on Xorg dummy 1920x1080) and `s2-client` (headless decoder) from images:ubuntu/24.04
# on the existing default profile (bridge hxbr0). The client lives in its own container because the VPS host
# ships FFmpeg 8 while the spike binaries link FFmpeg 6.1 (libavcodec60); both containers share the host kernel,
# so CLOCK_MONOTONIC is common to both.
# Needs in ~/s2/: scripts/{inside-setup.sh,xorg-dummy.conf,start-desktop.sh,long-doc.sh}.
set -euo pipefail
S2=${S2:-$HOME/s2}
inc() { sudo -n incus "$@"; }

inc launch images:ubuntu/24.04 s2-desktop -c limits.memory=5GiB
inc launch images:ubuntu/24.04 s2-client -c limits.memory=1GiB
for C in s2-desktop s2-client; do
  until inc exec "$C" -- getent hosts archive.ubuntu.com >/dev/null 2>&1; do sleep 2; done
done

inc file push "$S2/scripts/inside-setup.sh" s2-desktop/root/inside-setup.sh
inc exec s2-desktop -- bash /root/inside-setup.sh
inc file push "$S2/scripts/xorg-dummy.conf" s2-desktop/etc/X11/xorg-s2.conf
inc file push "$S2/scripts/start-desktop.sh" s2-desktop/usr/local/bin/start-desktop.sh
inc file push "$S2/scripts/long-doc.sh" s2-desktop/usr/local/bin/long-doc.sh
inc exec s2-desktop -- chmod +x /usr/local/bin/start-desktop.sh /usr/local/bin/long-doc.sh
inc exec s2-desktop -- /usr/local/bin/long-doc.sh

# decoder container: only the runtime libraries the client links against
inc exec s2-client -- bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq --no-install-recommends libavcodec60 libavutil58 libswscale7 libswresample4 libx264-164 ca-certificates procps'

for C in s2-desktop s2-client; do inc exec "$C" -- bash -c 'echo ready: $(hostname)'; done
