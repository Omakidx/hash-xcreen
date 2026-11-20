#!/usr/bin/env bash
# Runs inside the container as root.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  xfce4 xfce4-terminal xserver-xorg-core xserver-xorg-video-dummy x11-xserver-utils \
  xdotool mousepad mpv iproute2 procps dbus-x11 x11-utils xauth fonts-dejavu \
  libavcodec60 libavutil58 libswscale7 libswresample4 libx264-164 libxcb-shm0 libxcb-xfixes0 libxcb-damage0 \
  libxcb-randr0 python3 ca-certificates curl ffmpeg
id desk >/dev/null 2>&1 || useradd -m -s /bin/bash desk
mkdir -p /etc/X11
# 60 s of busy synthetic 1080p30 content for the video scenario
su - desk -c 'test -f ~/test.mp4 || ffmpeg -loglevel error -f lavfi -i testsrc2=size=1920x1080:rate=30 -t 60 -c:v libx264 -preset veryfast -pix_fmt yuv420p ~/test.mp4'
