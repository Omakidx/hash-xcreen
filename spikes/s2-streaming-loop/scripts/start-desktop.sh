#!/usr/bin/env bash
# Runs inside the container as root: starts headless Xorg (dummy) on :10 and an XFCE session as user `desk`.
pkill -u desk 2>/dev/null
pkill Xorg 2>/dev/null
sleep 1
rm -f /tmp/.X10-lock /tmp/.X11-unix/X10
nohup Xorg :10 -config /etc/X11/xorg-s2.conf -noreset -ac -nolisten tcp -logfile /tmp/xorg.log >/tmp/xorg.out 2>&1 &
for i in $(seq 50); do [ -S /tmp/.X11-unix/X10 ] && break; sleep 0.2; done
su - desk -c 'export DISPLAY=:10; nohup dbus-launch --exit-with-session startxfce4 >/tmp/xfce.log 2>&1 &'
sleep 6
su - desk -c 'DISPLAY=:10 xdpyinfo | grep dimensions'
