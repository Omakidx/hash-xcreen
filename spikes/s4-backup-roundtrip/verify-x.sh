#!/bin/sh
# start Xorg (dummy driver) and XFCE as alice; report processes and a window listing
pkill Xorg; pkill xfce4-session; sleep 1
(Xorg :10 -noreset -nolisten tcp -novtswitch -sharevts -logfile /var/log/s4-Xorg.log -config /etc/X11/xorg.conf.d/10-dummy.conf >/var/log/s4-xorg.out 2>&1 &)
sleep 3
runuser -u alice -- env DISPLAY=:10 HOME=/home/alice XDG_RUNTIME_DIR=/tmp/xdg-alice sh -c 'mkdir -p -m 700 /tmp/xdg-alice; nohup dbus-launch --exit-with-session xfce4-session >/tmp/s4-xfce.out 2>&1 &'
sleep 12
echo "--- procs"; pgrep -a Xorg | head -2; pgrep -a xfce4-session | head -1; pgrep -a xfwm4 | head -1; pgrep -a xfce4-panel | head -1
echo "--- xdpyinfo"; DISPLAY=:10 xdpyinfo | grep -E "dimensions|name of display"
echo "--- windows"; DISPLAY=:10 xdotool search --onlyvisible --name "" 2>/dev/null | wc -l
