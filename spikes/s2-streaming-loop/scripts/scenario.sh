#!/usr/bin/env bash
# Scenario driver, runs inside the container as user `desk` (pushed to /home/desk/scenario.sh).
#   scenario.sh prep <name>          set the desktop up (not measured)
#   scenario.sh run  <name> <secs>   generate input for <secs> seconds
# Names: idle typing scroll video drag
export DISPLAY=:10
mode=$1; name=$2; secs=${3:-20}

focus_mousepad() {
  wid=$(xdotool search --onlyvisible --class mousepad | head -1)
  xdotool windowsize "$wid" 1280 800 windowmove "$wid" 200 120 windowfocus "$wid"
  sleep 0.5
  xdotool mousemove 800 500 click 1
}

if [ "$mode" = prep ]; then
  pkill -x mpv; pkill -x mousepad; pkill -x thunar; sleep 1
  rm -rf /home/desk/.local/share/Mousepad
  case $name in
    idle) ;;
    typing) mousepad >/dev/null 2>&1 & sleep 4; focus_mousepad ;;
    scroll|drag) mousepad /home/desk/long.txt >/dev/null 2>&1 & sleep 4; focus_mousepad ;;
    video) mpv --fs --no-audio --vo=x11 --loop=inf --really-quiet /home/desk/test.mp4 >/dev/null 2>&1 & sleep 4 ;;
  esac
  xdotool mousemove 1800 1000
  sleep 1
  exit 0
fi

end=$((SECONDS + secs))
case $name in
  idle) sleep "$secs" ;;
  typing)
    # about 12 characters per second
    while [ $SECONDS -lt $end ]; do
      xdotool type --delay 80 "the quick brown fox jumps over the lazy dog while streaming pixels over quic. "
    done ;;
  scroll)
    # mouse wheel at about 40 notches per second, down then up
    while [ $SECONDS -lt $end ]; do
      xdotool click --repeat 60 --delay 25 5
      xdotool click --repeat 60 --delay 25 4
    done ;;
  video) sleep "$secs" ;;
  drag)
    # Alt + left button drags the window with xfwm4; circle path at about 100 moves per second
    xdotool mousemove 800 500 keydown alt mousedown 1
    while [ $SECONDS -lt $end ]; do
      awk 'BEGIN{for(i=0;i<200;i++) printf "mousemove %d %d\nsleep 0.01\n", 800+300*sin(i/31.8), 500+200*cos(i/31.8)}' | xdotool -
    done
    xdotool mouseup 1 keyup alt ;;
esac
xdotool mousemove 1800 1000
