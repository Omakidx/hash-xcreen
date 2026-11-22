#!/bin/sh
# Waits until the machine is quiet enough to measure on, or fails. The dedicated runner is meant
# to be idle between runs; this catches a stray build, an update or a noisy neighbour before it
# spoils a regression check. Usage: perf/quiet.sh [max_load_1m] [wait_seconds]
set -eu
max="${1:-0.50}"
wait_s="${2:-600}"
end=$(($(date +%s) + wait_s))
while :; do
    load=$(cut -d' ' -f1 /proc/loadavg)
    if awk -v l="$load" -v m="$max" 'BEGIN { exit !(l < m) }'; then
        echo "quiet: load average $load < $max"
        exit 0
    fi
    if [ "$(date +%s)" -ge "$end" ]; then
        echo "not quiet: load average $load >= $max after ${wait_s}s; busiest processes:" >&2
        ps -eo pcpu,pid,comm --sort=-pcpu | head -6 >&2
        exit 1
    fi
    sleep 10
done
