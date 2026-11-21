#!/bin/sh
# install.sh's `fetch` with a fake curl that ignores --max-filesize (what curl before 8.4 does
# without a Content-Length). Run by the shell under test (installer/tests/run.sh).
#   fetch-case.sh <install.sh> <mode: under|exact|over1|runaway> <max bytes>
# Prints: the first curl argument, the return code, whether the file survived and its size.
inst=$1
mode=$2
max=$3
set -- --hx-lib
# shellcheck source=../install.sh
. "$inst"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl() {
    echo "$1" >"$tmp/first"
    _dest=''
    while [ $# -gt 0 ]; do
        [ "$1" = -o ] && _dest=$2
        shift
    done
    case $mode in
    under) head -c $((max - 1)) /dev/zero >"$_dest" ;;
    exact) head -c "$max" /dev/zero >"$_dest" ;;
    over1) head -c $((max + 1)) /dev/zero >"$_dest" ;;
    runaway) head -c $((max * 20)) /dev/zero >"$_dest" ;;
    esac
}
fetch https://example.invalid/file "$tmp/out" "$max" 2>/dev/null
rc=$?
echo "first=$(cat "$tmp/first")"
echo "rc=$rc"
if [ -e "$tmp/out" ]; then echo "file=yes size=$(wc -c <"$tmp/out")"; else echo "file=no"; fi
