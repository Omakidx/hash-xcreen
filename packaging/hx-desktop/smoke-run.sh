#!/bin/sh
# Runs the packaged app headless: `--version` must print the expected version, then `--demo`
# (fake servers, no keyring, nothing saved) must stay up for a few seconds under Xvfb.
#
#   packaging/hx-desktop/smoke-run.sh VERSION COMMAND [ARG...]
#
# COMMAND is the installed `hx-desktop`, or the AppImage with APPIMAGE_EXTRACT_AND_RUN=1 set.
# Needs xvfb-run (apt install xvfb). Exit 0 only when both checks pass.
set -eu
export LC_ALL=C
want=${1:?usage: smoke-run.sh VERSION COMMAND [ARG...]}
shift

got=$("$@" --version)
if [ "$got" != "hx-desktop $want" ]; then
    echo "smoke-run.sh: --version printed '$got', expected 'hx-desktop $want'" >&2
    exit 1
fi
echo "smoke-run.sh: --version ok ($got)"

command -v xvfb-run >/dev/null 2>&1 || { echo "smoke-run.sh: xvfb-run not found" >&2; exit 2; }
log=$(mktemp)
cfg=$(mktemp -d)
trap 'rm -rf "$log" "$cfg"' EXIT
# timeout exits 124 when it had to stop a program that was still running: that is the pass.
# The software renderer keeps this independent of the runner's GL stack.
set +e
SLINT_BACKEND=winit-software XDG_CONFIG_HOME=$cfg timeout 8 xvfb-run -a -s '-screen 0 1280x800x24' "$@" --demo >"$log" 2>&1
rc=$?
set -e
if [ "$rc" -ne 124 ]; then
    echo "smoke-run.sh: --demo exited with $rc within 8 s (expected to keep running)" >&2
    cat "$log" >&2
    exit 1
fi
echo "smoke-run.sh: --demo ran for 8 s under Xvfb"
