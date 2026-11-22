#!/bin/sh
# shellcheck disable=SC2034 # the paths assigned after sourcing install.sh are read by its functions
# Runs install.sh's `main` in a fake root, as the shell under test (installer/tests/handoff.sh).
#   handoff-inner.sh <install.sh> <fake dir> <os-release file> <as-root yes|no> <expect-uid> <agent path> <main args...>
# The paths install.sh fixes for a real host are re-pointed into <fake dir>; main execs the
# hx-agent of the release (a stub), so the output is the stub's report.
inst=$1
fake=$2
osrel=$3
asroot=$4
euid=$5
agent=$6
shift 6
saved=$*
set -- --hx-lib
# shellcheck source=../install.sh
. "$inst"
LOCK_FILE=$fake/run/hx-install.lock
BOOT_BASE=$fake/var/lib
AGENT_CURRENT=$agent
OS_RELEASE=$osrel
SYSTEMD_DIR=$fake/sd
EXPECT_UID=$euid
if [ "$asroot" = yes ]; then
    is_root() { return 0; }
else
    is_root() { return 1; }
fi
# shellcheck disable=SC2086  # the test arguments hold no spaces
set -- $saved
main "$@"
