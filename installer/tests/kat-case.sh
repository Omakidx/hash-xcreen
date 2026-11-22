#!/bin/sh
# One signature-check case, run by the shell under test (installer/tests/run.sh).
#   kat-case.sh <install.sh> <current key line> <next key line> <message file> <minisig file>
# Prints the return code of verify_with on the first line and VERR on the second.
inst=$1
cur=$2
nxt=$3
msg=$4
sig=$5
set -- --hx-lib
# shellcheck source=../install.sh
. "$inst"
verify_with "$msg" "$sig" "$cur" "$nxt"
rc=$?
printf '%s\n%s\n' "$rc" "$VERR"
