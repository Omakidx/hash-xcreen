#!/bin/sh
# Runs install.sh's own KAT self-test (`selftest`), and then checks that it catches a broken
# verifier: with `openssl` shadowed by a function that always says "valid", the tampered vector
# would be accepted, so the self-test must fail.
#   selftest-case.sh <install.sh>
inst=$1
set -- --hx-lib
# shellcheck source=../install.sh
. "$inst"
if selftest; then echo "selftest=ok"; else echo "selftest=FAIL"; fi
openssl() {
    case $1 in
    pkeyutl) return 0 ;;
    *) command openssl "$@" ;;
    esac
}
if selftest; then echo "broken=accepted"; else echo "broken=rejected"; fi
