#!/bin/sh
# Runs the install.sh signature known-answer suite under the shell given as the first argument
# (default: sh), for example `sh installer/tests/run.sh dash` or `... posh`.
# Exits non-zero on the first deviation; prints one line per case.
set -u
shell=${1:-sh}
here=$(cd "$(dirname "$0")" && pwd)
inst=$here/../install.sh
vec=$here/vectors
fail=0

command -v "$shell" >/dev/null 2>&1 || { echo "run.sh: shell not found: $shell" >&2; exit 2; }
echo "== install.sh KATs under $shell"

keyline() { # token
    case $1 in
    UNPROV) echo UNPROVISIONED ;;
    garbage) echo 'RWQnotbase64!!' ;;
    *) sed -n 2p "$vec/key-$1.pub" ;;
    esac
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
{ cat "$vec/msg.bin"; printf x; } >"$tmp/msg.tampered"

# shellcheck disable=SC2034  # the last column is read by the Rust test only
while read -r name cur nxt msg sig expect reason _privd; do
    case $name in '' | '#'*) continue ;; esac
    m=$vec/$msg
    [ "$msg" = msg.tampered ] && m=$tmp/msg.tampered
    out=$("$shell" "$here/kat-case.sh" "$inst" "$(keyline "$cur")" "$(keyline "$nxt")" "$m" "$vec/$sig")
    rc=$(printf '%s\n' "$out" | sed -n 1p)
    verr=$(printf '%s\n' "$out" | sed -n 2p)
    want=$(printf '%s' "$reason" | tr _ ' ')
    if [ "$expect" = ok ]; then
        if [ "$rc" = 0 ]; then echo "ok   $name"; else echo "FAIL $name: wanted accept, rc=$rc ($verr)"; fail=1; fi
    else
        case $rc:$verr in
        0:*) echo "FAIL $name: wanted refusal, got accept"; fail=1 ;;
        *:*"$want"*) echo "ok   $name (refused: $verr)" ;;
        *) echo "FAIL $name: refused for another reason: rc=$rc ($verr), wanted '$want'"; fail=1 ;;
        esac
    fi
done <"$vec/cases.txt"

# The embedded self-test passes, and notices a verifier that accepts everything.
out=$("$shell" "$here/selftest-case.sh" "$inst")
if [ "$out" = "selftest=ok
broken=rejected" ]; then echo "ok   selftest (and it rejects a broken verifier)"; else echo "FAIL selftest: $out"; fail=1; fi

# The shipped repository file refuses to run as a release while no key is provisioned.
if "$shell" "$inst" --help >/dev/null 2>&1; then echo "ok   --help"; else echo "FAIL --help"; fail=1; fi
usage_rc=0
"$shell" "$inst" --channel nightly >/dev/null 2>&1 || usage_rc=$?
[ "$usage_rc" = 2 ] && echo "ok   bad --channel is exit 2" || { echo "FAIL bad --channel: exit $usage_rc"; fail=1; }

[ "$fail" = 0 ] && echo "== all KATs passed under $shell" || echo "== FAILED under $shell"
exit "$fail"
