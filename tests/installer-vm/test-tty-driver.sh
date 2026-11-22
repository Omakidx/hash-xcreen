#!/bin/bash
# Self-test of tty-driver.py (no VM): a stand-in program asks on /dev/tty the way hx-agent does
# (visible lines; hidden secrets with ECHO off, set with TCSAFLUSH so early input is discarded),
# retries one bad answer, and exits with a chosen status. Run by the workflow's `artifacts` job.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT

cat >"$t/ask.py" <<'PY'
import sys, termios
tty = open("/dev/tty", "r+b", buffering=0)
def line(prompt):
    tty.write(prompt.encode()); return tty.readline().decode().strip()
def secret(prompt):
    saved = termios.tcgetattr(tty)
    hidden = termios.tcgetattr(tty)
    hidden[3] &= ~termios.ECHO
    termios.tcsetattr(tty, termios.TCSAFLUSH, hidden)
    tty.write(prompt.encode())
    v = tty.readline().decode().strip()
    termios.tcsetattr(tty, termios.TCSAFLUSH, saved)
    tty.write(b"\n")
    return v
while line("Apps (basic or developer) [basic]: ") not in ("", "basic", "developer"):
    sys.stderr.write("--apps must be basic or developer\n")
user = line("Linux user name: ")
pw, pw2 = secret("Password (hidden): "), secret("Repeat the password: ")
if pw != pw2 or user != "alice":
    sys.exit(3)
print("pairing code: ABCD-2345")
sys.exit(int(sys.argv[1]))
PY
printf '%s' 'Sup3r-secret-pw' >"$t/pw"
cat >"$t/steps.json" <<JSON
[{"expect": "Apps \\\\(basic or developer\\\\) \\\\[basic\\\\]: ", "send": "bogus"},
 {"expect": "Apps \\\\(basic or developer\\\\) \\\\[basic\\\\]: ", "send": ""},
 {"expect": "Linux user name: ", "send": "alice"},
 {"expect": "Password \\\\(hidden\\\\): ", "send_file": "$t/pw"},
 {"expect": "Repeat the password: ", "send_file": "$t/pw"}]
JSON

echo "== answers in order, a retry, a hidden secret, exit 0"
python3 "$here/tty-driver.py" "$t/steps.json" "$t/out" -- python3 "$t/ask.py" 0
grep -q 'pairing code: ABCD-2345' "$t/out"
grep -q -- '--apps must be basic or developer' "$t/out"
if grep -qF 'Sup3r-secret-pw' "$t/out"; then echo "FAIL: a hidden answer was echoed" >&2; exit 1; fi

echo "== the command's own exit status passes through"
rc=0
python3 "$here/tty-driver.py" "$t/steps.json" "$t/out" -- python3 "$t/ask.py" 7 || rc=$?
[ "$rc" = 7 ] || { echo "FAIL: exit $rc, want 7" >&2; exit 1; }

echo "== a prompt that never comes is a failure (98), not a hang"
cat >"$t/never.json" <<JSON
[{"expect": "no such prompt", "send": "x", "timeout": 2}]
JSON
rc=0
python3 "$here/tty-driver.py" "$t/never.json" "$t/out" -- sh -c 'printf "hello\n"; sleep 30' 2>/dev/null || rc=$?
[ "$rc" = 98 ] || { echo "FAIL: exit $rc, want 98" >&2; exit 1; }

echo "== a command that ends before the steps are done is a failure (97)"
rc=0
python3 "$here/tty-driver.py" "$t/steps.json" "$t/out" -- sh -c 'echo bye' 2>/dev/null || rc=$?
[ "$rc" = 97 ] || { echo "FAIL: exit $rc, want 97" >&2; exit 1; }
echo "PASS: tty-driver"
