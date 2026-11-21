#!/bin/sh
# install.sh against a TEST-KEYED release dir (release/make-test-release.sh) in a fake root, under
# the shell given as the first argument (default sh). Nothing runs as root and nothing outside a
# temporary directory is touched: the lock file, the bootstrap directory, os-release and the
# systemd marker are re-pointed (see handoff-inner.sh).
#
# Covers: the full path (verify, extract hx-agent only, exec `hx-agent install --bootstrap-dir
# --lock-fd 9` with the lock still held and stdin untouched), the C1 exit codes (7, 9, 10, 11),
# an installed agent (no download), and the refusals: tampered tarball, tampered manifest, other
# key, other channel, future timestamp, Ubuntu 22.04.
set -u
shell=${1:-sh}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
command -v "$shell" >/dev/null 2>&1 || { echo "handoff.sh: shell not found: $shell" >&2; exit 2; }
echo "== install.sh hand-off under $shell"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
me=$(id -u)
fail=0

sh "$root/release/make-test-release.sh" --out "$tmp/rel" >/dev/null 2>&1 || { echo "FAIL cannot build the test release"; exit 1; }
sh "$root/release/make-test-release.sh" --out "$tmp/rel-future" --timestamp "$(($(date +%s) + 172800))" >/dev/null 2>&1
sh "$root/release/make-test-release.sh" --out "$tmp/rel-other" >/dev/null 2>&1
sh "$root/release/make-test-release.sh" --out "$tmp/rel-old" --timestamp "$(($(date +%s) - 100 * 86400))" >/dev/null 2>&1

fake=$tmp/fake
mkdir -p "$fake/run" "$fake/sd"
printf 'ID=ubuntu\nVERSION_ID="24.04"\n' >"$fake/os-24"
printf 'ID=ubuntu\nVERSION_ID="22.04"\n' >"$fake/os-22"
printf 'ID=fedora\nVERSION_ID=41\n' >"$fake/os-fedora"
printf 'ID=debian\nVERSION_ID="13"\n' >"$fake/os-deb13"
lock=$fake/run/hx-install.lock

# case <name> <expect rc> <os> <as-root> <expect-uid> <agent> <install.sh> <stdin text> <pattern>... -- <main args>
case_run() {
    name=$1 want=$2 os=$3 asroot=$4 euid=$5 agent=$6 inst=$7 input=$8
    shift 8
    pats=''
    while [ "$1" != -- ]; do pats="$pats|$1"; shift; done
    shift
    out=$(printf '%s' "$input" | "$shell" "$here/handoff-inner.sh" "$inst" "$fake" "$fake/$os" "$asroot" "$euid" "$agent" "$@" 2>&1)
    rc=$?
    ok=1
    [ "$rc" = "$want" ] || ok=0
    oldifs=$IFS
    IFS='|'
    for p in $pats; do
        [ -n "$p" ] || continue
        printf '%s' "$out" | grep -qF -- "$p" || ok=0
    done
    IFS=$oldifs
    if [ "$ok" = 1 ]; then
        echo "ok   $name"
    else
        echo "FAIL $name: exit $rc (wanted $want), patterns '$pats'"
        printf '%s\n' "$out" | sed 's/^/     | /'
        fail=1
    fi
}

R=$tmp/rel
none=$fake/no-agent

case_run "full path, json progress, lock held, stdin untouched" 0 os-24 yes "$me" "$none" "$R/install.sh" "HXI1-stdin-data" \
    'STUB-ARGV:--json install --bootstrap-dir ' ' --lock-fd 9 --channel stable --pair --user bob' \
    'STUB-FD9:open' 'STUB-LOCK:held' "STUB-LOCKFILE:$lock" 'STUB-STDIN:HXI1' \
    'STUB-FILES:artifact.tar.gz hx-agent manifest.json manifest.json.minisig ' \
    '"id":"bootstrap-preflight","state":"start"' '"id":"bootstrap-verify","state":"done"' \
    -- --release-dir "$R" --progress json --pair --user bob

case_run "text progress forwards no --json; option order kept" 0 os-deb13 yes "$me" "$none" "$R/install.sh" "" \
    'STUB-ARGV:install --bootstrap-dir ' ' --lock-fd 9 --channel stable --user bob --port 8443' \
    -- --user bob --release-dir "$R" --port 8443
case_run "--release-dir=dir and --channel=stable forms" 0 os-24 yes "$me" "$none" "$R/install.sh" "" 'STUB-FD9:open' \
    -- --release-dir="$R" --channel=stable
case_run "a 100-day-old manifest only warns" 0 os-24 yes "$me" "$none" "$tmp/rel-old/install.sh" "" 'older than 90 days' \
    -- --release-dir "$tmp/rel-old"

cat >"$tmp/installed-agent" <<'EOF'
#!/bin/sh
echo "INSTALLED-ARGV:$*"
EOF
chmod 0755 "$tmp/installed-agent"
case_run "installed agent: exec with --lock-fd 9, no bootstrap dir" 0 os-24 yes "$me" "$tmp/installed-agent" "$R/install.sh" "" \
    'INSTALLED-ARGV:install --lock-fd 9 --channel stable --ssh' 'an agent is already installed' \
    -- --ssh

case_run "not root is exit 7" 7 os-24 no "$me" "$none" "$R/install.sh" "" 'must run as root' -- --release-dir "$R"
case_run "Ubuntu 22.04 is refused (exit 9)" 9 os-22 yes "$me" "$none" "$R/install.sh" "" 'Ubuntu 22.04 is not supported' -- --release-dir "$R"
case_run "an unsupported OS is refused (exit 9)" 9 os-fedora yes "$me" "$none" "$R/install.sh" "" 'unsupported OS' -- --release-dir "$R"
if [ "$me" != 0 ]; then
    case_run "a release dir not owned by root is refused (exit 9)" 9 os-24 yes 0 "$none" "$R/install.sh" "" 'owned by root' -- --release-dir "$R"
fi
case_run "a release dir that is not absolute is a usage error" 2 os-24 yes "$me" "$none" "$R/install.sh" "" 'absolute' -- --release-dir relative/dir

# the lock: held by someone else -> exit 11
flock "$lock" sleep 4 &
holder=$!
sleep 1
case_run "another install holds the lock (exit 11)" 11 os-24 yes "$me" "$none" "$R/install.sh" "" 'another install or uninstall is running' -- --release-dir "$R"
wait "$holder" 2>/dev/null

# tampering
cp -R "$tmp/rel" "$tmp/t1"
art=$(ls "$tmp/t1"/hx-*.tar.gz)
# Change byte 100 to a value it does not already have (writing a fixed 'Z' left the file
# untouched whenever that byte was already 'Z', about one run in 256).
b=$(dd if="$art" bs=1 skip=100 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
if [ "$b" = 5a ]; then z=Y; else z=Z; fi
printf '%s' "$z" | dd of="$art" bs=1 seek=100 conv=notrunc 2>/dev/null
cmp -s "$art" "$tmp/rel/$(basename "$art")" && { echo "FAIL the tamper did not change the tarball"; fail=1; }
case_run "a tampered tarball (same size) is refused (exit 10)" 10 os-24 yes "$me" "$none" "$R/install.sh" "" 'digest does not match' -- --release-dir "$tmp/t1"
cp -R "$tmp/rel" "$tmp/t2"
{ cat "$tmp/rel/hx-0.1.0-x86_64.tar.gz"; printf 'x'; } >"$tmp/t2/hx-0.1.0-x86_64.tar.gz"
case_run "a tarball of the wrong size is refused (exit 10)" 10 os-24 yes "$me" "$none" "$R/install.sh" "" 'wrong size' -- --release-dir "$tmp/t2"
cp -R "$tmp/rel" "$tmp/t3"
sed 's/"size":/"size":1/' "$tmp/rel/manifest-x86_64.json" >"$tmp/t3/manifest-x86_64.json"
case_run "a tampered manifest is refused (exit 10)" 10 os-24 yes "$me" "$none" "$R/install.sh" "" 'signature is not valid' -- --release-dir "$tmp/t3"
case_run "a manifest signed by another key is refused (exit 10)" 10 os-24 yes "$me" "$none" "$tmp/rel-other/install.sh" "" 'signature is not valid' -- --release-dir "$R"
case_run "a manifest of another channel is refused (exit 10)" 10 os-24 yes "$me" "$none" "$R/install.sh" "" 'refused' -- --release-dir "$R" --channel beta
case_run "a manifest dated in the future is refused (exit 10)" 10 os-24 yes "$me" "$none" "$tmp/rel-future/install.sh" "" 'refused' -- --release-dir "$tmp/rel-future"
rm -f "$tmp/t1/manifest-x86_64.json.minisig"
case_run "a missing signature is refused (exit 1)" 1 os-24 yes "$me" "$none" "$R/install.sh" "" 'lacks the manifest' -- --release-dir "$tmp/t1"
case_run "json mode reports a failure as a result line" 10 os-24 yes "$me" "$none" "$tmp/rel-other/install.sh" "" \
    '"t":"result","ok":false,"exit":10,"stage":"bootstrap-verify","code":"VERIFY"' -- --release-dir "$R" --progress json

[ "$fail" = 0 ] && echo "== all hand-off cases passed under $shell" || echo "== FAILED under $shell"
exit "$fail"
