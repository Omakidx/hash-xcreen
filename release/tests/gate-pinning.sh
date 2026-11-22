#!/bin/sh
# Test of check 6 of release/gate.sh (every action of EVERY workflow is pinned to a commit SHA),
# on a synthetic tree, in dry-run mode (which skips the provisioned-key checks):
#
#   sh release/tests/gate-pinning.sh
set -eu
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

tree="$tmp/tree"
mkdir -p "$tree/release" "$tree/installer" "$tree/apps/hx-agent/src/privd/update" "$tree/.github/workflows"
cp "$root/release/gate.sh" "$tree/release/"
cp "$root/installer/install.sh" "$tree/installer/"
cp "$root/Cargo.toml" "$tree/"
cp "$root/apps/hx-agent/Cargo.toml" "$tree/apps/hx-agent/"
cp "$root/apps/hx-agent/src/privd/update/keys.rs" "$tree/apps/hx-agent/src/privd/update/"
wfd="$tree/.github/workflows"
cp "$root/.github/workflows/release.yml" "$wfd/"

fails=0
expect() { # <name> <exit status> <stderr must contain, or ''>
    name=$1 want=$2 needle=$3
    rc=0
    sh "$tree/release/gate.sh" --dry-run >"$tmp/out" 2>"$tmp/err" || rc=$?
    if [ "$rc" != "$want" ]; then
        echo "FAIL $name: exit $rc, wanted $want"
        cat "$tmp/err"
        fails=$((fails + 1))
    elif [ -n "$needle" ] && ! grep -q -- "$needle" "$tmp/err"; then
        echo "FAIL $name: stderr lacks '$needle'"
        cat "$tmp/err"
        fails=$((fails + 1))
    else
        echo "ok   $name"
    fi
}
sha=11d5960a326750d5838078e36cf38b85af677262
dig=887a259a5a534f3c4f36cb02dca341673c6089431057242cdc931e9f133147e9
wf() { printf 'jobs:\n  j:\n    steps:\n%s\n' "$2" >"$wfd/$1"; }

expect "the real release.yml alone passes" 0 ''

wf other.yml "      - uses: actions/checkout@$sha # v4"
expect "a pinned second workflow passes" 0 ''

wf other.yml "      - uses: actions/checkout@v4"
expect "a tag-pinned action in another workflow blocks" 1 'other.yml has actions not pinned'

wf other.yml "      - uses: actions/checkout@main # v4"
expect "a branch-pinned action blocks" 1 'other.yml has actions not pinned'

wf other.yml "      - uses: docker://rhysd/actionlint:1.7.7"
expect "an unpinned docker image blocks" 1 'other.yml has actions not pinned'

wf other.yml "      - uses: docker://rhysd/actionlint:1.7.7@sha256:$dig # v1.7.7"
expect "a digest-pinned docker image passes" 0 ''

wf other.yml "      # - uses: actions/checkout@v4
      - uses: actions/checkout@$sha"
expect "a commented-out unpinned line is ignored" 0 ''

wf other.yml "      - uses: actions/checkout@$sha # v4
      - uses: Swatinem/rust-cache@v2"
expect "one unpinned action among pinned ones blocks" 1 'rust-cache@v2'

rm -f "$wfd/other.yml"
wf second.yaml "      - uses: actions/checkout@v4"
expect "a .yaml workflow is covered too" 1 'second.yaml has actions not pinned'

if [ "$fails" = 0 ]; then
    echo "gate pinning tests: PASSED"
else
    echo "gate pinning tests: $fails FAILED" >&2
    exit 1
fi
