#!/bin/sh
# Test of the image-key check (7) of release/gate.sh, on a synthetic tree with per-run TEST keys:
#
#   sh release/tests/gate-image-keys.sh
#
# The gate finds the tree from its own location, so the test copies gate.sh, install.sh, the
# workspace manifests and release.yml into a temporary tree whose release keys are provisioned
# (and embedded in the copy of install.sh), and varies only apps/hx-agent/image-keys/.
set -eu
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

keygen() { sh "$root/release/openssl-minisign.sh" keygen "$tmp/k-$1"; }
for k in rel-current rel-next img-current img-next; do keygen "$k"; done
line() { tr -d '[:space:]' <"$tmp/k-$1/key.line"; }

tree="$tmp/tree"
mkdir -p "$tree/release" "$tree/installer" "$tree/apps/hx-agent/release-keys" \
    "$tree/apps/hx-agent/src/privd/update" "$tree/.github/workflows"
cp "$root/release/gate.sh" "$tree/release/"
cp "$root/Cargo.toml" "$tree/"
cp "$root/apps/hx-agent/Cargo.toml" "$tree/apps/hx-agent/"
cp "$root/apps/hx-agent/src/privd/update/keys.rs" "$tree/apps/hx-agent/src/privd/update/"
cp "$root/.github/workflows/release.yml" "$tree/.github/workflows/"
cp "$tmp/k-rel-current/key.pub" "$tree/apps/hx-agent/release-keys/current.pub"
cp "$tmp/k-rel-next/key.pub" "$tree/apps/hx-agent/release-keys/next.pub"
sed -e "s|^KEY_CURRENT=.*|KEY_CURRENT='$(line rel-current)'|" \
    -e "s|^KEY_NEXT=.*|KEY_NEXT='$(line rel-next)'|" \
    "$root/installer/install.sh" >"$tree/installer/install.sh"

fails=0
# expect <name> <exit status> <stderr must contain, or ''> [gate args...]
expect() {
    name=$1 want=$2 needle=$3
    shift 3
    rc=0
    sh "$tree/release/gate.sh" "$@" >"$tmp/out" 2>"$tmp/err" || rc=$?
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
imgdir="$tree/apps/hx-agent/image-keys"
set_img() { # <current: key dir name | text> <next: ...>
    rm -rf "$imgdir"
    mkdir -p "$imgdir"
    for w in current next; do
        if [ "$w" = current ]; then v=$1; else v=$2; fi
        case $v in
        k-*) cp "$tmp/$v/key.pub" "$imgdir/$w.pub" ;;
        *) printf '%s\n' "$v" >"$imgdir/$w.pub" ;;
        esac
    done
}

# a tree from before the prebuilt-image work has no image-keys directory: tolerated
rm -rf "$imgdir"
expect "no image-keys directory is tolerated" 0 ''

set_img UNPROVISIONED UNPROVISIONED
expect "both UNPROVISIONED blocks" 1 'image-keys/current.pub is UNPROVISIONED'
expect "both UNPROVISIONED: next is named too" 1 'image-keys/next.pub is UNPROVISIONED'
expect "a dry run skips the image keys" 0 '' --dry-run

set_img k-img-current UNPROVISIONED
expect "only the next key missing blocks" 1 'image-keys/next.pub is UNPROVISIONED'

set_img UNPROVISIONED k-img-next
expect "only the current key missing blocks" 1 'image-keys/current.pub is UNPROVISIONED'

set_img k-img-current k-img-next
expect "both provisioned and separate passes" 0 ''

set_img k-img-current k-img-current
expect "the same key twice blocks" 1 'same key'

set_img k-rel-current k-img-next
expect "an image key equal to a release key blocks" 1 'is a release key'

set_img 'RWnotakey' k-img-next
expect "a malformed key blocks" 1 'does not hold a valid minisign public key'

set_img k-img-current ''
expect "an empty file blocks" 1 'UNPROVISIONED'

set_img k-img-current k-img-next
rm -f "$imgdir/next.pub"
expect "a missing file blocks" 1 'image-keys/next.pub is missing'

if [ "$fails" = 0 ]; then
    echo "gate image-key tests: PASSED"
else
    echo "gate image-key tests: $fails FAILED" >&2
    exit 1
fi
