#!/bin/sh
# The release gate (design D7), runnable locally and from the `gate` job of release.yml.
#
#   release/gate.sh [--tag vX.Y.Z] [--dry-run] [--workflow FILE]
#
# --dry-run (the workflow_dispatch rehearsal, which signs with a per-run TEST key and publishes
# nothing) skips checks 2 and 3, the provisioned-key checks.
#
# Checks (all of them run; any failure makes the exit status 1):
#   1. --tag, when given: it matches the ipc.md 6.12 rule 1 syntax and equals "v" + the workspace
#      version;
#   2. apps/hx-agent/release-keys/current.pub AND next.pub are provisioned (a minisign public key,
#      not the word UNPROVISIONED) and parse (42 bytes, algorithm "Ed"), and are different keys;
#   3. installer/install.sh embeds exactly those two keys (KEY_CURRENT, KEY_NEXT);
#   5. release.yml enables none of the test-hook features (test-support, install-test-hooks,
#      privd-test-hooks, gateway-test-hooks, test-release-key, test-shadow-path);
#   6. supply chain of release.yml: every `uses:` is pinned to a full 40-hex commit SHA, and no
#      build cache (rust-cache, actions/cache) appears in it: a release build is never restored
#      from a cache a pull request could have written;
#   4. the compile-time gate exists: feature `release-build` in apps/hx-agent/Cargo.toml and its
#      const assertion in privd/update/keys.rs (the build itself, with --features release-build,
#      is the real enforcement and fails on an unprovisioned key).
# `cargo deny` and `cargo audit` are separate jobs of the same workflow.
set -u
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
tag='' dry=0 wf=''
while [ $# -gt 0 ]; do
    case $1 in
    --tag) tag=${2:?}; shift 2 ;;
    --dry-run) dry=1; shift ;;
    --workflow) wf=${2:?}; shift 2 ;;
    *) echo "gate.sh: unknown option $1" >&2; exit 2 ;;
    esac
done

fail=0
bad() { echo "GATE FAIL: $*" >&2; fail=1; }
good() { echo "gate ok:   $*"; }

# the verification helpers of the shipped installer (test mode)
set -- --hx-lib
# shellcheck source=../installer/install.sh
. "$root/installer/install.sh"

# ---- 1. tag ----
ws=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version *= *"\(.*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)
if [ -z "$ws" ]; then
    bad "cannot read the workspace version from Cargo.toml"
elif [ -n "$tag" ]; then
    if ! printf '%s\n' "$tag" | grep -Eq '^v[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(-(alpha|beta|rc)\.[0-9]{1,4})?$'; then
        bad "tag '$tag' does not match the release version syntax"
    elif [ "$tag" != "v$ws" ]; then
        bad "tag '$tag' is not v$ws (the workspace version)"
    else
        good "tag $tag equals the workspace version"
    fi
fi

if [ "$dry" = 1 ]; then
    good "dry run: the provisioned-key checks are skipped"
else
    # ---- 2. keys ----
    keyline() { # file : the key line, or UNPROVISIONED
        _l=$(grep -v '^[[:space:]]*#' "$1" | grep -v '^untrusted comment:' | grep -v '^[[:space:]]*$' | head -n 1 | tr -d '[:space:]')
        printf '%s' "$_l"
    }
    kc=$(keyline "$root/apps/hx-agent/release-keys/current.pub")
    kn=$(keyline "$root/apps/hx-agent/release-keys/next.pub")
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    idc='' idn=''
    for which in current next; do
        if [ "$which" = current ]; then k=$kc; else k=$kn; fi
        if [ -z "$k" ] || [ "$k" = UNPROVISIONED ]; then
            bad "release-keys/$which.pub is UNPROVISIONED: a release needs both keys (the maintainer provisions them)"
            continue
        fi
        if b64_file "$k" "$tmp/$which.raw" 42 && [ "$(dd if="$tmp/$which.raw" bs=1 count=2 2>/dev/null)" = Ed ]; then
            good "release-keys/$which.pub is a minisign public key"
            id=$(hex_of "$tmp/$which.raw" 2 8)
            if [ "$which" = current ]; then idc=$id; else idn=$id; fi
        else
            bad "release-keys/$which.pub does not hold a valid minisign public key line"
        fi
    done
    if [ -n "$idc" ] && [ "$idc" = "$idn" ]; then bad "current.pub and next.pub are the same key"; fi

    # ---- 3. install.sh embeds the same keys ----
    if [ "$KEY_CURRENT" = "$kc" ] && [ "$KEY_NEXT" = "$kn" ]; then
        good "install.sh embeds the keys of release-keys/*.pub"
    else
        bad "install.sh KEY_CURRENT / KEY_NEXT differ from release-keys/current.pub / next.pub"
    fi

fi

# ---- 4. the compile-time gate exists ----
if grep -q '^release-build' "$root/apps/hx-agent/Cargo.toml" &&
    grep -q 'feature = "release-build"' "$root/apps/hx-agent/src/privd/update/keys.rs"; then
    good "the release-build compile-time gate is present"
else
    bad "the release-build gate is missing from Cargo.toml or keys.rs"
fi

# ---- 5. no test-hook feature in a release build ----
# The compile-time gate (keys.rs) rejects `test-support` and `test-release-key` next to
# `release-build`; the features of the other workstreams are checked here, textually, on the
# workflow that builds the release. `test-shadow-path` is hx-pwcheck's HX_PWCHECK_SHADOW override.
FORBIDDEN='test-support install-test-hooks privd-test-hooks gateway-test-hooks test-release-key test-shadow-path'
[ -n "$wf" ] || wf="$root/.github/workflows/release.yml"
if [ -f "$wf" ]; then
    hit=''
    for f in $FORBIDDEN; do
        # a cargo line that names the feature (comments are ignored)
        if grep -v '^[[:space:]]*#' "$wf" | grep -E 'cargo +(build|install|test|run)' | grep -q -- "$f"; then hit="$hit $f"; fi
    done
    if [ -n "$hit" ]; then bad "release.yml builds with forbidden test features:$hit"; else good "release.yml enables no test-hook feature"; fi
else
    bad ".github/workflows/release.yml is missing"
fi

# ---- 6. supply chain: SHA-pinned actions, no cache ----
if [ -f "$wf" ]; then
    # every `uses:` (comments ignored) must end in @<40 hex>, optionally followed by a comment
    unpinned=$(grep -v '^[[:space:]]*#' "$wf" | grep -E '^[[:space:]]*-?[[:space:]]*uses:' |
        grep -Ev '^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*[A-Za-z0-9._/-]+@[0-9a-f]{40}([[:space:]]+#.*)?[[:space:]]*$' || true)
    if [ -n "$unpinned" ]; then
        bad "release.yml has actions not pinned to a 40-hex commit SHA:"
        printf '%s\n' "$unpinned" >&2
    else
        good "every action in release.yml is pinned to a commit SHA"
    fi
    if grep -Eq 'rust-cache|actions/cache' "$wf"; then
        bad "release.yml uses a build cache (rust-cache or actions/cache): release builds are uncached"
    else
        good "release.yml uses no build cache"
    fi
fi

[ "$fail" = 0 ] && echo "release gate: PASSED" || echo "release gate: BLOCKED" >&2
exit "$fail"
