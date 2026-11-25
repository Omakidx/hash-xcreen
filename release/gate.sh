#!/bin/sh
# The release gate (design D7), runnable locally and from the `gate` job of release.yml.
#
#   release/gate.sh [--tag vX.Y.Z] [--dry-run] [--workflow FILE]
#
# --dry-run (the workflow_dispatch rehearsal, which signs with a per-run TEST key and publishes
# nothing) skips checks 2, 3 and 7, the provisioned-key checks.
#
# Checks (all of them run; any failure makes the exit status 1):
#   1. --tag, when given: it matches the ipc.md 6.12 rule 1 syntax and equals "v" + the workspace
#      version;
#   2. apps/hx-agent/release-keys/current.pub AND next.pub are provisioned (a minisign public key,
#      not the word UNPROVISIONED) and parse (42 bytes, algorithm "Ed"), and are different keys;
#   3. installer/install.sh embeds exactly those two keys (KEY_CURRENT, KEY_NEXT);
#   7. apps/hx-agent/image-keys/current.pub AND next.pub (the SEPARATE key pair of the desktop
#      images, secret half in the `image-signing` environment of images.yml) are provisioned, parse,
#      are different keys and differ from the release keys: an agent that ships without them could
#      never use a prebuilt image until it updates. The check is skipped only while the directory
#      does not exist at all (a tree from before the prebuilt-image work);
#   5. release.yml enables none of the test-hook features (test-support, install-test-hooks,
#      privd-test-hooks, gateway-test-hooks, test-release-key, test-shadow-path);
#   6. supply chain: in EVERY file of .github/workflows every `uses:` is pinned to a full 40-hex
#      commit SHA (a docker:// image to a sha256 digest), and no build cache (rust-cache,
#      actions/cache) appears in release.yml: a release build is never restored from a cache a
#      pull request could have written; every `container:` / `image:` value that names a registry
#      image (not `${{ ... }}`) is pinned by `@sha256:<64 hex>` as well;
#   8. job isolation, in EVERY file of .github/workflows: a job with `environment:` (it holds
#      signing secrets) runs no cargo, rustup, workspace binary (`signed/hx-*`, `target/*/hx-*`) or
#      workspace script and checks nothing out; a job with `contents: write` runs no cargo, rustup or
#      workspace binary. Such jobs only handle artifacts built by secret-free jobs;
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


    # ---- 7. the image keys: a separate pair, provisioned ----
    ikdir="$root/apps/hx-agent/image-keys"
    if [ ! -d "$ikdir" ]; then
        good "apps/hx-agent/image-keys/ does not exist in this tree: the image-key check is skipped"
    else
        iidc='' iidn=''
        for which in current next; do
            f="$ikdir/$which.pub"
            if [ ! -f "$f" ]; then
                bad "image-keys/$which.pub is missing"
                continue
            fi
            k=$(keyline "$f")
            if [ -z "$k" ] || [ "$k" = UNPROVISIONED ]; then
                bad "image-keys/$which.pub is UNPROVISIONED: a release needs both image keys (the maintainer provisions them)"
                continue
            fi
            if b64_file "$k" "$tmp/image-$which.raw" 42 && [ "$(dd if="$tmp/image-$which.raw" bs=1 count=2 2>/dev/null)" = Ed ]; then
                good "image-keys/$which.pub is a minisign public key"
                id=$(hex_of "$tmp/image-$which.raw" 2 8)
                if [ "$which" = current ]; then iidc=$id; else iidn=$id; fi
            else
                bad "image-keys/$which.pub does not hold a valid minisign public key line"
                continue
            fi
            if [ "$k" = "$kc" ] || [ "$k" = "$kn" ]; then
                bad "image-keys/$which.pub is a release key: the image key pair must be separate (a leaked image key must not sign agent releases)"
            fi
        done
        if [ -n "$iidc" ] && [ "$iidc" = "$iidn" ]; then bad "image-keys/current.pub and next.pub are the same key"; fi
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
# The compile-time gate (keys.rs) rejects every hx-agent test feature next to `release-build`;
# this textual check on the workflow that builds the release is a second line, and the only one
# for `test-shadow-path` (hx-pwcheck's HX_PWCHECK_SHADOW override, another crate).
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

# ---- 6. supply chain: SHA-pinned actions in EVERY workflow, no cache in release.yml ----
# Every `uses:` of every file in .github/workflows (comments ignored) must end in @<40 hex> (a
# `docker://` image: @sha256:<64 hex>), optionally followed by a comment. $wf is checked as well
# (it is release.yml unless --workflow says otherwise).
pinned_re='^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*(docker://)?[A-Za-z0-9._/:-]+@(sha256:[0-9a-f]{64}|[0-9a-f]{40})([[:space:]]+#.*)?[[:space:]]*$'
pinfiles=''
[ -f "$wf" ] && pinfiles=$wf
for f in "$root"/.github/workflows/*.yml "$root"/.github/workflows/*.yaml; do
    [ -f "$f" ] || continue
    [ "$f" = "$wf" ] && continue
    pinfiles="$pinfiles $f"
done
for f in $pinfiles; do
    unpinned=$(grep -v '^[[:space:]]*#' "$f" | grep -E '^[[:space:]]*-?[[:space:]]*uses:' | grep -Ev "$pinned_re" || true)
    if [ -n "$unpinned" ]; then
        bad "$(basename "$f") has actions not pinned to a 40-hex commit SHA (or an image sha256 digest):"
        printf '%s\n' "$unpinned" >&2
    else
        good "every action in $(basename "$f") is pinned to a commit SHA"
    fi
done
if [ -f "$wf" ]; then
    if grep -Eq 'rust-cache|actions/cache' "$wf"; then
        bad "release.yml uses a build cache (rust-cache or actions/cache): release builds are uncached"
    else
        good "release.yml uses no build cache"
    fi
fi

# ---- 6b. container and image references are pinned by digest ----
# Every `container:` / `image:` value in every workflow that names a registry image (it contains ':'
# or '/'; a `${{ matrix.image }}` indirection is checked where the matrix defines it) must carry
# `@sha256:<64 hex>`. List forms (`image: ["a:1", "b:2"]`) are checked per element.
image_refs() { # <file>: the container/image values, one per line (comments skipped)
    awk '
    /^[[:space:]]*#/ { next }
    {
        if (!match($0, /(^|[[:space:]{,])(container|image):[[:space:]]*/)) next
        rest = substr($0, RSTART + RLENGTH)
        if (rest == "" || rest ~ /^\$/) next
        if (rest ~ /^\[/) {
            sub(/^\[/, "", rest); sub(/\].*$/, "", rest)
            n = split(rest, a, ",")
            for (i = 1; i <= n; i++) { v = a[i]; gsub(/^[[:space:]"\047]+/, "", v); gsub(/[[:space:]"\047]+$/, "", v); print v }
        } else {
            v = rest; gsub(/^["\047]/, "", v); sub(/["\047 ,}].*$/, "", v); print v
        }
    }' "$1"
}
for f in $pinfiles; do
    badref=''
    for v in $(image_refs "$f"); do
        case $v in *[:/]*) ;; *) continue ;; esac
        case $v in '$'*) continue ;; esac
        if ! printf '%s\n' "$v" | grep -Eq '@sha256:[0-9a-f]{64}$'; then badref="$badref $v"; fi
    done
    if [ -n "$badref" ]; then
        bad "$(basename "$f") has container/image references not pinned by @sha256 digest:$badref"
    else
        good "every container/image reference in $(basename "$f") is pinned by digest"
    fi
done

# ---- 8. job isolation: secrets and write tokens never meet workspace code ----
isolation() { # <file>: one line per violation
    awk -v F="$(basename "$1")" '
    function flush() {
        if (job == "") return
        if ((env || wr) && runs != "") print F ": job " job " (" (env ? "environment" : "contents: write") ") runs build or workspace code:" runs
        if (env && ws != "") print F ": job " job " (environment) runs a workspace script or checks the workspace out:" ws
    }
    /^[^ #]/ { if (injobs) flush(); job = ""; injobs = ($0 ~ /^jobs:/); if (!injobs && $0 ~ /^permissions:/) top = 1; next }
    /^[[:space:]]*#/ { next }
    !injobs { if (top && $0 ~ /^[[:space:]]+contents:[[:space:]]*write/) print F ": workflow-level permissions grant contents: write to every job"; next }
    /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { flush(); job = $1; sub(/:$/, "", job); env = 0; wr = 0; runs = ""; ws = ""; next }
    {
        if ($0 ~ /^    environment:/) env = 1
        if ($0 ~ /contents:[[:space:]]*write/ || $0 ~ /permissions:[[:space:]]*write-all/) wr = 1
        line = $0; sub(/^[[:space:]]+/, "", line)
        if (line ~ /(^|[^A-Za-z0-9_.\/-])(cargo|rustup)([[:space:]]|$)/ || line ~ /signed\/hx-/ || line ~ /target\/([A-Za-z0-9_-]+\/)*(release|debug)\/hx-/) runs = runs " [" line "]"
        if (line ~ /actions\/checkout@/ || line ~ /(^|[[:space:];&|(])(sh|bash|dash)[[:space:]]+(\.\/)?(release|installer|packaging|perf|scripts)\//) ws = ws " [" line "]"
    }
    END { if (injobs) flush() }' "$1"
}
for f in $pinfiles; do
    iso=$(isolation "$f")
    if [ -n "$iso" ]; then
        bad "$(basename "$f") breaks job isolation (a signing or write-token job must only handle artifacts, never run build or workspace code):"
        printf '%s\n' "$iso" >&2
    else
        good "no environment or contents: write job in $(basename "$f") runs build or workspace code"
    fi
done

[ "$fail" = 0 ] && echo "release gate: PASSED" || echo "release gate: BLOCKED" >&2
exit "$fail"
