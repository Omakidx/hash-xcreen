#!/bin/sh
# Builds a TEST-KEYED release directory for local use (gate G1a: the 1E test harness uses it).
# Nothing here is a real release: the keys are made for this run and `release-keys/*.pub` are
# not touched.
#
#   release/make-test-release.sh --out DIR [--version V] [--channel stable|beta]
#       [--bin-dir DIR] [--session-dir DIR] [--timestamp UNIX] [--min-previous V]
#
# DIR (must not exist, or be empty) receives:
#   hx-<V>-x86_64.tar.gz          deterministic ustar tarball (release/assemble.sh)
#   manifest-x86_64.json          canonical manifest (release/manifest.sh)
#   manifest-x86_64.json.minisig  prehashed minisign signature made with the test CURRENT key
#   install.sh                    a copy of installer/install.sh whose KEY_CURRENT / KEY_NEXT are
#                                 the test keys (nothing else changed), accepted by
#                                 `sh DIR/install.sh --release-dir DIR`
#   test-release.pubkey           the test CURRENT public key line: build the agent with
#                                 HX_TEST_RELEASE_PUBKEY="$(cat DIR/test-release.pubkey)" and
#                                 --features test-release-key and privd's `extract` /
#                                 UpdateKeys accept the release too
#   private/{current,next}/       the test secret keys (mode 0700; re-sign or tamper in tests)
#
# Defaults: --version is the workspace version, --channel stable, --timestamp now. Without
# --bin-dir the binaries are small shell stubs (the stub hx-agent prints how it was started and
# whether it holds the install lock); without --session-dir the four hx-session.deb files are
# placeholders. Pass real build outputs for an end-to-end run.
# The release dir is owned by the invoking user: run install.sh against it as root only inside a
# test environment (install.sh insists on a root-owned release dir).
set -eu
export LC_ALL=C

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)

die() { echo "make-test-release.sh: $*" >&2; exit 2; }

out='' version='' channel=stable bin='' sess='' ts='' minprev=''
while [ $# -gt 0 ]; do
    case $1 in
    --out) out=${2:?}; shift 2 ;;
    --version) version=${2:?}; shift 2 ;;
    --channel) channel=${2:?}; shift 2 ;;
    --bin-dir) bin=${2:?}; shift 2 ;;
    --session-dir) sess=${2:?}; shift 2 ;;
    --timestamp) ts=${2:?}; shift 2 ;;
    --min-previous) minprev=${2:?}; shift 2 ;;
    *) die "unknown option $1" ;;
    esac
done
[ -n "$out" ] || die "--out is required"
if [ -z "$version" ]; then
    version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version *= *"\(.*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)
    [ -n "$version" ] || die "cannot read the workspace version"
fi
[ -n "$ts" ] || ts=$(date +%s)
if [ -e "$out" ] && [ -n "$(ls -A "$out" 2>/dev/null)" ]; then die "$out exists and is not empty"; fi
mkdir -p "$out"
out=$(cd "$out" && pwd)
chmod 0755 "$out"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# ---- inputs ----
if [ -z "$bin" ]; then
    bin=$work/bin
    mkdir -p "$bin"
    for b in hx-privd hx-gatewayd hx-update-fetcher hx-backup-worker hx-privd-rescue; do
        printf '#!/bin/sh\nexit 0\n' >"$bin/$b"
    done
    cat >"$bin/hx-agent" <<'STUB'
#!/bin/sh
# hx-agent stub of a TEST release: reports how the bootstrap started it, then exits 0.
echo "STUB-ARGV:$*"
if [ -e /proc/self/fd/9 ]; then echo "STUB-FD9:open"; else echo "STUB-FD9:closed"; fi
l=$(readlink /proc/self/fd/9 2>/dev/null || true)
echo "STUB-LOCKFILE:$l"
if [ -n "$l" ] && ! flock -n "$l" true 2>/dev/null; then echo "STUB-LOCK:held"; else echo "STUB-LOCK:free"; fi
if [ ! -t 0 ]; then echo "STUB-STDIN:$(dd bs=1 count=4 2>/dev/null)"; fi
dir=''
while [ $# -gt 0 ]; do
    if [ "$1" = --bootstrap-dir ]; then dir=$2; fi
    shift
done
if [ -n "$dir" ]; then echo "STUB-FILES:$(ls "$dir" | tr '\n' ' ')"; fi
exit 0
STUB
    chmod 0755 "$bin"/*
fi
if [ -z "$sess" ]; then
    sess=$work/session
    for d in ubuntu-24.04 ubuntu-26.04 debian-12 debian-13; do
        mkdir -p "$sess/$d"
        printf '!<arch>\nplaceholder %s\n' "$d" >"$sess/$d/hx-session.deb"
    done
fi

# ---- tarball, manifest ----
sh "$here/assemble.sh" --version "$version" --bin-dir "$bin" --session-dir "$sess" --out "$out" \
    --source-date-epoch "$ts"
art="$out/hx-$version-x86_64.tar.gz"
if [ -n "$minprev" ]; then
    sh "$here/manifest.sh" --version "$version" --channel "$channel" --artifact "$art" \
        --timestamp "$ts" --min-previous "$minprev" --out "$out/manifest-x86_64.json"
else
    sh "$here/manifest.sh" --version "$version" --channel "$channel" --artifact "$art" \
        --timestamp "$ts" --out "$out/manifest-x86_64.json"
fi

# ---- keys, signature, patched install.sh ----
mkdir -p "$out/private"
chmod 0700 "$out/private"
sh "$here/openssl-minisign.sh" keygen "$out/private/current"
sh "$here/openssl-minisign.sh" keygen "$out/private/next"
sh "$here/openssl-minisign.sh" sign "$out/private/current" "$out/manifest-x86_64.json" \
    "hx-manifest v$version channel=$channel arch=x86_64"
cur=$(cat "$out/private/current/key.line")
nxt=$(cat "$out/private/next/key.line")
printf '%s\n' "$cur" >"$out/test-release.pubkey"
sed -e "s|^KEY_CURRENT='.*'\$|KEY_CURRENT='$cur'|" -e "s|^KEY_NEXT='.*'\$|KEY_NEXT='$nxt'|" \
    "$root/installer/install.sh" >"$out/install.sh"
chmod 0755 "$out/install.sh"
grep -q "^KEY_CURRENT='$cur'\$" "$out/install.sh" && grep -q "^KEY_NEXT='$nxt'\$" "$out/install.sh" ||
    die "could not embed the test keys in install.sh"
chmod 0644 "$out"/manifest-x86_64.json "$out"/manifest-x86_64.json.minisig "$art"

echo "make-test-release.sh: test release $version ($channel) in $out" >&2
echo "make-test-release.sh: agent build: HX_TEST_RELEASE_PUBKEY=\"\$(cat $out/test-release.pubkey)\" cargo build -p hx-agent --features test-release-key" >&2
