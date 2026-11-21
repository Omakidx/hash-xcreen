#!/bin/sh
# Writes the canonical release manifest (design C6, ipc.md 6.12): ONE line, no spaces, the keys
# in exactly this order, ending in one LF. privd's serde parser accepts it and install.sh's
# grep depends on the exact shape.
#
#   release/manifest.sh --version V --channel stable|beta --artifact <tar.gz file> \
#       --timestamp <unix seconds> [--min-previous V] [--arch x86_64] --out <file>
#
# size and sha256 are computed from the artifact file; the artifact name must be hx-V-ARCH.tar.gz.
set -eu
export LC_ALL=C

die() { echo "manifest.sh: $*" >&2; exit 2; }

version='' channel='' artifact='' ts='' minprev='' arch=x86_64 out=''
while [ $# -gt 0 ]; do
    case $1 in
    --version) version=${2:?}; shift 2 ;;
    --channel) channel=${2:?}; shift 2 ;;
    --artifact) artifact=${2:?}; shift 2 ;;
    --timestamp) ts=${2:?}; shift 2 ;;
    --min-previous) minprev=${2:?}; shift 2 ;;
    --arch) arch=${2:?}; shift 2 ;;
    --out) out=${2:?}; shift 2 ;;
    *) die "unknown option $1" ;;
    esac
done

VER_RE='^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(-(alpha|beta|rc)\.[0-9]{1,4})?$'
printf '%s\n' "$version" | grep -Eq "$VER_RE" || die "bad --version (ipc.md 6.12 rule 1)"
case $channel in stable | beta) ;; *) die "--channel must be stable or beta" ;; esac
[ "$arch" = x86_64 ] || die "only x86_64 is built"
[ -f "$artifact" ] || die "--artifact is not a file"
printf '%s\n' "$ts" | grep -Eq '^(0|[1-9][0-9]{0,11})$' || die "bad --timestamp"
[ "$ts" -gt 0 ] || die "--timestamp must be positive"
if [ -n "$minprev" ]; then
    printf '%s\n' "$minprev" | grep -Eq "$VER_RE" || die "bad --min-previous"
fi
[ -n "$out" ] || die "--out is required"

name="hx-$version-$arch.tar.gz"
[ "$(basename "$artifact")" = "$name" ] || die "the artifact file must be named $name"
size=$(wc -c <"$artifact" | tr -d ' ')
[ "$size" -ge 1 ] && [ "$size" -le 268435456 ] || die "artifact size $size is outside 1..256 MiB"
sha=$(sha256sum "$artifact" | cut -d ' ' -f 1)

{
    printf '{"schema":1,"channel":"%s","version":"%s","arch":"%s","artifact":"%s","size":%s,"sha256":"%s","timestamp":%s' \
        "$channel" "$version" "$arch" "$name" "$size" "$sha" "$ts"
    if [ -n "$minprev" ]; then printf ',"min_previous":"%s"' "$minprev"; fi
    printf '}\n'
} >"$out"
