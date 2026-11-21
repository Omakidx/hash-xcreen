#!/bin/sh
# Assembles the release tarball hx-<V>-x86_64.tar.gz (design C6, ipc.md 6.12 rule 4).
#
#   release/assemble.sh --version V --bin-dir DIR --session-dir DIR --out DIR \
#       --source-date-epoch N [--allow-partial-session]
#
# --bin-dir holds the agent binaries (static musl in a real release):
#   hx-privd hx-gatewayd hx-agent hx-update-fetcher hx-backup-worker   required
#   hx-privd-rescue                                                    optional (warns if absent)
# --session-dir holds <distro>/hx-session.deb for ubuntu-24.04 ubuntu-26.04 debian-12 debian-13;
# all four are required unless --allow-partial-session (local tests only).
#
# The archive is deterministic for a given input and gzip version: ustar ONLY (privd's `extract`
# refuses pax and GNU long-name headers), owner 0:0, a fixed mtime, sorted names, regular files
# only (no directory or link entries), `gzip -n`. Members are named without a leading "./":
#   hx-privd hx-gatewayd hx-agent hx-update-fetcher hx-backup-worker [hx-privd-rescue]
#   VERSION  session/<distro>/hx-session.deb
set -eu
export LC_ALL=C

die() { echo "assemble.sh: $*" >&2; exit 2; }

version='' bin='' sess='' out='' sde='' partial=0
while [ $# -gt 0 ]; do
    case $1 in
    --version) version=${2:?}; shift 2 ;;
    --bin-dir) bin=${2:?}; shift 2 ;;
    --session-dir) sess=${2:?}; shift 2 ;;
    --out) out=${2:?}; shift 2 ;;
    --source-date-epoch) sde=${2:?}; shift 2 ;;
    --allow-partial-session) partial=1; shift ;;
    *) die "unknown option $1" ;;
    esac
done
printf '%s\n' "$version" | grep -Eq '^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(-(alpha|beta|rc)\.[0-9]{1,4})?$' ||
    die "bad --version (ipc.md 6.12 rule 1)"
[ -d "$bin" ] || die "--bin-dir is not a directory"
[ -d "$sess" ] || die "--session-dir is not a directory"
[ -n "$out" ] || die "--out is required"
printf '%s\n' "$sde" | grep -Eq '^[0-9]{1,12}$' || die "--source-date-epoch must be a Unix time"

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
umask 022

for b in hx-privd hx-gatewayd hx-agent hx-update-fetcher hx-backup-worker; do
    [ -f "$bin/$b" ] && [ ! -L "$bin/$b" ] || die "$bin/$b is missing"
    cp "$bin/$b" "$stage/$b"
    chmod 0755 "$stage/$b"
done
if [ -f "$bin/hx-privd-rescue" ]; then
    cp "$bin/hx-privd-rescue" "$stage/hx-privd-rescue"
    chmod 0755 "$stage/hx-privd-rescue"
else
    echo "assemble.sh: warning: hx-privd-rescue is not in $bin (optional for privd)" >&2
fi
printf '%s\n' "$version" >"$stage/VERSION"
chmod 0644 "$stage/VERSION"

for d in ubuntu-24.04 ubuntu-26.04 debian-12 debian-13; do
    deb="$sess/$d/hx-session.deb"
    if [ -f "$deb" ] && [ ! -L "$deb" ]; then
        mkdir -p "$stage/session/$d"
        cp "$deb" "$stage/session/$d/hx-session.deb"
        chmod 0644 "$stage/session/$d/hx-session.deb"
    elif [ "$partial" -eq 0 ]; then
        die "$deb is missing (every distro is required for a release)"
    fi
done

mkdir -p "$out"
art="$out/hx-$version-x86_64.tar.gz"
(
    cd "$stage"
    find . -type f | sed 's|^\./||' | sort >"$stage.list"
    tar --format=ustar --owner=0 --group=0 --numeric-owner --mtime="@$sde" \
        --no-recursion -cf - -T "$stage.list" | gzip -n -9 >"$art.tmp"
    rm -f "$stage.list"
)
mv "$art.tmp" "$art"

# Self-checks: readable, ustar magic in the first header, no non-regular members, within bounds.
gzip -t "$art"
magic=$(gzip -dc "$art" | dd bs=1 skip=257 count=5 2>/dev/null)
[ "$magic" = ustar ] || die "the archive is not ustar"
if [ "$(gzip -dc "$art" | dd bs=1 skip=262 count=1 2>/dev/null | od -An -tx1 | tr -d ' ')" != 00 ]; then
    die "the archive uses the GNU ustar variant (magic not NUL-terminated)"
fi
if tar -tvzf "$art" | grep -v '^-' >/dev/null; then die "the archive holds a non-regular member"; fi
size=$(wc -c <"$art" | tr -d ' ')
[ "$size" -le 268435456 ] || die "the archive is larger than 256 MiB"
echo "assemble.sh: wrote $art ($size bytes)" >&2
