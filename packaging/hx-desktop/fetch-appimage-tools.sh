#!/bin/sh
# Downloads the AppImage build tools pinned in appimage-tools.lock into DIR and verifies every
# SHA-256 BEFORE anything is made executable. A file whose digest is wrong is deleted and the
# script fails: an unverified download is never run.
#
#   packaging/hx-desktop/fetch-appimage-tools.sh DIR
set -eu
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
dir=${1:?usage: fetch-appimage-tools.sh DIR}
mkdir -p "$dir"
grep -v '^#' "$here/appimage-tools.lock" | grep -v '^$' | while read -r name sha url; do
    f=$dir/$name
    if [ -f "$f" ] && printf '%s  %s\n' "$sha" "$f" | sha256sum -c - >/dev/null 2>&1; then
        echo "fetch-appimage-tools.sh: $name already verified"
    else
        rm -f "$f"
        # https only, no redirect to another scheme; the digest is the real check
        curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$f.part" "$url"
        if ! printf '%s  %s\n' "$sha" "$f.part" | sha256sum -c - >/dev/null; then
            rm -f "$f.part"
            echo "fetch-appimage-tools.sh: SHA-256 mismatch for $name (expected $sha)" >&2
            exit 1
        fi
        mv "$f.part" "$f"
        echo "fetch-appimage-tools.sh: $name verified"
    fi
    chmod 0755 "$f"
done
