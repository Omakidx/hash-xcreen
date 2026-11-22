#!/bin/sh
# Smoke test of an hx-desktop AppImage without FUSE: extract it, check the files and that every
# library the binary links resolves from the bundle or the system, then run it (smoke-run.sh).
#
#   packaging/hx-desktop/smoke-appimage.sh APPIMAGE VERSION
set -eu
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
img=${1:?usage: smoke-appimage.sh APPIMAGE VERSION}
ver=${2:?usage: smoke-appimage.sh APPIMAGE VERSION}
app=io.github.omakidx.hashxcreen
img=$(cd "$(dirname "$img")" && pwd)/$(basename "$img")
[ -x "$img" ] || { echo "smoke-appimage.sh: $img is not executable" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
(cd "$work" && "$img" --appimage-extract >/dev/null)
sq=$work/squashfs-root
for f in AppRun usr/bin/hx-desktop "usr/share/applications/$app.desktop" "$app.desktop" \
    "usr/share/metainfo/$app.metainfo.xml" "usr/share/icons/hicolor/scalable/apps/$app.svg" \
    "usr/share/icons/hicolor/256x256/apps/$app.png" .DirIcon; do
    [ -e "$sq/$f" ] || { echo "smoke-appimage.sh: $f is missing from the AppImage" >&2; exit 1; }
done
grep -q '^Exec=hx-desktop$' "$sq/$app.desktop" || { echo "smoke-appimage.sh: root desktop file has the wrong Exec" >&2; exit 1; }
ls "$sq"/usr/lib/libavcodec.so.* >/dev/null 2>&1 || { echo "smoke-appimage.sh: FFmpeg is not bundled" >&2; exit 1; }
if ldd "$sq/usr/bin/hx-desktop" | grep -q 'not found'; then
    ldd "$sq/usr/bin/hx-desktop" | grep 'not found' >&2
    echo "smoke-appimage.sh: unresolved library" >&2
    exit 1
fi
echo "smoke-appimage.sh: layout ok, $(find "$sq/usr/lib" -type f | wc -l) bundled libraries"

APPIMAGE_EXTRACT_AND_RUN=1 sh "$here/smoke-run.sh" "$ver" "$img"
