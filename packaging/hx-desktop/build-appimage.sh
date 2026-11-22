#!/bin/sh
# Builds the hx-desktop AppImage (x86_64). Run it on Ubuntu 24.04: the AppImage runs on every distro
# whose glibc is at least that of the build host (2.39), so the oldest supported build host is the
# one to use (the release workflow and CI build it on ubuntu-24.04).
#
#   packaging/hx-desktop/build-appimage.sh --bin PATH --out DIR --source-date-epoch N \
#       --tools-dir DIR [--version V]
#
#   --bin      the release build of hx-desktop (cargo build --release --locked -p hx-desktop --bin hx-desktop)
#   --out      receives <out>/hx-desktop-<V>-x86_64.AppImage
#   --tools-dir  where fetch-appimage-tools.sh keeps linuxdeploy, appimagetool and the runtime
#              (downloaded on first use, always verified against appimage-tools.lock)
#   --version  default: the workspace version
#
# What it does: stage the files (common.sh) into an AppDir; linuxdeploy copies every shared library
# the binary links and every library those need into the AppDir, except the ones every desktop
# provides (its excludelist: glibc, OpenGL/EGL, libdrm, X11 and so on) and patches RPATH to
# $ORIGIN/../lib; appimagetool packs the AppDir with the pinned runtime. FFmpeg IS bundled (see
# README.md for why). The system provides: glibc, the graphics stack (EGL, Wayland, X11/XCB,
# libxkbcommon are loaded at run time), fontconfig, harfbuzz and fribidi (the excludelist) and, for saved servers, a Secret Service (keyring).
set -eu
export LC_ALL=C
# shellcheck source=packaging/hx-desktop/common.sh
. "$(dirname "$0")/common.sh"

version='' bin='' out='' sde='' tools=''
while [ $# -gt 0 ]; do
    case $1 in
    --version) version=${2:?}; shift 2 ;;
    --bin) bin=${2:?}; shift 2 ;;
    --out) out=${2:?}; shift 2 ;;
    --source-date-epoch) sde=${2:?}; shift 2 ;;
    --tools-dir) tools=${2:?}; shift 2 ;;
    *) die "unknown option $1" ;;
    esac
done
[ -n "$version" ] || version=$(workspace_version)
check_version "$version"
check_sde "$sde"
[ -n "$out" ] && [ -n "$tools" ] || die "--out and --tools-dir are required"
[ "$(uname -m)" = x86_64 ] || die "x86_64 only"

# the tools: downloaded when missing, ALWAYS verified against the pinned SHA-256 before use
sh "$here/fetch-appimage-tools.sh" "$tools"
tools=$(cd "$tools" && pwd)
ld=$tools/linuxdeploy-x86_64.AppImage
at=$tools/appimagetool-x86_64.AppImage
rt=$tools/runtime-x86_64

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
umask 022
appdir=$work/hx-desktop.AppDir
stage_payload "$appdir" "$bin" "$version" "$sde"

# linuxdeploy: bundle the libraries, link AppRun, place the desktop file and the icon at the root.
# NO_STRIP: its bundled `strip` is older than the libraries of a current distro and fails on
# them; the binary is already stripped by stage_payload and the distro's libraries ship stripped.
# --appimage-extract-and-run: the AppImage tools need no FUSE (CI containers have none).
(
    cd "$work"
    NO_STRIP=1 APPIMAGE_EXTRACT_AND_RUN=1 "$ld" --appdir "$appdir" \
        --executable "$appdir/usr/bin/$BIN_NAME" \
        --desktop-file "$appdir/usr/share/applications/$APP_ID.desktop" \
        --icon-file "$appdir/usr/share/icons/hicolor/256x256/apps/$APP_ID.png" --icon-filename "$APP_ID"
) >"$work/linuxdeploy.log" 2>&1 || { cat "$work/linuxdeploy.log" >&2; die "linuxdeploy failed"; }

[ -e "$appdir/AppRun" ] || die "linuxdeploy made no AppRun"
[ -f "$appdir/usr/bin/$BIN_NAME" ] || die "the binary is not in the AppDir"
# every bundled library must be able to find the others without the system's copies
ls "$appdir/usr/lib" >/dev/null 2>&1 || die "no usr/lib in the AppDir (nothing was bundled?)"

# deterministic file times, then the squashfs
SOURCE_DATE_EPOCH=$sde
export SOURCE_DATE_EPOCH
find "$appdir" -exec touch -h -d "@$sde" {} +

mkdir -p "$out"
# absolute: appimagetool runs in the work directory
out=$(cd "$out" && pwd)
name=hx-desktop-$version-x86_64.AppImage
rm -f "$out/$name"
# -n: do not run appstreamcli (CI validates the metainfo itself); --runtime-file: the pinned runtime
(
    cd "$work"
    ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$at" --runtime-file "$rt" -n --comp zstd "$appdir" "$out/$name"
) >"$work/appimagetool.log" 2>&1 || { cat "$work/appimagetool.log" >&2; die "appimagetool failed"; }
chmod 0755 "$out/$name"
echo "build-appimage.sh: $out/$name ($version) $(du -h "$out/$name" | cut -f 1), $(find "$appdir/usr/lib" -type f | wc -l) bundled libraries" >&2
