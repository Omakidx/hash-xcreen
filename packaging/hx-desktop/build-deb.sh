#!/bin/sh
# Builds hx-desktop.deb for ONE distro. Run it on that distro (the workflows run it in a job
# container of the distro): dpkg-shlibdeps computes `Depends` from the libraries the binary really
# links, so the result is only right for the distro it was built on. Same house style as
# packaging/hx-session/build-deb.sh.
#
#   packaging/hx-desktop/build-deb.sh --distro <d> --bin PATH --out DIR --source-date-epoch N [--version V]
#
#   --distro   ubuntu-24.04 | ubuntu-26.04 | debian-12 | debian-13 (selects the expected FFmpeg sonames)
#   --bin      the release build of hx-desktop (cargo build --release --locked -p hx-desktop --bin hx-desktop)
#   --out      receives <out>/hx-desktop.deb
#   --version  default: the workspace version
#
# Files, all root:root (the binary is stripped; none of it is setuid):
#   /usr/bin/hx-desktop                                          0755
#   /usr/share/applications/io.github.omakidx.hashxcreen.desktop
#   /usr/share/icons/hicolor/{16,24,32,48,64,128,256,512}x*/apps/io.github.omakidx.hashxcreen.png
#   /usr/share/icons/hicolor/scalable/apps/io.github.omakidx.hashxcreen.svg
#   /usr/share/metainfo/io.github.omakidx.hashxcreen.metainfo.xml
#   /usr/share/doc/hx-desktop/copyright
# No maintainer scripts: dpkg's own triggers refresh the icon cache and the desktop database.
# Version: V with every `-` replaced by `~` (so 1.4.2~rc.1 sorts before 1.4.2). Architecture amd64.
#
# Depends = what dpkg-shlibdeps finds (the linked libraries, FFmpeg among them) + RUNTIME_DEPENDS
# below (libraries the binary opens at run time, which no tool can see). Recommends: a Secret
# Service, which the app needs to keep the device key (without one it shows an error screen).
#
# KNOWN GAP, ubuntu-26.04: that release ships FFmpeg 8 (libavcodec62) and the workspace pins
# ffmpeg-next 7.1, which supports FFmpeg up to 7.1. The cargo build fails there (ffmpeg-sys-next's
# bindings want libavcodec/avfft.h, which FFmpeg 8 removed), not this script: the pull-request
# workflow has no 26.04 cell, and the release workflow does not publish a 26.04 desktop package
# until the workspace moves to ffmpeg-next 8.
# See packaging/hx-desktop/README.md.
#
# FFmpeg sonames expected per distro (checked 2026-11-22, the same table as packaging/hx-session):
#   ubuntu-24.04  libavcodec60 libavutil58   FFmpeg 6.1    (the build host of CI and releases)
#   ubuntu-26.04  libavcodec62 libavutil60   FFmpeg 8.0.1
#   debian-12     libavcodec59 libavutil57   FFmpeg 5.1.9
#   debian-13     libavcodec61 libavutil59   FFmpeg 7.1.5
set -eu
export LC_ALL=C
# shellcheck source=packaging/hx-desktop/common.sh
. "$(dirname "$0")/common.sh"

# Libraries the app opens with dlopen, which no tool can see (checked with `strings` on the release
# binary, 2026-11-22): winit loads the X11 and Wayland client libraries and libxkbcommon when the first
# window opens; Slint's renderer loads EGL, with GLX (libGL) as the X11 fallback. Re-check this list
# when slint or winit is bumped.
RUNTIME_DEPENDS='libegl1, libgl1, libwayland-client0, libwayland-egl1, libx11-6, libx11-xcb1, libxcursor1, libxi6, libxkbcommon0, libxkbcommon-x11-0, libxrender1'
RECOMMENDS='gnome-keyring | keepassxc | kwalletmanager, fonts-dejavu-core | fonts-noto-core'

version='' distro='' bin='' out='' sde=''
while [ $# -gt 0 ]; do
    case $1 in
    --version) version=${2:?}; shift 2 ;;
    --distro) distro=${2:?}; shift 2 ;;
    --bin) bin=${2:?}; shift 2 ;;
    --out) out=${2:?}; shift 2 ;;
    --source-date-epoch) sde=${2:?}; shift 2 ;;
    *) die "unknown option $1" ;;
    esac
done
[ -n "$version" ] || version=$(workspace_version)
check_version "$version"
check_sde "$sde"
case $distro in
ubuntu-24.04) want='libavcodec60 libavutil58' ;;
ubuntu-26.04) want='libavcodec62 libavutil60' ;;
debian-12) want='libavcodec59 libavutil57' ;;
debian-13) want='libavcodec61 libavutil59' ;;
*) die "unknown --distro" ;;
esac
[ -n "$out" ] || die "--out is required"
for t in dpkg-deb dpkg-shlibdeps strip; do command -v "$t" >/dev/null 2>&1 || die "$t not found (apt install dpkg-dev binutils)"; done

debver=$(printf '%s' "$version" | tr '-' '~')

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
umask 022
pkg=$work/pkg
mkdir -p "$pkg/usr/share/doc/hx-desktop" "$pkg/DEBIAN" "$work/debian"
stage_payload "$pkg" "$bin" "$version" "$sde"
install -m 0644 "$here/copyright" "$pkg/usr/share/doc/hx-desktop/copyright"
chmod 0755 "$pkg/usr/share/doc/hx-desktop" "$pkg/DEBIAN"

# ---- Depends from the libraries the binary really links ----
cat >"$work/debian/control" <<'EOF'
Source: hx-desktop
Section: net
Priority: optional
Maintainer: hash-xcreen <noreply@users.noreply.github.com>

Package: hx-desktop
Architecture: amd64
Description: hash-xcreen desktop app
EOF
substvars=$(cd "$work" && dpkg-shlibdeps -O "-e$pkg/usr/bin/$BIN_NAME" 2>"$work/shlibdeps.err") || {
    cat "$work/shlibdeps.err" >&2
    die "dpkg-shlibdeps failed"
}
linked=$(printf '%s\n' "$substvars" | sed -n 's/^shlibs:Depends=//p')
[ -n "$linked" ] || die "dpkg-shlibdeps produced no Depends"

# the dependency package names, without version constraints and alternatives' versions
names=$(printf '%s' "$linked" | tr ',' '\n' | sed 's/^ *//; s/ *(.*$//; s/ *|.*$//')
missing=''
for w in $want libc6; do
    printf '%s\n' "$names" | grep -qx "$w" || missing="$missing $w"
done
if [ -n "$missing" ]; then
    echo "build-deb.sh: Depends computed on this host: $linked" >&2
    die "expected packages missing from Depends:$missing (is this really $distro?)"
fi
depends="$linked, $RUNTIME_DEPENDS"

size=$(du -sk "$pkg/usr" | cut -f 1)
cat >"$pkg/DEBIAN/control" <<EOF
Package: hx-desktop
Version: $debver
Architecture: amd64
Maintainer: hash-xcreen <noreply@users.noreply.github.com>
Installed-Size: $size
Depends: $depends
Recommends: $RECOMMENDS
Section: net
Priority: optional
Homepage: https://github.com/Omakidx/hash-xcreen
Description: hash-xcreen desktop app
 Your own remote desktop, on a server you control. Adds a server over SSH or
 with one command, protects each device with a PIN, and shows the remote
 desktop in a window.
EOF
chmod 0644 "$pkg/DEBIAN/control"

# deterministic file times
SOURCE_DATE_EPOCH=$sde
export SOURCE_DATE_EPOCH
find "$pkg" -exec touch -h -d "@$sde" {} +

mkdir -p "$out"
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$out/hx-desktop.deb" >/dev/null
echo "build-deb.sh: $out/hx-desktop.deb ($debver, $distro) Depends: $depends" >&2
