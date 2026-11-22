#!/bin/sh
# Builds hx-session.deb for ONE distro (design C6). Run it on that distro (the release workflow runs
# it in a job container of the distro): dpkg-shlibdeps computes `Depends` from the libraries the
# binaries really link, so the result is only right for the distro it was built on.
#
#   packaging/hx-session/build-deb.sh --version V --distro <d> --bin-dir DIR --out DIR \
#       --source-date-epoch N [--allow-missing-pwcheck]
#
#   --distro   ubuntu-24.04 | ubuntu-26.04 | debian-12 | debian-13 (selects the expected FFmpeg sonames)
#   --bin-dir  holds the release builds of `hx-session` and `hx-pwcheck`
#              (`cargo build --release --locked -p hx-session --bin hx-session -p hx-pwcheck`)
#   --out      receives <out>/hx-session.deb
#
# The package carries binaries only: no systemd units (they stay in recipes/fragments/xfce-desktop.toml)
# and no maintainer scripts. Files, all root:root:
#   /usr/lib/hx-session/            0755
#   /usr/lib/hx-session/hx-session  0755
#   /usr/lib/hx-session/hx-pwcheck  0755
#   /usr/share/doc/hx-session/copyright
# Version: V with every `-` replaced by `~` (so 1.4.2~rc.1 sorts before 1.4.2). Architecture amd64.
#
# TODO(WS-4b): apps/hx-pwcheck does not exist on the branch this was written on. Until it lands,
# `--allow-missing-pwcheck` builds the package without it (local tests); a release build does not
# pass that flag, so the release workflow fails closed if hx-pwcheck was not built.
#
# FFmpeg sonames expected per distro (checked 2026-11-21):
#   ubuntu-24.04  libavcodec60 libavutil58   FFmpeg 6.1    (spike 1c-e2e, on a 24.04 host)
#   ubuntu-26.04  libavcodec62 libavutil60   FFmpeg 8.0.1  (packages.ubuntu.com, resolute: 7:8.0.1-3ubuntu2)
#   debian-12     libavcodec59 libavutil57   FFmpeg 5.1.9  (packages.debian.org, bookworm: 7:5.1.9-0+deb12u1)
#   debian-13     libavcodec61 libavutil59   FFmpeg 7.1.5  (packages.debian.org, trixie: 7:7.1.5-0+deb13u1)
set -eu
export LC_ALL=C

die() { echo "build-deb.sh: $*" >&2; exit 2; }

version='' distro='' bin='' out='' sde='' allow_missing=0
while [ $# -gt 0 ]; do
    case $1 in
    --version) version=${2:?}; shift 2 ;;
    --distro) distro=${2:?}; shift 2 ;;
    --bin-dir) bin=${2:?}; shift 2 ;;
    --out) out=${2:?}; shift 2 ;;
    --source-date-epoch) sde=${2:?}; shift 2 ;;
    --allow-missing-pwcheck) allow_missing=1; shift ;;
    *) die "unknown option $1" ;;
    esac
done
printf '%s\n' "$version" | grep -Eq '^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(-(alpha|beta|rc)\.[0-9]{1,4})?$' ||
    die "bad --version (ipc.md 6.12 rule 1)"
case $distro in
ubuntu-24.04) want='libavcodec60 libavutil58' ;;
ubuntu-26.04) want='libavcodec62 libavutil60' ;;
debian-12) want='libavcodec59 libavutil57' ;;
debian-13) want='libavcodec61 libavutil59' ;;
*) die "unknown --distro" ;;
esac
[ -d "$bin" ] || die "--bin-dir is not a directory"
[ -n "$out" ] || die "--out is required"
printf '%s\n' "$sde" | grep -Eq '^[0-9]{1,12}$' || die "--source-date-epoch must be a Unix time"
for t in dpkg-deb dpkg-shlibdeps; do command -v "$t" >/dev/null 2>&1 || die "$t not found (apt install dpkg-dev)"; done

here=$(cd "$(dirname "$0")" && pwd)
debver=$(printf '%s' "$version" | tr '-' '~')

bins='hx-session'
if [ -f "$bin/hx-pwcheck" ]; then
    bins='hx-session hx-pwcheck'
elif [ "$allow_missing" -eq 1 ]; then
    echo "build-deb.sh: warning: $bin/hx-pwcheck is missing (TODO WS-4b); building WITHOUT it" >&2
else
    die "$bin/hx-pwcheck is missing (pass --allow-missing-pwcheck only for local tests)"
fi
[ -f "$bin/hx-session" ] || die "$bin/hx-session is missing"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
umask 022
pkg=$work/pkg
mkdir -p "$pkg/usr/lib/hx-session" "$pkg/usr/share/doc/hx-session" "$pkg/DEBIAN" "$work/debian"
for b in $bins; do
    cp "$bin/$b" "$pkg/usr/lib/hx-session/$b"
    chmod 0755 "$pkg/usr/lib/hx-session/$b"
done
cp "$here/copyright" "$pkg/usr/share/doc/hx-session/copyright"
chmod 0644 "$pkg/usr/share/doc/hx-session/copyright"
chmod 0755 "$pkg/usr/lib/hx-session" "$pkg/usr" "$pkg/usr/lib" "$pkg/usr/share" "$pkg/usr/share/doc" "$pkg/usr/share/doc/hx-session"

# ---- Depends from the libraries the binaries really link ----
cat >"$work/debian/control" <<'EOF'
Source: hx-session
Section: net
Priority: optional
Maintainer: hash-xcreen <noreply@users.noreply.github.com>

Package: hx-session
Architecture: amd64
Description: hash-xcreen in-desktop session daemon
EOF
set --
for b in $bins; do set -- "$@" "-e$pkg/usr/lib/hx-session/$b"; done
substvars=$(cd "$work" && dpkg-shlibdeps -O "$@" 2>"$work/shlibdeps.err") || {
    cat "$work/shlibdeps.err" >&2
    die "dpkg-shlibdeps failed"
}
depends=$(printf '%s\n' "$substvars" | sed -n 's/^shlibs:Depends=//p')
[ -n "$depends" ] || die "dpkg-shlibdeps produced no Depends"

# the dependency package names, without version constraints and alternatives' versions
names=$(printf '%s' "$depends" | tr ',' '\n' | sed 's/^ *//; s/ *(.*$//; s/ *|.*$//')
missing=''
for w in $want libc6; do
    printf '%s\n' "$names" | grep -qx "$w" || missing="$missing $w"
done
if [ -n "$missing" ]; then
    echo "build-deb.sh: Depends computed on this host: $depends" >&2
    die "expected packages missing from Depends:$missing (is this really $distro?)"
fi
if [ "$bins" = 'hx-session hx-pwcheck' ]; then
    printf '%s\n' "$names" | grep -qx libcrypt1 || die "hx-pwcheck must link libcrypt1 (libxcrypt crypt_rn); Depends: $depends"
fi

size=$(du -sk "$pkg/usr" | cut -f 1)
cat >"$pkg/DEBIAN/control" <<EOF
Package: hx-session
Version: $debver
Architecture: amd64
Maintainer: hash-xcreen <noreply@users.noreply.github.com>
Installed-Size: $size
Depends: $depends
Section: net
Priority: optional
Homepage: https://github.com/Omakidx/hash-xcreen
Description: hash-xcreen in-desktop session daemon
 Captures, encodes and serves the desktop of an hash-xcreen container, and
 checks the desktop user's password. Installed by the host agent (privd).
EOF
chmod 0755 "$pkg/DEBIAN"
chmod 0644 "$pkg/DEBIAN/control"

# deterministic file times
SOURCE_DATE_EPOCH=$sde
export SOURCE_DATE_EPOCH
find "$pkg" -exec touch -h -d "@$sde" {} +

mkdir -p "$out"
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$out/hx-session.deb" >/dev/null
echo "build-deb.sh: $out/hx-session.deb ($debver, $distro) Depends: $depends" >&2
