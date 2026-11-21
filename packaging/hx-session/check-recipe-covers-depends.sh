#!/bin/sh
# Fails when the hx-session.deb depends on a package the desktop recipe does not install.
# privd's InstallSession runs `dpkg -i`, which resolves no dependencies, so every library in the
# package's Depends must already be in the image: the recipe installs the FFmpeg runtime through
# the per-distro vars `libavcodec_pkg` and `libavutil_pkg` (recipes/fragments/distro-<d>.toml,
# referenced from recipes/fragments/xfce-desktop.toml).
#
#   packaging/hx-session/check-recipe-covers-depends.sh --deb <hx-session.deb> --distro <d>
#
# Packages present in every base image (libc6, libgcc-s1, libcrypt1, libstdc++6: Essential or
# required by apt itself) need no recipe entry.
set -eu
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

deb='' distro=''
while [ $# -gt 0 ]; do
    case $1 in
    --deb) deb=${2:?}; shift 2 ;;
    --distro) distro=${2:?}; shift 2 ;;
    *) echo "check-recipe-covers-depends.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
[ -f "$deb" ] && [ -f "$root/recipes/fragments/distro-$distro.toml" ] || {
    echo "usage: check-recipe-covers-depends.sh --deb <deb> --distro <ubuntu-24.04|...>" >&2
    exit 2
}

frag=$root/recipes/fragments/distro-$distro.toml
var() { sed -n "s/^$1 *= *\"\(.*\)\"\$/\1/p" "$frag" | head -n 1; }
avcodec=$(var libavcodec_pkg)
avutil=$(var libavutil_pkg)
[ -n "$avcodec" ] && [ -n "$avutil" ] || { echo "FAIL: $frag defines no libavcodec_pkg / libavutil_pkg" >&2; exit 1; }
# the package list of the desktop fragment must reference both vars
for v in libavcodec_pkg libavutil_pkg; do
    grep -q "{{$v}}" "$root/recipes/fragments/xfce-desktop.toml" ||
        { echo "FAIL: xfce-desktop.toml does not install {{$v}}" >&2; exit 1; }
done

depends=$(dpkg-deb -f "$deb" Depends)
names=$(printf '%s' "$depends" | tr ',' '\n' | sed 's/^ *//; s/ *(.*$//; s/ *|.*$//')
status=0
for n in $names; do
    case $n in
    libc6 | libgcc-s1 | libcrypt1 | libstdc++6) continue ;;
    "$avcodec" | "$avutil") continue ;;
    *)
        echo "FAIL: the .deb depends on '$n', which the $distro recipe does not install" >&2
        status=1
        ;;
    esac
done
for n in "$avcodec" "$avutil"; do
    printf '%s\n' "$names" | grep -qx "$n" || {
        echo "FAIL: the recipe installs '$n' but the .deb does not depend on it (stale var?)" >&2
        status=1
    }
done
[ "$status" = 0 ] && echo "recipe covers the .deb Depends for $distro: $depends"
exit "$status"
