#!/bin/sh
# Shared by build-deb.sh and build-appimage.sh: sourced, never run. Defines the app id, the version
# rules and `stage_payload`, which lays out the files both packages ship under one prefix.
# shellcheck disable=SC2034  # variables are used by the scripts that source this file

APP_ID=io.github.omakidx.hashxcreen
BIN_NAME=hx-desktop
ICON_SIZES='16 24 32 48 64 128 256 512'

die() { echo "$(basename "$0"): $*" >&2; exit 2; }

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

# The workspace version, read the way the release gate reads it.
workspace_version() {
    sed -n '/^\[workspace.package\]/,/^\[/s/^version *= *"\(.*\)"$/\1/p' "$root/Cargo.toml" | head -n 1
}

# Same rule as release.yml and packaging/hx-session (ipc.md 6.12 rule 1).
check_version() {
    printf '%s\n' "$1" | grep -Eq '^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(-(alpha|beta|rc)\.[0-9]{1,4})?$' ||
        die "bad version '$1' (ipc.md 6.12 rule 1)"
}

check_sde() {
    printf '%s\n' "$1" | grep -Eq '^[0-9]{1,12}$' || die "--source-date-epoch must be a Unix time"
}

# stage_payload ROOT BIN VERSION SDE
#   ROOT  directory that receives usr/... (created)
#   BIN   the release build of hx-desktop (copied and stripped; the original is untouched)
# Installs, all 0644 unless noted:
#   usr/bin/hx-desktop (0755), usr/share/applications/<id>.desktop,
#   usr/share/icons/hicolor/<N>x<N>/apps/<id>.png (each size), .../scalable/apps/<id>.svg,
#   usr/share/metainfo/<id>.metainfo.xml (version and date filled in)
stage_payload() {
    _root=$1 _bin=$2 _ver=$3 _sde=$4
    [ -f "$_bin" ] || die "$_bin is missing (cargo build --release --locked -p hx-desktop --bin hx-desktop)"
    mkdir -p "$_root/usr/bin" "$_root/usr/share/applications" "$_root/usr/share/metainfo" \
        "$_root/usr/share/icons/hicolor/scalable/apps"
    cp "$_bin" "$_root/usr/bin/$BIN_NAME"
    ${STRIP:-strip} --strip-unneeded "$_root/usr/bin/$BIN_NAME"
    chmod 0755 "$_root/usr/bin/$BIN_NAME"
    install -m 0644 "$here/$APP_ID.desktop" "$_root/usr/share/applications/$APP_ID.desktop"
    install -m 0644 "$here/icons/hash-xcreen.svg" "$_root/usr/share/icons/hicolor/scalable/apps/$APP_ID.svg"
    for _s in $ICON_SIZES; do
        mkdir -p "$_root/usr/share/icons/hicolor/${_s}x${_s}/apps"
        install -m 0644 "$here/icons/png/hash-xcreen-$_s.png" \
            "$_root/usr/share/icons/hicolor/${_s}x${_s}/apps/$APP_ID.png"
    done
    _date=$(date -u -d "@$_sde" +%Y-%m-%d)
    sed "s/@VERSION@/$_ver/; s/@DATE@/$_date/" "$here/$APP_ID.metainfo.xml.in" \
        >"$_root/usr/share/metainfo/$APP_ID.metainfo.xml"
    chmod 0644 "$_root/usr/share/metainfo/$APP_ID.metainfo.xml"
    # no leftover placeholder
    ! grep -q '@[A-Z]*@' "$_root/usr/share/metainfo/$APP_ID.metainfo.xml" || die "metainfo placeholder left"
    # directories: 0755
    find "$_root" -type d -exec chmod 0755 {} +
}
