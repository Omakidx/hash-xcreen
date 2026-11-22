#!/bin/sh
# shellcheck disable=SC2034 # the paths assigned after sourcing install.sh are read by its functions
# install.sh's download path in a fake root, with a fake curl that serves a test release dir and
# ignores --max-filesize (an old curl). Run by the shell under test (installer/tests/handoff.sh).
#   download-case.sh <install.sh> <release dir> <fake dir> <mode: ok|big-manifest|big-artifact>
# The fake curl pads the manifest to over 1 MiB, or the artifact by one byte beyond the manifest's
# size, and records its first argument; install.sh must refuse both without help from curl.
inst=$1
rel=$2
fake=$3
mode=$4
set -- --hx-lib
# shellcheck source=../install.sh
. "$inst"
LOCK_FILE=$fake/run/hx-install.lock
BOOT_BASE=$fake/var/lib
AGENT_CURRENT=$fake/no-agent
OS_RELEASE=$fake/os-24
SYSTEMD_DIR=$fake/sd
EXPECT_UID=$(id -u)
is_root() { return 0; }
curl() {
    echo "CURL-FIRST:$1" >>"$fake/curl.log"
    _dest='' _url=''
    while [ $# -gt 0 ]; do
        [ "$1" = -o ] && _dest=$2
        _url=$1
        shift
    done
    case $_url in
    */manifest-x86_64.json)
        cp "$rel/manifest-x86_64.json" "$_dest"
        [ "$mode" = big-manifest ] && head -c 1100000 /dev/zero | tr '\000' ' ' >>"$_dest"
        ;;
    */manifest-x86_64.json.minisig) cp "$rel/manifest-x86_64.json.minisig" "$_dest" ;;
    */hx-*-x86_64.tar.gz)
        cp "$rel"/hx-*-x86_64.tar.gz "$_dest"
        [ "$mode" = big-artifact ] && printf 'x' >>"$_dest"
        ;;
    *) return 22 ;;
    esac
    return 0
}
: >"$fake/curl.log"
main --pair
