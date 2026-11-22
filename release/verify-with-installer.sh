#!/bin/sh
# Verifies a minisign signature with the verification function of a SHIPPED install.sh (sourced in
# its test mode, `--hx-lib`), against the keys that script embeds. The release job runs this on the
# signature it has just made, which proves the install.sh it publishes accepts the signature it
# publishes. Exit 0 valid, 1 not valid.
#
#   release/verify-with-installer.sh <install.sh> <file> <file.minisig>
set -u
[ $# -eq 3 ] || { echo "usage: verify-with-installer.sh <install.sh> <file> <minisig>" >&2; exit 2; }
inst=$1
file=$2
sig=$3
set -- --hx-lib
# shellcheck source=../installer/install.sh
. "$inst"
if verify_signature "$file" "$sig"; then
    echo "verify-with-installer: $file is validly signed (accepted by $inst)"
    exit 0
fi
echo "verify-with-installer: NOT valid: $VERR" >&2
exit 1
