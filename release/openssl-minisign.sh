#!/bin/sh
# Test-only minisign-compatible key generation and signing with openssl alone (no minisign
# binary needed). It makes the per-run TEST keys of the local release-dir builder
# (release/make-test-release.sh); real releases are signed by the minisign CLI in the protected
# `release-signing` environment of release.yml, with keys this repository never sees.
#
#   openssl-minisign.sh keygen <dir>                 writes <dir>/secret.pem (0600), <dir>/key.pub
#                                                    (a minisign public key file) and <dir>/key.line
#   openssl-minisign.sh sign <dir> <file> <comment>  writes <file>.minisig (prehashed, "ED")
#
# The signature file layout is documented in installer/install.sh. Needs openssl >= 3.0.
set -eu
umask 077
export LC_ALL=C

b64() { base64 | tr -d '\n'; }

case ${1:-} in
keygen)
    dir=${2:?usage: keygen <dir>}
    mkdir -p "$dir"
    openssl genpkey -algorithm ed25519 -out "$dir/secret.pem" 2>/dev/null
    chmod 0600 "$dir/secret.pem"
    openssl rand 8 >"$dir/keyid.bin"
    openssl pkey -in "$dir/secret.pem" -pubout -outform DER 2>/dev/null | tail -c 32 >"$dir/pk.raw"
    [ "$(wc -c <"$dir/pk.raw")" -eq 32 ] || { echo "cannot extract the public key" >&2; exit 1; }
    # "Ed" | key id | public key, base64 (minisign public key line)
    { printf 'Ed'; cat "$dir/keyid.bin" "$dir/pk.raw"; } | b64 >"$dir/key.line"
    printf '\n' >>"$dir/key.line"
    {
        echo 'untrusted comment: hash-xcreen TEST release key (never a real release)'
        cat "$dir/key.line"
    } >"$dir/key.pub"
    ;;
sign)
    dir=${2:?usage: sign <dir> <file> <comment>}
    file=${3:?usage: sign <dir> <file> <comment>}
    comment=${4:?usage: sign <dir> <file> <comment>}
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    openssl dgst -blake2b512 -binary "$file" >"$tmp/hash"
    openssl pkeyutl -sign -inkey "$dir/secret.pem" -rawin -in "$tmp/hash" -out "$tmp/sig"
    { cat "$tmp/sig"; printf '%s' "$comment"; } >"$tmp/global.msg"
    openssl pkeyutl -sign -inkey "$dir/secret.pem" -rawin -in "$tmp/global.msg" -out "$tmp/gsig"
    {
        echo 'untrusted comment: signature from hash-xcreen TEST release key'
        { printf 'ED'; cat "$dir/keyid.bin" "$tmp/sig"; } | b64
        printf '\n'
        printf 'trusted comment: %s\n' "$comment"
        b64 <"$tmp/gsig"
        printf '\n'
    } >"$file.minisig"
    ;;
*)
    echo "usage: openssl-minisign.sh keygen <dir> | sign <dir> <file> <comment>" >&2
    exit 2
    ;;
esac
