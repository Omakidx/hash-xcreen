#!/bin/sh
# hash-xcreen installer bootstrap (docs/architecture.md 5.1; design contract C4 and C5).
#
#   curl -fsSL https://github.com/Omakidx/hash-xcreen/releases/download/channel-stable/install.sh \
#     | sudo sh -s -- --pair
#   sudo sh install.sh --ssh ...            (run from a file: --ssh reads its secrets from stdin)
#
# What this script does, and nothing else:
#   1. preflight: root, x86_64, systemd, a supported OS, the tools it needs, a known-answer
#      self-test of its own signature check;
#   2. takes /run/hx-install.lock (fd 9) so two installs cannot run at once;
#   3. downloads the signed release manifest of the channel, verifies the minisign signature
#      with openssl (below), then downloads the release tarball and checks its size and SHA-256;
#   4. extracts ./hx-agent from it into a private directory under /var/lib (not /run: Ubuntu and
#      Debian mount /run noexec, and the agent is executed from there), and
#   5. execs `hx-agent install`, which verifies everything again with its compiled-in keys and
#      does the real work. The lock stays held across the exec.
#
# TRUST ROOT. With `curl ... | sudo sh` this script itself is unsigned: TLS to github.com is all
# that protects the first step (every later step is signature-checked). To check the script
# before running it, download it with its signature and verify with minisign and the release
# public key published in the repository (apps/hx-agent/release-keys/current.pub):
#     curl -O https://github.com/Omakidx/hash-xcreen/releases/download/channel-stable/install.sh
#     curl -O https://github.com/Omakidx/hash-xcreen/releases/download/channel-stable/install.sh.minisig
#     minisign -Vm install.sh -P <the public key line of current.pub>
#     sudo sh install.sh --pair ...
#
# It reads no environment variable of its own (curl honours http_proxy / https_proxy / the
# `*_proxy` family by itself). Everything it needs is fixed below. The whole script is wrapped in
# `main "$@"` on its last line, so a download cut short never runs half a script.
#
# Options consumed here (everything else is passed on to `hx-agent install` unchanged):
#   --channel stable|beta     release channel (default stable); also forwarded
#   --release-dir <abs dir>   use manifest-x86_64.json, its .minisig and the tarball from this
#                             directory instead of downloading (still fully verified)
#   --progress text|json      json: JSON Lines stage events on stdout, forwarded as --json
#   --allow-old-release       accept a manifest older than 90 days (refused by default: it
#                             may be a replay of an old, superseded release)
#   -h, --help
#
# Exit codes (hx-agent install shares them): 0 ok, 1 failed, 2 usage, 7 not root,
# 9 preflight failed (nothing changed), 10 verification failed, 11 another install is running.
#
# ---------------------------------------------------------------------------------------------
# Signature check (design D2). A minisign signature file has four LF-terminated lines:
#     untrusted comment: <text>
#     base64( "ED" | key id (8) | Ed25519 signature (64) )      <- "ED" = prehashed
#     trusted comment: <printable ASCII>
#     base64( Ed25519 signature (64) over  signature(64) | trusted comment bytes )
# and the first signature is over BLAKE2b-512(file). openssl does both: `dgst -blake2b512` and
# `pkeyutl -verify -rawin` (Ed25519 needs -rawin; one-shot; the input must be a regular file).
# Accepted only when: the algorithm is exactly "ED" (the legacy "Ed" is refused, as privd does),
# the key id equals the id of an embedded provisioned key, both signatures verify, the file has
# LF line endings only and the trusted comment is printable ASCII.
#
# Facts checked on 2026-11-21 (see the report of the 1E WS-3 work):
#   - openssl-pkeyutl(1) of the OpenSSL 3.0 manual documents -rawin and says it is required for
#     EdDSA: https://docs.openssl.org/3.0/man1/openssl-pkeyutl/ ; it was run here on 3.0.13.
#   - Supported hosts ship OpenSSL >= 3.0: Ubuntu 24.04 (3.0.13), Debian 12 (3.0.x),
#     Debian 13 and Ubuntu 26.04 (3.5.x, from memory). The KAT self-test below proves at run time
#     that the local openssl really does BLAKE2b-512 and raw Ed25519 verification.
# ---------------------------------------------------------------------------------------------

# The release signing keys: the base64 key line of release-keys/current.pub and next.pub, or
# UNPROVISIONED. apps/hx-agent/tests/installer_keys.rs keeps these equal to those files, and the
# release gate (release/gate.sh) refuses a release while either is UNPROVISIONED.
KEY_CURRENT='UNPROVISIONED'
KEY_NEXT='UNPROVISIONED'

# Fixed locations. Assigned unconditionally, so the environment cannot influence them (a shell
# imports every environment variable as a shell variable). Tests override them after sourcing.
BASE_URL='https://github.com/Omakidx/hash-xcreen/releases/download'
LOCK_FILE='/run/hx-install.lock'
BOOT_BASE='/var/lib'
AGENT_CURRENT='/usr/lib/hx/current/hx-agent'
OS_RELEASE='/etc/os-release'
SYSTEMD_DIR='/run/systemd/system'
EXPECT_UID=0
MAX_MANIFEST=1048576
MAX_ARTIFACT=268435456

CHANNEL='stable'
PROGRESS='text'
RELEASE_DIR=''
ALLOW_OLD=0
BOOT=''
VERR=''

# --- KAT begin (generated by apps/hx-agent/tests/installer_sh.rs; do not edit by hand) ---
KAT_KEY='RWTrri0V6lbx8tqeAVqceeecd60xN1xDcNIrYwFihPZKuUV3ysD6Z3e6'
KAT_SIG='untrusted comment: hx installer known-answer test
RUTrri0V6lbx8hc+pPKYZCBJOlp6eYzGWnRz6fhdxVBFFnvgLdXmBuZ5lRkpQrWgF6atUVePnIi6s91lJtUxCmip+uNgZDXgiwg=
trusted comment: hx-manifest v0.0.0 channel=stable arch=x86_64
9POWtg/hcEWNI+LD6KAB3NQf3cHsLZ4pLmyZx9jik4xNjiH3ILGeNghqhQwiaOrt+g1XDypvEbjmSAP2otVUDQ==
'
# --- KAT end ---
KAT_MSG='hx installer known-answer test'

# ----- output --------------------------------------------------------------------------------

err() { printf 'hx install: %s\n' "$*" >&2; }
note() { printf 'hx install: %s\n' "$*" >&2; }

# JSON Lines progress. Constant strings only: nothing attacker-controlled is ever interpolated.
json_stage() { # id state
    if [ "$PROGRESS" = json ]; then
        printf '{"v":1,"t":"stage","id":"%s","state":"%s"}\n' "$1" "$2"
    fi
    return 0
}

# die <exit> <stage-id> <code> <constant message> : the message must hold no quote or backslash.
die() {
    err "$4"
    if [ "$PROGRESS" = json ]; then
        printf '{"v":1,"t":"stage","id":"%s","state":"fail"}\n' "$2"
        printf '{"v":1,"t":"result","ok":false,"exit":%s,"stage":"%s","code":"%s","message":"%s","retryable":false}\n' "$1" "$2" "$3" "$4"
    fi
    exit "$1"
}

cleanup() {
    if [ -n "$BOOT" ] && [ -d "$BOOT" ]; then
        rm -rf "$BOOT"
    fi
}

# ----- minisign verification -----------------------------------------------------------------

# b64_file <b64 line> <out file> <expected byte count>: strict base64 (canonical: re-encoding must
# give the same line back), exactly <n> bytes.
b64_file() {
    printf '%s' "$1" | base64 -d >"$2" 2>/dev/null || return 1
    [ "$(wc -c <"$2")" -eq "$3" ] || return 1
    [ "$(base64 <"$2" | tr -d '\n')" = "$1" ] || return 1
    return 0
}

hex_of() { # file skip count
    dd if="$1" bs=1 skip="$2" count="$3" 2>/dev/null | od -An -v -tx1 | tr -d ' \n'
}

# verify_with <msg file> <minisig file> <key1> <key2>
# Returns 0 when valid; 1 not valid (VERR says why); 2 when a provisioned key is malformed;
# 3 when no key is provisioned.
verify_with() {
    _msg=$1 _sig=$2 _k1=$3 _k2=$4
    # TMPDIR is the caller's: a scratch directory is only ever made under /tmp (mktemp -d is 0700)
    _t=$(TMPDIR=/tmp mktemp -d) || {
        VERR='cannot create a temporary directory'
        return 1
    }
    _verify_in "$_t" "$_msg" "$_sig" "$_k1" "$_k2"
    _rc=$?
    rm -rf "$_t"
    return "$_rc"
}

_verify_in() {
    _d=$1 _msg=$2 _sig=$3
    VERR=''
    # 1. the file shape: exactly four LF-terminated lines, no CR, no NUL, small
    [ -f "$_sig" ] || {
        VERR='the signature file is missing'
        return 1
    }
    [ "$(wc -c <"$_sig")" -le 2048 ] || {
        VERR='the signature file is too large'
        return 1
    }
    [ "$(wc -l <"$_sig")" -eq 4 ] && [ "$(sed -n '$=' "$_sig")" = 4 ] || {
        VERR='the signature file does not have exactly four lines'
        return 1
    }
    [ "$(LC_ALL=C tr -d '\r\000' <"$_sig" | wc -c)" -eq "$(wc -c <"$_sig")" ] || {
        VERR='the signature file has CR or NUL bytes (LF line endings only)'
        return 1
    }
    _l1=$(sed -n 1p "$_sig")
    _l2=$(sed -n 2p "$_sig")
    _l3=$(sed -n 3p "$_sig")
    _l4=$(sed -n 4p "$_sig")
    case $_l1 in 'untrusted comment:'*) ;; *)
        VERR='the signature file is malformed (untrusted comment)'
        return 1
        ;;
    esac
    case $_l3 in 'trusted comment: '*) ;; *)
        VERR='the signature file is malformed (trusted comment)'
        return 1
        ;;
    esac
    _tc=${_l3#trusted comment: }
    if printf '%s' "$_tc" | LC_ALL=C grep -q '[^ -~]'; then
        VERR='the trusted comment is not printable ASCII'
        return 1
    fi
    # 2. the signature: 74 bytes, algorithm exactly "ED", key id, raw signature
    b64_file "$_l2" "$_d/sig1" 74 || {
        VERR='the signature is not 74 bytes of canonical base64'
        return 1
    }
    _alg=$(dd if="$_d/sig1" bs=1 count=2 2>/dev/null)
    if [ "$_alg" = Ed ]; then
        VERR='legacy (non-prehashed) signatures are refused'
        return 1
    fi
    [ "$_alg" = ED ] || {
        VERR='unknown signature algorithm'
        return 1
    }
    _sigid=$(hex_of "$_d/sig1" 2 8)
    dd if="$_d/sig1" of="$_d/sig" bs=1 skip=10 count=64 2>/dev/null
    b64_file "$_l4" "$_d/gsig" 64 || {
        VERR='the global signature is not 64 bytes of canonical base64'
        return 1
    }
    # 3. which embedded key (the unprovisioned ones are skipped)
    _found=0
    for _k in "$4" "$5"; do
        [ -n "$_k" ] || continue
        [ "$_k" = UNPROVISIONED ] && continue
        _found=1
        b64_file "$_k" "$_d/pk" 42 || {
            VERR='an embedded release key is malformed'
            return 2
        }
        [ "$(dd if="$_d/pk" bs=1 count=2 2>/dev/null)" = Ed ] || {
            VERR='an embedded release key is malformed'
            return 2
        }
        [ "$(hex_of "$_d/pk" 2 8)" = "$_sigid" ] || continue
        # key id matches: build the SPKI of the raw Ed25519 key and verify both signatures
        dd if="$_d/pk" of="$_d/pkraw" bs=1 skip=10 count=32 2>/dev/null
        {
            printf '\060\052\060\005\006\003\053\145\160\003\041\000'
            cat "$_d/pkraw"
        } >"$_d/spki.der"
        openssl dgst -blake2b512 -binary "$_msg" >"$_d/hash" 2>/dev/null || {
            VERR='openssl cannot compute BLAKE2b-512'
            return 1
        }
        openssl pkeyutl -verify -pubin -inkey "$_d/spki.der" -keyform DER -rawin \
            -in "$_d/hash" -sigfile "$_d/sig" >/dev/null 2>&1 || {
            VERR='the signature does not verify'
            return 1
        }
        {
            cat "$_d/sig"
            printf '%s' "$_tc"
        } >"$_d/global.msg"
        openssl pkeyutl -verify -pubin -inkey "$_d/spki.der" -keyform DER -rawin \
            -in "$_d/global.msg" -sigfile "$_d/gsig" >/dev/null 2>&1 || {
            VERR='the trusted comment does not verify'
            return 1
        }
        return 0
    done
    if [ "$_found" -eq 0 ]; then
        VERR='this installer embeds no release signing key'
        return 3
    fi
    VERR='the signature was made by an unknown key'
    return 1
}

# verify_signature <file> <minisig file>: against the embedded KEY_CURRENT and KEY_NEXT. This is
# the function the release job calls (sourced with --hx-lib) on the signature it just made.
verify_signature() {
    verify_with "$1" "$2" "$KEY_CURRENT" "$KEY_NEXT"
}

# The known-answer self-test: a valid vector must pass, a tampered one must fail for the right
# reason. Run before any signature is trusted.
selftest() {
    _s=$(TMPDIR=/tmp mktemp -d) || return 1
    printf '%s\n' "$KAT_MSG" >"$_s/msg"
    printf '%s\n' "${KAT_MSG}x" >"$_s/msg.bad"
    printf '%s' "$KAT_SIG" >"$_s/sig"
    _ok=0
    if verify_with "$_s/msg" "$_s/sig" "$KAT_KEY" UNPROVISIONED; then
        verify_with "$_s/msg.bad" "$_s/sig" "$KAT_KEY" UNPROVISIONED
        [ $? -eq 1 ] && [ "$VERR" = 'the signature does not verify' ] && _ok=1
    fi
    rm -rf "$_s"
    [ "$_ok" -eq 1 ]
}

# ----- preflight -----------------------------------------------------------------------------

is_root() { [ "$(id -u)" = 0 ]; }

os_field() {
    sed -n "s/^$1=//p" "$OS_RELEASE" 2>/dev/null | tail -n 1 | tr -d "\"'"
}

need() { # tool
    command -v "$1" >/dev/null 2>&1 || {
        err "required tool not found: $1"
        return 1
    }
}

check_tools() {
    _missing=0
    for _t in "$@"; do
        need "$_t" || _missing=1
    done
    [ "$_missing" -eq 0 ]
}

openssl_major() {
    openssl version 2>/dev/null | sed -n 's/^OpenSSL \([0-9][0-9]*\)\..*/\1/p'
}

usage() {
    cat <<'EOF'
usage: install.sh [--channel stable|beta] [--release-dir DIR] [--progress text|json]
                  [--allow-old-release] [OPTIONS]

Downloads the signed hash-xcreen release, verifies it and runs `hx-agent install`.
Run as root (for example `curl -fsSL <url>/install.sh | sudo sh -s -- --pair`).
Every other option is passed on to `hx-agent install`; see `hx-agent install --help`.
EOF
}

# ----- manifest ------------------------------------------------------------------------------

VER_RE='[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(-(alpha|beta|rc)\.[0-9]{1,4})?'

# mf <field> : the value of a field of the (already validated, canonical) manifest in $MANIFEST.
mf() {
    sed -n "s/^.*\"$1\":\"\{0,1\}\([^\",}]*\)\"\{0,1\}[,}].*\$/\1/p" "$MANIFEST"
}

# manifest_check <file> <channel> <arch>: validates the canonical form (C6) and the fields; sets
# M_VERSION M_SIZE M_SHA M_ARTIFACT M_TS. Returns 1 with VERR set.
manifest_check() {
    MANIFEST=$1
    [ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] || {
        VERR='the manifest is missing'
        return 1
    }
    [ "$(wc -l <"$MANIFEST")" -eq 1 ] && [ "$(sed -n '$=' "$MANIFEST")" = 1 ] || {
        VERR='the manifest is not exactly one line'
        return 1
    }
    LC_ALL=C grep -Eq '^\{"schema":1,"channel":"(stable|beta)","version":"'"$VER_RE"'","arch":"x86_64","artifact":"hx-'"$VER_RE"'-x86_64\.tar\.gz","size":(0|[1-9][0-9]{0,8}),"sha256":"[0-9a-f]{64}","timestamp":(0|[1-9][0-9]{0,11})(,"min_previous":"'"$VER_RE"'")?\}$' "$MANIFEST" || {
        VERR='the manifest is not in the canonical form'
        return 1
    }
    M_CHANNEL=$(mf channel)
    M_VERSION=$(mf version)
    M_ARCH=$(mf arch)
    M_ARTIFACT=$(mf artifact)
    M_SIZE=$(mf size)
    M_SHA=$(mf sha256)
    M_TS=$(mf timestamp)
    [ "$M_CHANNEL" = "$2" ] || {
        VERR='the manifest is for another channel'
        return 1
    }
    [ "$M_ARCH" = "$3" ] || {
        VERR='the manifest is for another architecture'
        return 1
    }
    [ "$M_ARTIFACT" = "hx-$M_VERSION-x86_64.tar.gz" ] || {
        VERR='the manifest names an unexpected artifact'
        return 1
    }
    [ "$M_SIZE" -ge 1 ] && [ "$M_SIZE" -le "$MAX_ARTIFACT" ] || {
        VERR='the manifest announces an unacceptable size'
        return 1
    }
    _now=$(date +%s)
    [ "$M_TS" -le $((_now + 86400)) ] || {
        VERR='the manifest is dated in the future'
        return 1
    }
    if [ "$M_TS" -lt $((_now - 90 * 86400)) ]; then
        if [ "$ALLOW_OLD" -ne 1 ]; then
            VERR='the release manifest is older than 90 days (--allow-old-release installs it anyway)'
            return 1
        fi
        note 'warning: the release manifest is older than 90 days (--allow-old-release given)'
    fi
    return 0
}

# insecure <path>: true when the group-write or the other-write bit is set, or the owner is not
# EXPECT_UID (a 0775 or 0757 mode is refused, not just 0777).
insecure() {
    [ -n "$(find "$1" -maxdepth 0 \( -perm -0020 -o -perm -0002 -o ! -user "$EXPECT_UID" \) 2>/dev/null)" ]
}

# parents_secure <absolute path>: every ancestor directory of <path>, up to /, is owned by root (or
# EXPECT_UID, which is 0 on a real host) and not group- or other-writable. A sticky directory (/tmp)
# may be writable: nobody but the owner of an entry can rename or replace it. A symlink among the
# ancestors must itself be owned that way, and the fully resolved path (pwd -P) is checked as well,
# so nobody who is not root can swap a component of the path between the checks and the open.
_anc_ok() {
    if [ -L "$1" ]; then
        [ -z "$(find "$1" -maxdepth 0 ! -user 0 ! -user "$EXPECT_UID" 2>/dev/null)" ] || return 1
        return 0
    fi
    [ -d "$1" ] || return 1
    [ -z "$(find "$1" -maxdepth 0 \( \( ! -user 0 ! -user "$EXPECT_UID" \) -o \
        \( \( -perm -0020 -o -perm -0002 \) ! -perm -1000 \) \) 2>/dev/null)" ]
}
_anc_chain() { # <path>: every proper ancestor of it
    _c=$1
    while :; do
        _c=$(dirname "$_c")
        _anc_ok "$_c" || return 1
        [ "$_c" = / ] && return 0
    done
}
parents_secure() {
    _anc_chain "$1" || return 1
    _ph=$(cd "$1" 2>/dev/null && pwd -P) || return 1
    [ "$_ph" = "$1" ] || { _anc_ok "$_ph" && _anc_chain "$_ph"; }
}

# copy_capped <src> <dst> <max-bytes>: a regular file (not a FIFO, device or link; refused BEFORE it
# is opened), owned by EXPECT_UID and not group- or other-writable, of at most <max-bytes>; the copy
# itself is bounded too, so nothing can hang or fill /run.
copy_capped() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    insecure "$1" && return 1
    [ "$(wc -c <"$1")" -le "$3" ] || return 1
    head -c $(($3 + 1)) <"$1" >"$2" || return 1
    [ "$(wc -c <"$2")" -le "$3" ]
}

# fetch <url> <dest> <max-bytes>. `-q` first: ~/.curlrc is ignored. curl before 8.4 (Debian 12 has
# 7.88.1) does not enforce --max-filesize without a Content-Length, so the cap is also enforced
# without curl: the subshell's file-size limit (ulimit -f, 512-byte blocks) stops a runaway write,
# and the size is checked afterwards.
fetch() {
    _blocks=$((($3 + 511) / 512 + 1))
    (
        ulimit -f "$_blocks" || exit 1
        curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 --max-redirs 5 \
            --connect-timeout 20 --max-time 1800 --max-filesize "$3" \
            -fsSL -o "$2" "$1" </dev/null
    ) || {
        rm -f "$2"
        return 1
    }
    [ -f "$2" ] && [ "$(wc -c <"$2")" -le "$3" ] || {
        rm -f "$2"
        return 1
    }
}

# ----- main ----------------------------------------------------------------------------------

main() {
    # Test mode: `set -- --hx-lib; . ./install.sh` defines the functions and returns.
    if [ "${1:-}" = --hx-lib ]; then
        return 0
    fi

    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    export PATH
    LC_ALL=C
    export LC_ALL
    # an operator-controlled TMPDIR must not steer any scratch file (mktemp honours it)
    unset TMPDIR
    IFS='
'
    umask 077
    set -u

    # Options: consume ours, keep the rest in order.
    _n=$#
    _i=0
    while [ "$_i" -lt "$_n" ]; do
        _a=$1
        shift
        _i=$((_i + 1))
        case $_a in
            --channel | --release-dir | --progress)
                if [ "$_i" -ge "$_n" ]; then
                    err "$_a needs a value"
                    exit 2
                fi
                _v=$1
                shift
                _i=$((_i + 1))
                case $_a in
                    --channel) CHANNEL=$_v ;;
                    --release-dir) RELEASE_DIR=$_v ;;
                    --progress) PROGRESS=$_v ;;
                esac
                ;;
            --channel=*) CHANNEL=${_a#--channel=} ;;
            --release-dir=*) RELEASE_DIR=${_a#--release-dir=} ;;
            --progress=*) PROGRESS=${_a#--progress=} ;;
            --allow-old-release) ALLOW_OLD=1 ;;
            -h | --help)
                usage
                exit 0
                ;;
            *) set -- "$@" "$_a" ;;
        esac
    done
    case $CHANNEL in stable | beta) ;; *)
        err "--channel must be stable or beta"
        exit 2
        ;;
    esac
    case $PROGRESS in text | json) ;; *)
        err "--progress must be text or json"
        exit 2
        ;;
    esac
    if [ -n "$RELEASE_DIR" ]; then
        case $RELEASE_DIR in /*) ;; *)
            err "--release-dir must be an absolute path"
            exit 2
            ;;
        esac
    fi
    set -- --channel "$CHANNEL" "$@"

    trap cleanup EXIT
    trap 'exit 1' HUP INT TERM

    # ---- bootstrap-preflight ----
    json_stage bootstrap-preflight start
    is_root || die 7 bootstrap-preflight NOT_ROOT 'this installer must run as root (use sudo)'
    [ "$(uname -m)" = x86_64 ] ||
        die 9 bootstrap-preflight PREFLIGHT 'only x86_64 hosts are supported'
    [ -d "$SYSTEMD_DIR" ] ||
        die 9 bootstrap-preflight PREFLIGHT 'systemd is required (it is not the init system here)'
    _id=$(os_field ID)
    _ver=$(os_field VERSION_ID)
    case "$_id:$_ver" in
        ubuntu:24.04 | ubuntu:26.04 | debian:12 | debian:13) ;;
        ubuntu:22.04)
            die 9 bootstrap-preflight PREFLIGHT 'Ubuntu 22.04 is not supported (systemd 249 has no systemd-creds); supported: Ubuntu 24.04 and 26.04, Debian 12 and 13'
            ;;
        *)
            note "detected: ID=$_id VERSION_ID=$_ver"
            die 9 bootstrap-preflight PREFLIGHT 'unsupported OS; supported: Ubuntu 24.04 and 26.04, Debian 12 and 13'
            ;;
    esac
    check_tools flock id mktemp ||
        die 9 bootstrap-preflight PREFLIGHT 'a required tool is missing'
    json_stage bootstrap-preflight 'done'

    # ---- the lock, held across the exec (C4) ----
    if [ -L "$LOCK_FILE" ] || ! (: >>"$LOCK_FILE") 2>/dev/null; then
        die 9 bootstrap-preflight PREFLIGHT 'cannot open the install lock file'
    fi
    exec 9>>"$LOCK_FILE"
    flock -n 9 || die 11 bootstrap-preflight LOCKED 'another install or uninstall is running'

    # ---- an installed agent is never replaced here: updates go through privd ----
    if [ -x "$AGENT_CURRENT" ]; then
        note 'an agent is already installed: resuming with it (no download)'
        [ -z "$RELEASE_DIR" ] || note 'ignoring --release-dir: the installed release is used'
        if [ "$PROGRESS" = json ]; then
            set -- --json install --lock-fd 9 "$@"
        else
            set -- install --lock-fd 9 "$@"
        fi
        exec "$AGENT_CURRENT" "$@"
    fi

    # ---- the verification tools and the self-test ----
    check_tools sed grep tr wc dd od base64 cat cut cp head date openssl sha256sum tar gzip find ||
        die 9 bootstrap-preflight PREFLIGHT 'a required tool is missing'
    [ -n "$RELEASE_DIR" ] || check_tools curl ||
        die 9 bootstrap-preflight PREFLIGHT 'curl is required'
    _major=$(openssl_major)
    [ -n "$_major" ] && [ "$_major" -ge 3 ] ||
        die 9 bootstrap-preflight PREFLIGHT 'OpenSSL 3.0 or newer is required'
    selftest ||
        die 9 bootstrap-preflight PREFLIGHT 'the signature self-test failed; this host cannot verify the release'
    [ "$KEY_CURRENT" != UNPROVISIONED ] || [ "$KEY_NEXT" != UNPROVISIONED ] ||
        die 9 bootstrap-preflight PREFLIGHT 'this installer embeds no release signing key; it is not a release build'

    BOOT=$(mktemp -d "$BOOT_BASE/hx-bootstrap.XXXXXX") ||
        die 1 bootstrap-download IO 'cannot create the bootstrap directory'

    # ---- bootstrap-download: the manifest and its signature ----
    json_stage bootstrap-download start
    _arch=x86_64
    if [ -n "$RELEASE_DIR" ]; then
        [ -d "$RELEASE_DIR" ] && [ ! -L "$RELEASE_DIR" ] ||
            die 9 bootstrap-preflight PREFLIGHT 'the release directory is not a directory'
        ! insecure "$RELEASE_DIR" ||
            die 9 bootstrap-preflight PREFLIGHT 'the release directory must be owned by root and not writable by group or others'
        parents_secure "$RELEASE_DIR" ||
            die 9 bootstrap-preflight PREFLIGHT 'every parent directory of the release directory must be owned by root and not writable by group or others'
        for _f in manifest-x86_64.json manifest-x86_64.json.minisig; do
            [ -f "$RELEASE_DIR/$_f" ] && [ ! -L "$RELEASE_DIR/$_f" ] ||
                die 1 bootstrap-download IO 'the release directory lacks the manifest or its signature'
        done
        copy_capped "$RELEASE_DIR/manifest-x86_64.json" "$BOOT/manifest.json" "$MAX_MANIFEST" &&
            copy_capped "$RELEASE_DIR/manifest-x86_64.json.minisig" "$BOOT/manifest.json.minisig" 4096 ||
            die 9 bootstrap-preflight PREFLIGHT 'a manifest file of the release directory is not an acceptable regular file'
    else
        _base="$BASE_URL/channel-$CHANNEL"
        fetch "$_base/manifest-x86_64.json" "$BOOT/manifest.json" "$MAX_MANIFEST" ||
            die 1 bootstrap-download DOWNLOAD 'cannot download the release manifest'
        fetch "$_base/manifest-x86_64.json.minisig" "$BOOT/manifest.json.minisig" 4096 ||
            die 1 bootstrap-download DOWNLOAD 'cannot download the manifest signature'
    fi
    json_stage bootstrap-download 'done'

    # ---- bootstrap-verify ----
    json_stage bootstrap-verify start
    verify_signature "$BOOT/manifest.json" "$BOOT/manifest.json.minisig" || {
        note "$VERR"
        die 10 bootstrap-verify VERIFY 'the release manifest signature is not valid'
    }
    manifest_check "$BOOT/manifest.json" "$CHANNEL" "$_arch" || {
        note "$VERR"
        die 10 bootstrap-verify VERIFY 'the signed release manifest was refused'
    }
    note "release $M_VERSION ($CHANNEL)"

    if [ -n "$RELEASE_DIR" ]; then
        [ -e "$RELEASE_DIR/$M_ARTIFACT" ] ||
            die 1 bootstrap-download IO 'the release directory lacks the release tarball'
        copy_capped "$RELEASE_DIR/$M_ARTIFACT" "$BOOT/artifact.tar.gz" "$M_SIZE" ||
            die 9 bootstrap-preflight PREFLIGHT 'the release tarball is not an acceptable regular file'
    else
        fetch "$BASE_URL/v$M_VERSION/$M_ARTIFACT" "$BOOT/artifact.tar.gz" "$M_SIZE" ||
            die 1 bootstrap-download DOWNLOAD 'cannot download the release tarball'
    fi
    [ "$(wc -c <"$BOOT/artifact.tar.gz")" -eq "$M_SIZE" ] ||
        die 10 bootstrap-verify VERIFY 'the release tarball has the wrong size'
    _got=$(sha256sum "$BOOT/artifact.tar.gz" | cut -d ' ' -f 1)
    [ "$_got" = "$M_SHA" ] ||
        die 10 bootstrap-verify VERIFY 'the release tarball digest does not match the manifest'

    # ---- extract ./hx-agent only ----
    tar -tzf "$BOOT/artifact.tar.gz" >"$BOOT/members" 2>/dev/null ||
        die 10 bootstrap-verify VERIFY 'the release tarball cannot be read'
    _member=''
    for _cand in hx-agent ./hx-agent; do
        if [ "$(grep -cx -- "$_cand" "$BOOT/members")" -eq 1 ]; then
            _member=$_cand
            break
        fi
    done
    [ -n "$_member" ] ||
        die 10 bootstrap-verify VERIFY 'the release tarball has no hx-agent'
    tar -xzf "$BOOT/artifact.tar.gz" -C "$BOOT" --no-same-owner --no-same-permissions -- "$_member" 2>/dev/null ||
        die 10 bootstrap-verify VERIFY 'cannot extract hx-agent'
    rm -f "$BOOT/members"
    [ -f "$BOOT/hx-agent" ] && [ ! -L "$BOOT/hx-agent" ] ||
        die 10 bootstrap-verify VERIFY 'hx-agent is not a regular file'
    chmod 0700 "$BOOT/hx-agent"
    json_stage bootstrap-verify 'done'

    # ---- hand off (C4): the lock stays held on fd 9 ----
    if [ "$PROGRESS" = json ]; then
        set -- --json install --bootstrap-dir "$BOOT" --lock-fd 9 "$@"
    else
        set -- install --bootstrap-dir "$BOOT" --lock-fd 9 "$@"
    fi
    trap - EXIT
    exec "$BOOT/hx-agent" "$@"
}

main "$@"
