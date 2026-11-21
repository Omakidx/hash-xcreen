#!/bin/bash
# Builds what every installer-vm cell needs, once, on an Ubuntu 24.04 runner:
#
#   tests/installer-vm/build-artifacts.sh <out-dir>
#
#   <out-dir>/release/   a TEST-KEYED release directory (install.sh, tarball, manifest, signature)
#                        around the real binaries, built with the test key and the test hooks
#   <out-dir>/client     the installer_vm_client test binary (pairing and PIN-login client)
#
# The keys are made for this run: the agent embeds the public one through the `test-release-key`
# feature (HX_TEST_RELEASE_PUBKEY), and `release-keys/*.pub` are never touched. The private keys
# stay in a temporary directory and are not part of the output.
#
# Features of the agent build: `test-release-key` (the test key), `install-test-hooks`
# (`--test-fail-after` for the failure-injection steps; `--test-allow-container` is not needed on a
# VM) and `privd-test-hooks` (harmless on a VM, whose sysctls are writable). NONE of them is in a
# release build, and the release gate (`release-build`) refuses them. `cargo build -p hx-agent
# --bins`, never `--workspace`.
#
# The hx-session package is real for ubuntu-24.04 (the runner's own distro, so dpkg-shlibdeps gives
# the right Depends); the packages for the other three distros are placeholders: the VM hosts need
# the tarball to carry one, but the desktop built by default is Ubuntu 24.04.
set -euo pipefail

out=${1:?usage: build-artifacts.sh <out-dir>}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$repo"

version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version *= *"\(.*\)"$/\1/p' Cargo.toml | head -n 1)
now=$(date +%s)

echo "==> test keys"
sh release/openssl-minisign.sh keygen "$work/keys/current"
sh release/openssl-minisign.sh keygen "$work/keys/next"
pubkey=$(cat "$work/keys/current/key.line")

echo "==> agent binaries (test key, test hooks)"
HX_TEST_RELEASE_PUBKEY="$pubkey" cargo build -p hx-agent --bins --release --locked \
    --features test-release-key,install-test-hooks,privd-test-hooks

echo "==> hx-session and hx-pwcheck"
cargo build --release --locked -p hx-session --bin hx-session -p hx-pwcheck --bin hx-pwcheck

mkdir -p "$work/bin" "$work/pkg"
for b in hx-privd hx-gatewayd hx-agent hx-update-fetcher hx-backup-worker hx-privd-rescue; do
    cp "target/release/$b" "$work/bin/$b"
done
cp target/release/hx-session target/release/hx-pwcheck "$work/pkg/"

echo "==> hx-session.deb (ubuntu-24.04) and placeholders"
for d in ubuntu-24.04 ubuntu-26.04 debian-12 debian-13; do
    mkdir -p "$work/session/$d"
    if [ "$d" = ubuntu-24.04 ]; then
        sh packaging/hx-session/build-deb.sh --version "$version" --distro "$d" --bin-dir "$work/pkg" \
            --out "$work/session/$d" --source-date-epoch "$now"
    else
        printf '!<arch>\nplaceholder %s\n' "$d" >"$work/session/$d/hx-session.deb"
    fi
done

echo "==> test-keyed release directory"
rm -rf "$out/release"
sh release/make-test-release.sh --out "$out/release" --bin-dir "$work/bin" --session-dir "$work/session" \
    --key-dir "$work/keys" --timestamp "$now"
[ "$(cat "$out/release/test-release.pubkey")" = "$pubkey" ] || { echo "the release key is not the one the agent embeds" >&2; exit 1; }

echo "==> client test binary"
exe=$(cargo test -p hx-agent --test installer_vm_client --no-run --locked --message-format=json |
    jq -r 'select(.reason=="compiler-artifact" and .profile.test==true and .target.name=="installer_vm_client") | .executable' | tail -n 1)
[ -x "$exe" ] || { echo "cannot find the client test binary" >&2; exit 1; }
cp "$exe" "$out/client"

echo "artifacts in $out: $(ls "$out" | tr '\n' ' ')"
