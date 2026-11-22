#!/bin/bash
# Builds what every installer-vm cell needs, once, on an Ubuntu 24.04 runner:
#
#   tests/installer-vm/build-artifacts.sh <out-dir>
#
#   <out-dir>/release/   a TEST-KEYED release directory (install.sh, tarball, manifest, signature)
#                        around the real binaries, built with the test key and the test hooks
#   <out-dir>/client     the installer_vm_client test binary (pairing and PIN-login client)
#   <out-dir>/img/       a TEST-SIGNED prebuilt desktop image for the `prebuilt` cells: the image
#                        `hx-image-ubuntu-24.04-xfce-basic-<build_id>.img`, `images-manifest-x86_64.json`
#                        and its `.minisig` (design 1D, section 6). Skipped with HX_SKIP_IMAGE=1.
#
# The keys are made for this run: the agent embeds the public ones through the `test-release-key`
# and `test-image-key` features (HX_TEST_RELEASE_PUBKEY, HX_TEST_IMAGE_PUBKEY), and
# `release-keys/*.pub` and `image-keys/*.pub` are never touched. The private keys stay in a
# temporary directory and are not part of the output. The IMAGE key is a key pair of its own, as in
# production (a leaked image key must never be able to sign a release).
#
# Features of the agent build: `test-release-key` (the test key), `test-image-key` (the test image
# key), `install-test-hooks` (`--test-fail-after` for the failure-injection steps;
# `--test-allow-container` is not needed on a VM) and `privd-test-hooks` (harmless on a VM, whose
# sysctls are writable). NONE of them is in a release build, and the release gate
# (`release-build`) refuses them. `cargo build -p hx-agent --bins`, never `--workspace`.
#
# The test image is built on THIS machine by `hx-imagectl build-image --recipe
# ubuntu-24.04-xfce-basic`, which needs root and a running Incus (the workflow sets up the same
# btrfs-backed Incus as images.yml before calling this script). The recipe does not depend on the
# host OS of a cell: `--distro` (default ubuntu-24.04) chooses it, so the one image serves all four
# host OSes. Its `recipe_digest` is the one of the agent built here, which is what privd matches.
# The manifest is built by `hx-imagectl manifest` and signed with the test image key and the exact
# trusted comment image CI writes (`hx-images-manifest schema=1 arch=x86_64 timestamp=<T>`).
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
sh release/openssl-minisign.sh keygen "$work/keys/image"
imgkey=$(cat "$work/keys/image/key.line")

echo "==> agent binaries (test keys, test hooks)"
HX_TEST_RELEASE_PUBKEY="$pubkey" HX_TEST_IMAGE_PUBKEY="$imgkey" cargo build -p hx-agent --bins --release --locked \
    --features test-release-key,test-image-key,install-test-hooks,privd-test-hooks

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

if [ "${HX_SKIP_IMAGE:-0}" = 1 ]; then
    echo "==> test image skipped (HX_SKIP_IMAGE=1): the prebuilt cells cannot run from this output"
else
    echo "==> hx-imagectl and the test image (ubuntu-24.04-xfce-basic)"
    command -v incus >/dev/null 2>&1 || { echo "build-artifacts.sh: the test image needs Incus on this machine (see images.yml); or set HX_SKIP_IMAGE=1" >&2; exit 1; }
    cargo build --release --locked -p hx-imagectl
    imagectl="$repo/target/release/hx-imagectl"
    as_root=''
    [ "$(id -u)" = 0 ] || as_root=sudo
    build_id="$(date -u +%Y%m%d).1"
    # --out must not exist or be empty; the tool needs root for Incus, so the files are chown'ed back.
    $as_root "$imagectl" build-image --recipe ubuntu-24.04-xfce-basic --prefix hxci \
        --build-id "$build_id" --out "$work/imgbuild" --pool-gib 40
    $as_root chown -R "$(id -u):$(id -g)" "$work/imgbuild"
    ls -l "$work/imgbuild"
    # One file only: a split image (`.p0`) exists for GitHub's release-asset limit, not for --image-file.
    set -- "$work"/imgbuild/hx-image-ubuntu-24.04-xfce-basic-*.img
    { [ $# = 1 ] && [ -f "$1" ]; } || { echo "expected exactly one image file, got: $*" >&2; ls "$work/imgbuild" >&2; exit 1; }
    image=$1
    [ ! -e "$image.p0" ] || { echo "the image was split into parts" >&2; exit 1; }
    t=$(date +%s)
    rm -rf "$out/img"
    mkdir -p "$out/img"
    "$imagectl" manifest --entries "$work/imgbuild" --timestamp "$t" --out "$out/img/images-manifest-x86_64.json"
    sh release/openssl-minisign.sh sign "$work/keys/image" "$out/img/images-manifest-x86_64.json" \
        "hx-images-manifest schema=1 arch=x86_64 timestamp=$t"
    mv "$image" "$out/img/"
    # What the agent will do, done here first: the manifest verifies with the test key, and the
    # image is the one it lists.
    "$imagectl" verify --manifest "$out/img/images-manifest-x86_64.json" \
        --sig "$out/img/images-manifest-x86_64.json.minisig" --pubkey "$work/keys/image/key.pub" \
        --image "$out/img/$(basename "$image")"
    ls -l "$out/img"
fi

echo "==> client test binary"
exe=$(cargo test -p hx-agent --test installer_vm_client --no-run --locked --message-format=json |
    jq -r 'select(.reason=="compiler-artifact" and .profile.test==true and .target.name=="installer_vm_client") | .executable' | tail -n 1)
[ -x "$exe" ] || { echo "cannot find the client test binary" >&2; exit 1; }
cp "$exe" "$out/client"

echo "artifacts in $out: $(ls "$out" | tr '\n' ' ')"
