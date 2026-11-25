#!/bin/sh
# Test of checks 6b (container/image digests) and 8 (job isolation) of release/gate.sh, on a
# synthetic tree, in dry-run mode (which skips the provisioned-key checks):
#
#   sh release/tests/gate-isolation.sh
set -eu
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

tree="$tmp/tree"
mkdir -p "$tree/release" "$tree/installer" "$tree/apps/hx-agent/src/privd/update" "$tree/.github/workflows"
cp "$root/release/gate.sh" "$tree/release/"
cp "$root/installer/install.sh" "$tree/installer/"
cp "$root/Cargo.toml" "$tree/"
cp "$root/apps/hx-agent/Cargo.toml" "$tree/apps/hx-agent/"
cp "$root/apps/hx-agent/src/privd/update/keys.rs" "$tree/apps/hx-agent/src/privd/update/"
wfd="$tree/.github/workflows"
cp "$root/.github/workflows/release.yml" "$wfd/"

fails=0
expect() { # <name> <exit status> <stderr must contain, or ''>
    name=$1 want=$2 needle=$3
    rc=0
    sh "$tree/release/gate.sh" --dry-run >"$tmp/out" 2>"$tmp/err" || rc=$?
    if [ "$rc" != "$want" ]; then
        echo "FAIL $name: exit $rc, wanted $want"
        cat "$tmp/err"
        fails=$((fails + 1))
    elif [ -n "$needle" ] && ! grep -q -- "$needle" "$tmp/err"; then
        echo "FAIL $name: stderr lacks '$needle'"
        cat "$tmp/err"
        fails=$((fails + 1))
    else
        echo "ok   $name"
    fi
}
sha=11d5960a326750d5838078e36cf38b85af677262
dig=887a259a5a534f3c4f36cb02dca341673c6089431057242cdc931e9f133147e9
# wfj <file> <job header lines> <step lines>: one job named j
wfj() { printf 'permissions:\n  contents: read\njobs:\n  j:\n%s\n    steps:\n%s\n' "$2" "$3" >"$wfd/$1"; }

expect "the real workflows pass" 0 ''

# ---- 8: a job with an environment ----
wfj other.yml "    environment: signing" "      - run: sudo apt-get install -y minisign
      - run: minisign -S -m file"
expect "an environment job that only installs minisign and signs passes" 0 ''

wfj other.yml "    environment: signing" "      - run: cargo build --release"
expect "an environment job running cargo blocks" 1 'job j (environment) runs build or workspace code'

wfj other.yml "    environment: signing" "      - run: rustup toolchain install"
expect "an environment job running rustup blocks" 1 'job j (environment) runs build or workspace code'

wfj other.yml "    environment: signing" "      - run: signed/hx-imagectl verify"
expect "an environment job running a signed/hx-* binary blocks" 1 'runs build or workspace code'

wfj other.yml "    environment: signing" "      - run: target/release/hx-imagectl manifest"
expect "an environment job running a workspace-built binary blocks" 1 'runs build or workspace code'

wfj other.yml "    environment: signing" "      - uses: actions/checkout@$sha # v4"
expect "an environment job checking out the workspace blocks" 1 'checks the workspace out'

wfj other.yml "    environment: signing" "      - run: sh release/manifest.sh --out m"
expect "an environment job running a workspace script blocks" 1 'runs a workspace script'

wfj other.yml "    environment: signing" "      # cargo build is NOT run here
      - run: echo \"\$HOME/.cargo/bin\" >/dev/null"
expect "a comment or a .cargo path in an environment job is ignored" 0 ''

# ---- 8: a job with contents: write ----
wfj other.yml "    permissions:
      contents: write" "      - run: gh release upload t f
      - run: sha256sum -c sums"
expect "a contents: write job using only gh and coreutils passes" 0 ''

wfj other.yml "    permissions:
      contents: write" "      - run: |
          bin=\"\$PWD/signed/hx-imagectl\"
          \"\$bin\" verify --manifest m
          gh release upload channel-stable install.sh --clobber"
expect "a contents: write job running a signed/hx-* binary blocks (the old images.yml publish job)" 1 'contents: write) runs build or workspace code'

wfj other.yml "    permissions:
      contents: write" "      - run: cargo run -p tool"
expect "a contents: write job running cargo blocks" 1 'contents: write) runs build or workspace code'

wfj other.yml "    permissions:
      contents: read" "      - run: cargo build
      - run: target/release/hx-imagectl verify"
expect "a read-only job may run cargo and workspace binaries" 0 ''

printf 'permissions:\n  contents: write\njobs:\n  j:\n    steps:\n      - run: echo hi\n' >"$wfd/other.yml"
expect "a workflow-level contents: write blocks" 1 'workflow-level permissions grant contents: write'

# ---- 6b: container and image digests ----
rm -f "$wfd/other.yml"
d64=$dig$dig
d64=$(printf '%s' "$d64" | cut -c1-64)
wfj other.yml "    container: ubuntu:24.04" "      - run: true"
expect "a tag-pinned container blocks" 1 'not pinned by @sha256 digest: ubuntu:24.04'

wfj other.yml "    container: ubuntu:24.04@sha256:$d64" "      - run: true"
expect "a digest-pinned container passes" 0 ''

wfj other.yml "    container: \${{ matrix.image }}
    strategy:
      matrix:
        include:
          - { distro: a, image: \"debian:12\" }" "      - run: true"
expect "a tag-pinned matrix image blocks" 1 'debian:12'

wfj other.yml "    container: \${{ matrix.image }}
    strategy:
      matrix:
        include:
          - { distro: a, image: \"debian:12@sha256:$d64\", known: false }" "      - run: true"
expect "a digest-pinned matrix image passes" 0 ''

wfj other.yml "    strategy:
      matrix:
        image: [\"ubuntu:24.04@sha256:$d64\", \"debian:13\"]" "      - run: true"
expect "one unpinned element of an image list blocks" 1 'debian:13'

wfj other.yml "    strategy:
      matrix:
        image: [build, prebuilt]" "      - run: true"
expect "a matrix key named image with plain words is not a registry reference" 0 ''

if [ "$fails" = 0 ]; then
    echo "gate isolation tests: PASSED"
else
    echo "gate isolation tests: $fails FAILED" >&2
    exit 1
fi
