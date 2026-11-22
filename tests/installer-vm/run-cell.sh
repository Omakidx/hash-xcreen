#!/bin/bash
# One cell of .github/workflows/installer-vm.yml: the real installer on a fresh KVM VM.
#
#   CELL_OS=ubuntu-24.04 CELL_IMAGE=build ART=/path/to/artifacts OUT=/path/to/out \
#       [CELL_VARIANT=none|ufw|docker-host|private] tests/installer-vm/run-cell.sh
#
#   CELL_OS       ubuntu-24.04 | ubuntu-26.04 | debian-12 | debian-13 (the VM's OS)
#   CELL_IMAGE    build    : the full install, every check below
#                 prebuilt : `--image prebuilt` must be refused cleanly (exit 6, nothing changed):
#                            privd answers UNIMPLEMENTED for the prebuilt path in this release
#   CELL_VARIANT  none         plain host
#                 ufw          ufw is active on the VM before the install (the port rule must open 443)
#                 docker-host  Docker runs on the VM, with a published port (DOCKER-USER, DNAT drop)
#                 private      install with --allow-private-networks (checklist item 5)
#   ART           holds `release/` (a test-keyed release directory made by
#                 tests/installer-vm/build-artifacts.sh) and `client` (the compiled
#                 installer_vm_client test binary)
#   OUT           receives the evidence: JSON Lines of every run, stage timings, logs
#
# Needs on the runner: Incus with KVM (see the workflow), jq, sudo. Nothing here is run on a
# developer machine's host: the VM is the only place the installer touches.
#
# Cell steps (build): launch the VM; install with failure injection and resume; the real install
# with secrets on stdin; units and credentials; pairing and PIN login from the runner over QUIC and
# WebSocket, and the first frame of the real desktop; the secrets canary; the host-ruleset checklist
# from inside the desktop; idempotence; a pending update whose privd fails (OnFailure rollback); a
# VM reboot; uninstall in both modes with an empty-leftovers check.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
: "${CELL_OS:?}" "${CELL_IMAGE:?}" "${ART:?}" "${OUT:?}"
variant=${CELL_VARIANT:-none}
mkdir -p "$OUT"
INCUS="sudo incus"
vm=hx1e-vm-$(echo "$CELL_OS" | tr -d '.-')
AGENT=/usr/lib/hx/current/hx-agent
CLIENT=$ART/client

step() { echo; echo "==> [$CELL_OS/$CELL_IMAGE/$variant] $*"; }
die() { echo "FAIL: $*" >&2; exit 1; }

case $CELL_OS in
ubuntu-24.04) image=ubuntu/24.04 ;;
ubuntu-26.04) image=ubuntu/26.04 ;;
debian-12) image=debian/12 ;;
debian-13) image=debian/13 ;;
*) die "unknown CELL_OS $CELL_OS" ;;
esac

# Debian 12 has no Incus in its main archive, so its build path needs the Zabbly repository, whose
# pinned key ships UNPROVISIONED until the maintainer adds it. Skip the cell visibly rather than
# fail it or hide a failure; it runs for real as soon as the key file holds a key.
if [ "$CELL_OS" = debian-12 ] && [ "$CELL_IMAGE" = build ] &&
    grep -q '^UNPROVISIONED' apps/hx-agent/src/install/zabbly-key.asc; then
    echo "::warning title=debian-12 build skipped::the Zabbly apt key (apps/hx-agent/src/install/zabbly-key.asc) is UNPROVISIONED; this cell needs it"
    exit 0
fi

vmx() { $INCUS exec "$vm" --force-noninteractive -- "$@"; }
vmsh() { $INCUS exec "$vm" --force-noninteractive -- sh -c "$1"; }
# The VM's address on its default-route interface. Not `incus list -c 4`: once the installer has
# made hxbr0 (and with a host Docker, docker0) the VM has several addresses, the CSV field is
# quoted and multi-line, and the first word is not a usable address.
vm_addr() { vmsh 'ip -4 -o addr show dev "$(ip route show default | awk "{print \$5; exit}")" | awk "{print \$4}" | cut -d/ -f1 | head -n 1'; }

cleanup() {
    $INCUS exec "$vm" -- journalctl -a --no-pager -n 400 >"$OUT/vm-journal.txt" 2>&1 || true
    $INCUS exec "$vm" -- cat /var/log/hx-install.log >"$OUT/hx-install.log" 2>&1 || true
    $INCUS exec "$vm" -- cat /var/lib/hx/install-state.json >"$OUT/install-state.json" 2>&1 || true
    $INCUS delete --force "$vm" >/dev/null 2>&1 || true
    rm -rf "$OUT/secrets"
}
trap cleanup EXIT

# ---- the VM ----
step "launch $image as a KVM VM"
$INCUS launch "images:$image" "$vm" --vm -c limits.cpu=3 -c limits.memory=10GiB \
    -c security.secureboot=false -d root,size=40GiB
for _ in $(seq 1 100); do $INCUS exec "$vm" -- true 2>/dev/null && break; sleep 3; done
$INCUS exec "$vm" -- true || die "the VM agent never came up"
for _ in $(seq 1 60); do
    s=$(vmsh 'systemctl is-system-running 2>&1' || true)
    [ "$s" = running ] || [ "$s" = degraded ] && break
    sleep 3
done
for _ in $(seq 1 40); do vmsh 'getent hosts deb.debian.org >/dev/null 2>&1 || getent hosts archive.ubuntu.com >/dev/null 2>&1' && break; sleep 3; done
vmsh 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq curl openssl ca-certificates acl python3-minimal >/dev/null'
vm_ip=$(vm_addr)
[ -n "$vm_ip" ] || die "the VM has no address"
echo "VM $vm at $vm_ip"

# The release directory, root-owned (install.sh insists), and the cell scripts.
tar -C "$ART" --owner=0 --group=0 --numeric-owner -cf - release | $INCUS exec "$vm" -- tar -xf - -C /root
vmsh 'chmod 0755 /root/release /root/release/install.sh && stat -c "%U:%G %a" /root/release'
for f in vm-cell.sh checklist.sh; do $INCUS file push --uid 0 --gid 0 --mode 0755 "$here/$f" "$vm/root/$f" >/dev/null; done

install_args=(sh /root/release/install.sh --release-dir /root/release --progress json)

# ---- the prebuilt cell: a clean refusal ----
if [ "$CELL_IMAGE" = prebuilt ]; then
    step "--image prebuilt must be refused with exit 6 and change nothing"
    mkdir -p "$OUT/secrets"
    HX1E_VM_DIR="$OUT/secrets" "$CLIENT" --ignored --exact vm_secrets >/dev/null 2>&1
    set +e
    $INCUS exec "$vm" --force-noninteractive -- "${install_args[@]}" --ssh --user alice --image prebuilt \
        <"$OUT/secrets/frames.bin" >"$OUT/prebuilt.jsonl" 2>"$OUT/prebuilt.err"
    rc=$?
    set -e
    [ "$rc" = 6 ] || die "--image prebuilt exited $rc, want 6: $(cat "$OUT/prebuilt.err")"
    vmsh 'test ! -e /var/lib/hx/install-state.json && test ! -e /usr/lib/hx && ! dpkg -s incus >/dev/null 2>&1' ||
        die "a refused install changed the host"
    echo "PASS: --image prebuilt refused with exit 6, no state, no /usr/lib/hx, no incus package"
    exit 0
fi

# ---- variants that prepare the host ----
case $variant in
ufw)
    step "ufw active before the install"
    vmsh 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null && ufw default deny incoming && ufw allow 22/tcp && ufw --force enable && ufw status verbose'
    ;;
docker-host)
    step "Docker on the host, with a published port"
    vmsh 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io >/dev/null && systemctl enable --now docker && docker pull -q busybox'
    ;;
esac
extra=()
[ "$variant" = private ] && extra+=(--allow-private-networks)
chk=()
[ "$variant" = private ] && chk+=(private)
[ "$variant" = docker-host ] && chk+=(docker)

# ---- secrets (made by the client test, never printed) and the canary ----
step "secrets and canary"
mkdir -p "$OUT/secrets"
chmod 0700 "$OUT/secrets"
HX1E_VM_DIR="$OUT/secrets" "$CLIENT" --ignored --exact vm_secrets >/dev/null 2>&1
S=$OUT/secrets
{
    cat "$S/password"; echo
    cat "$S/pin"; echo
    cat "$S/token"; echo
    sed 's/^hxt1-//' "$S/token"; echo
} | $INCUS exec "$vm" -- sh -c 'umask 077; cat > /root/hx1e-canary.pat'
vmx sh /root/vm-cell.sh canary-start

run_install() { # run_install <tag> [extra installer args...]
    local tag=$1
    shift
    set +e
    $INCUS exec "$vm" --force-noninteractive -- "${install_args[@]}" --ssh --user alice "${extra[@]}" "$@" \
        <"$S/frames.bin" >"$OUT/$tag.jsonl" 2>"$OUT/$tag.err"
    rc=$?
    set -e
    for sec in password pin token; do
        if grep -qF -f <(cat "$S/$sec") "$OUT/$tag.jsonl" "$OUT/$tag.err"; then die "a secret reached the installer's output ($tag)"; fi
    done
    [ "$(grep -vc '^{' "$OUT/$tag.jsonl" || true)" = 0 ] || die "non-JSON lines on stdout ($tag)"
    return "$rc"
}
result_of() { jq -c 'select(.t=="result")' "$OUT/$1.jsonl" | tail -n 1; }

# ---- failure injection and resume (Gate 1) ----
for stage in incus host; do
    step "stop after $stage, then resume"
    rc=0
    run_install "fail-$stage" --test-fail-after "$stage" || rc=$?
    [ "$rc" = 1 ] || die "--test-fail-after $stage exited $rc: $(cat "$OUT/fail-$stage.err")"
    [ "$(result_of "fail-$stage" | jq -r .code)" = TEST_HOOK ] || die "stage $stage did not stop at the hook: $(result_of "fail-$stage")"
done

# ---- the install ----
step "the install (resumes after host)"
rc=0
run_install install || rc=$?
[ "$rc" = 0 ] || die "install exited $rc: $(cat "$OUT/install.err") $(result_of install)"
res=$(result_of install)
echo "$res" | jq -e '.ok == true and (.server_public_key | length == 64) and .port == 443' >/dev/null || die "bad result: $res"
server_key=$(echo "$res" | jq -r .server_public_key)
jq -r 'select(.t=="stage" and .state=="done") | [.id, .ms] | @tsv' "$OUT"/fail-incus.jsonl "$OUT"/fail-host.jsonl "$OUT"/install.jsonl >"$OUT/stages.tsv"
echo "PASS: install exit 0, server key ${server_key:0:12}..., port rule $(echo "$res" | jq -r .port_rule)"

step "units and credentials"
vmx sh /root/vm-cell.sh units
if [ "$variant" = ufw ]; then
    vmsh 'ufw status | grep -E "^443/(tcp|udp).*ALLOW"' || die "ufw: the installer did not open 443"
    echo "PASS: ufw allows 443/tcp and 443/udp"
fi

# ---- pairing and PIN login from the runner ----
step "pairing and PIN login from the runner (QUIC with the app's token, WebSocket with a code)"
code() { vmsh "$AGENT pairing code 2>&1 | grep -Eo '[0-9A-Z]{4}-[0-9A-Z]{4}' | head -n 1"; }
HX1E_VM_DIR="$S" HX1E_VM_ADDR="$vm_ip:443" HX1E_VM_SERVER_KEY="$server_key" HX1E_VM_STREAM=1 \
    HX1E_VM_CREDS="quic:$(cat "$S/token"),ws:$(code)" \
    "$CLIENT" --ignored --exact vm_login --nocapture 2>&1 | tee "$OUT/client.log" | grep -E '^(PASS|thread)' || die "client failed: see client.log"
grep -q 'first frame' "$OUT/client.log" || die "no first frame"

# ---- canary ----
step "secrets canary"
vmx sh /root/vm-cell.sh canary-check

# ---- the host-ruleset checklist, from inside the desktop ----
step "host-ruleset checklist (hx-provision README items 1 to 5)"
vmx bash /root/checklist.sh "${chk[@]}"

# ---- idempotence ----
step "idempotence: a second run changes nothing"
vmx sh /root/vm-cell.sh snapshot /root/snap-before
run_install again || die "the second run exited non-zero: $(cat "$OUT/again.err")"
vmx sh /root/vm-cell.sh snapshot /root/snap-after
vmsh 'diff /root/snap-before /root/snap-after' || die "a second run changed files"
echo "PASS: the second run changed no file (sha256, mode, owner, mtime)"

# ---- rescue ----
step "rescue: a pending update whose hx-privd fails"
vmx sh /root/vm-cell.sh rescue

# ---- reboot ----
step "VM reboot"
$INCUS restart "$vm"
for _ in $(seq 1 100); do $INCUS exec "$vm" -- true 2>/dev/null && break; sleep 3; done
for _ in $(seq 1 60); do
    s=$(vmsh 'systemctl is-system-running 2>&1' || true)
    [ "$s" = running ] || [ "$s" = degraded ] && break
    sleep 3
done
vm_ip=$(vm_addr)
vmx sh /root/vm-cell.sh reboot-check
[ -n "$vm_ip" ] || die "the VM has no address after the reboot"
HX1E_VM_DIR="$S" HX1E_VM_ADDR="$vm_ip:443" HX1E_VM_SERVER_KEY="$server_key" HX1E_VM_CREDS="quic:$(code)" \
    "$CLIENT" --ignored --exact vm_login --nocapture 2>&1 | tee "$OUT/client-reboot.log" | grep -E '^(PASS|thread)' ||
    { tail -n 20 "$OUT/client-reboot.log" >&2; die "login after the reboot failed"; }

# ---- uninstall, both modes ----
step "uninstall --keep-desktop"
vmsh "$AGENT uninstall --keep-desktop --yes" || die "uninstall --keep-desktop failed"
vmx sh /root/vm-cell.sh leftovers keep
step "reinstall over the kept desktop, then uninstall --destroy-desktop"
run_install reinstall || die "reinstall exited non-zero: $(cat "$OUT/reinstall.err")"
vmsh "$AGENT uninstall --destroy-desktop --yes" || die "uninstall --destroy-desktop failed"
vmx sh /root/vm-cell.sh leftovers destroy

echo
echo "CELL PASSED: $CELL_OS / $CELL_IMAGE / $variant"
