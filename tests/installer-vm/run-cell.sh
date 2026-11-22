#!/bin/bash
# One cell of .github/workflows/installer-vm.yml: the real installer on a fresh KVM VM.
#
#   CELL_OS=ubuntu-24.04 CELL_IMAGE=build ART=/path/to/artifacts OUT=/path/to/out \
#       [CELL_VARIANT=none|ufw|docker-host|private|docker|interactive] tests/installer-vm/run-cell.sh
#
#   CELL_OS       ubuntu-24.04 | ubuntu-26.04 | debian-12 | debian-13 (the VM's OS)
#   CELL_IMAGE    build    : the full install, every check below
#                 prebuilt : `--image prebuilt` must be refused cleanly (exit 6, nothing changed):
#                            privd answers UNIMPLEMENTED for the prebuilt path in this release
#   CELL_VARIANT  none         plain host
#                 docker       install with --docker: the incus stage must take Zabbly (6.0.5 or newer),
#                              the desktop gets nesting and the syscall intercepts, and Docker
#                              runs inside it (hello-world), also after a reboot
#                 interactive  install with --interactive, answered on a pseudo-terminal
#                              (tty-driver.py): prompts, hidden secrets, the printed pairing code,
#                              QUIC pairing with that code and a PIN login; a shorter cell
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
# VM reboot; uninstall in both modes with an empty-leftovers check. The interactive variant runs
# only: launch, the interactive install, pairing and login with the printed code, the canary, the
# checklist, a re-run that must not ask again, and uninstall with the leftovers check.
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
[ "$variant" = docker ] && extra+=(--docker)
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

# ---- the interactive cell: --interactive on a pseudo-terminal ----
if [ "$variant" = interactive ]; then
    step "the pty driver needs python3 (the cell's minimal set has python3-minimal only)"
    vmsh 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 >/dev/null'
    $INCUS file push --uid 0 --gid 0 --mode 0755 "$here/tty-driver.py" "$vm/root/tty-driver.py" >/dev/null
    $INCUS file push --uid 0 --gid 0 --mode 0644 "$here/interactive-steps.json" "$vm/root/interactive-steps.json" >/dev/null
    # The typed secrets: files in the VM that only the driver reads (never argv, never the environment).
    $INCUS file push --uid 0 --gid 0 --mode 0600 "$S/password" "$vm/root/hx1e-pw" >/dev/null
    $INCUS file push --uid 0 --gid 0 --mode 0600 "$S/pin" "$vm/root/hx1e-pin" >/dev/null

    step "install.sh --interactive, answered on a pseudo-terminal"
    rc=0
    $INCUS exec "$vm" --force-noninteractive -- python3 /root/tty-driver.py /root/interactive-steps.json /root/interactive.out -- \
        sh /root/release/install.sh --release-dir /root/release --progress json --interactive 2>"$OUT/interactive-driver.err" || rc=$?
    $INCUS file pull "$vm/root/interactive.out" "$OUT/interactive.out" >/dev/null 2>&1 || true
    [ "$rc" = 0 ] || { tail -n 30 "$OUT/interactive.out" >&2 || true; die "the interactive install exited $rc (97: ended before every prompt, 98: a prompt never came): $(cat "$OUT/interactive-driver.err")"; }
    out=$OUT/interactive.out
    for sec in password pin; do
        if grep -qF -f <(cat "$S/$sec") "$out"; then die "the $sec was echoed on the terminal: it must be hidden"; fi
    done
    echo "PASS: exit 0; the hidden answers (password, PIN) never reached the terminal output"
    grep -q 'must be basic or developer' "$out" || die "the bad answer for --apps was not rejected with a message"
    grep -q 'Repeat the password: ' "$out" && grep -q 'Repeat the PIN: ' "$out" || die "the secrets were not asked twice"
    echo "PASS: a bad answer was refused and asked again; the password and the PIN were asked twice"
    # Nothing may change before every question is answered: the first stage that changes the host
    # ("packages") starts after the last prompt.
    last=$(grep -n 'Repeat the PIN: ' "$out" | head -n 1 | cut -d: -f1)
    first=$(grep -n '"id":"packages"' "$out" | head -n 1 | cut -d: -f1)
    [ -n "$last" ] && [ -n "$first" ] && [ "$first" -gt "$last" ] || die "the packages stage (line ${first:-none}) did not come after the last prompt (line ${last:-none})"
    echo "PASS: every prompt came before the first stage that changes the host"
    grep -E '^\{' "$out" >"$OUT/interactive.jsonl" || true
    res=$(jq -c 'select(.t=="result")' "$OUT/interactive.jsonl" | tail -n 1)
    echo "$res" | jq -e '.ok == true and .exit == 0 and (.server_public_key | length == 64) and .port == 443 and .pairing.kind == "code" and .pairing.expires_at_unix_s > 0' >/dev/null || die "bad result: $res"
    server_key=$(echo "$res" | jq -r .server_public_key)
    pair_code=$(grep -Eo 'pairing code: [0-9A-Z]{4}-[0-9A-Z]{4}' "$out" | head -n 1 | sed 's/^pairing code: //')
    [ -n "$pair_code" ] || die "no 'pairing code: XXXX-XXXX' in the output"
    grep -q 'address: ' "$out" && grep -q 'valid until ' "$out" || die "the address and the expiry were not printed"
    grep -q 'Enter this code in the app to pair' "$out" || die "the pairing instruction was not printed"
    echo "PASS: the result is ok, the code ${pair_code:0:2}.. was printed with the address, the port and the expiry"
    jq -r 'select(.t=="stage" and .state=="done") | [.id, .ms] | @tsv' "$OUT/interactive.jsonl" >"$OUT/stages.tsv"

    step "units and credentials"
    vmx sh /root/vm-cell.sh units

    step "pairing with the printed code over QUIC, and PIN login"
    HX1E_VM_DIR="$S" HX1E_VM_ADDR="$vm_ip:443" HX1E_VM_SERVER_KEY="$server_key" HX1E_VM_STREAM=1 \
        HX1E_VM_CREDS="quic:$pair_code" \
        "$CLIENT" --ignored --exact vm_login --nocapture 2>&1 | tee "$OUT/client.log" | grep -E '^(PASS|thread)' || die "client failed: see client.log"
    grep -q 'first frame' "$OUT/client.log" || die "no first frame"
    echo "PASS: the printed code paired a device over QUIC and the typed PIN logged in"

    step "secrets canary"
    vmx sh /root/vm-cell.sh canary-check

    step "host-ruleset checklist"
    vmx bash /root/checklist.sh

    step "a re-run without a mode must not ask again"
    rc=0
    $INCUS exec "$vm" --force-noninteractive -- sh /root/release/install.sh --release-dir /root/release --progress json \
        </dev/null >"$OUT/again.jsonl" 2>"$OUT/again.err" || rc=$?
    [ "$rc" = 0 ] || die "the re-run exited $rc: $(cat "$OUT/again.err")"
    jq -e 'select(.t=="result") | .ok == true' "$OUT/again.jsonl" >/dev/null || die "the re-run did not end ok: $(tail -n 3 "$OUT/again.jsonl")"
    echo "PASS: the re-run (no --interactive, no terminal) ended ok without a question"

    step "uninstall --destroy-desktop"
    vmsh "$AGENT uninstall --destroy-desktop --yes" || die "uninstall --destroy-desktop failed"
    vmx sh /root/vm-cell.sh leftovers destroy
    echo
    echo "CELL PASSED: $CELL_OS / $CELL_IMAGE / $variant"
    exit 0
fi

# ---- failure injection and resume (Gate 1) ----
for stage in incus host; do
    step "stop after $stage, then resume"
    rc=0
    run_install "fail-$stage" --test-fail-after "$stage" || rc=$?
    [ "$rc" = 1 ] || die "--test-fail-after $stage exited $rc: $(cat "$OUT/fail-$stage.err")"
    [ "$(result_of "fail-$stage" | jq -r .code)" = TEST_HOOK ] || die "stage $stage did not stop at the hook: $(result_of "fail-$stage")"
    if [ "$stage" = incus ]; then
        # Where did Incus come from? Always logged; with --docker it must be Zabbly (the distro
        # Incus of ubuntu-24.04 is 6.0.0 and of debian-13 6.0.4, both below the 6.0.5 Docker needs).
        src=$(vmsh 'cat /var/lib/hx/install-state.json' | jq -r '.created.incus.source // "none"')
        echo "incus source: $src ($(vmsh "dpkg-query -W -f='\${Version}' incus"))"
        if [ "$variant" = docker ]; then
            [ "$src" = zabbly ] || die "--docker: the incus stage took '$src', want zabbly"
            vmx sh /root/vm-cell.sh zabbly 6.0.5
        fi
    fi
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

if [ "$variant" = docker ]; then
    step "--docker: the result, nesting and intercepts, and Docker inside the desktop"
    n=$(jq -r 'select(.t=="step" and .privd_stage=="DOCKER") | .id' "$OUT/install.jsonl" | wc -l)
    [ "$n" -gt 0 ] || die "no DOCKER progress step in the install output: privd did not enable Docker"
    bad=$(jq -r 'select(.t=="warn") | .message | select(test("docker"; "i"))' "$OUT/install.jsonl" || true)
    [ -z "$bad" ] || die "a Docker warning in the install output: $bad"
    echo "$res" | jq -e '[.desktop.warnings[] | select(test("docker"; "i"))] | length == 0' >/dev/null || die "the result carries a Docker warning: $res"
    vmx sh /root/vm-cell.sh docker alice
    echo "PASS: $n DOCKER progress steps, no Docker warning in the result"
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
[ "$variant" != docker ] || vmx sh /root/vm-cell.sh docker alice
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
