#!/bin/sh
# Runs INSIDE the VM of one installer-vm cell, as root: the checks that need the VM's own view.
# Driven by tests/installer-vm/run-cell.sh (through `incus exec`); never run it on a machine that is
# not a throwaway VM: `snapshot`, `uninstall-*` and `rescue` change the host on purpose.
#
#   vm-cell.sh <phase>
#     canary-start            start sampling /proc/*/cmdline and environ for the secrets in PAT
#     canary-check            stop the sampler; scan /proc samples, the journal and the files
#     units                   units active, 443 listening, systemd-analyze verify, credentials
#     snapshot <file>         write the hash list of everything the installer owns
#     rescue                  plant a pending update whose hx-privd cannot start; expect rollback
#     reboot-check            after a VM reboot: the firewall table, unit order, the desktop
#     leftovers <keep|destroy>  nothing the installer created may remain
#
# POSIX sh; `set -eu`. Every failure prints what it saw and exits non-zero.
set -eu

PAT=/root/hx1e-canary.pat
HITS=/root/hx1e-canary.hits
AGENT=/usr/lib/hx/current/hx-agent

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

phase=${1:-}
[ -n "$phase" ] || fail "usage: vm-cell.sh <phase>"
shift

case $phase in

canary-start)
    [ -s "$PAT" ] || fail "$PAT is missing"
    : >"$HITS"
    systemd-run --unit=hx1e-canary --collect -q sh -c \
        "while :; do grep -l -a -F -f $PAT /proc/[0-9]*/cmdline /proc/[0-9]*/environ 2>/dev/null; sleep 0.05; done >> $HITS"
    pass "canary sampler started"
    ;;

canary-check)
    systemctl stop hx1e-canary.service || true
    hits=$(sort -u "$HITS" | head -20)
    [ -z "$hits" ] || fail "a secret was in /proc/<pid>/cmdline or environ: $hits"
    j=$(journalctl -a --no-pager 2>/dev/null | grep -a -F -c -f "$PAT" || true)
    [ "${j:-0}" = 0 ] || fail "a secret is in the journal ($j lines)"
    f=$(grep -r -a -F -l -f "$PAT" /var/log/hx /var/log/hx-install.log /etc/hx /var/lib/hx /var/lib/hx-gatewayd /run/hx /run/credentials /usr/lib/hx /usr/local/lib/systemd /etc/systemd 2>/dev/null || true)
    [ -z "$f" ] || fail "a secret is on disk: $f"
    pass "no secret in /proc cmdline/environ (sampled every 50 ms), the journal, /var/log/hx*, the state file, /etc/hx, /var/lib/hx*, /run/hx, /run/credentials, the units"
    ;;

units)
    for u in hx-privd.socket hx-gatewayd-admin.socket hx-gatewayd-public.socket incus.socket; do
        [ "$(systemctl is-active "$u")" = active ] || fail "$u is not active"
    done
    # hx-host-firewall.service only reloads the ruleset at boot (privd loaded it for this boot).
    [ "$(systemctl is-enabled hx-host-firewall.service)" = enabled ] || fail "hx-host-firewall.service is not enabled"
    ss -H -ltnu | grep -q ':443 ' || fail "nothing listens on 443"
    [ "$(ss -H -ltnu | grep -c ':443 ')" -ge 2 ] || fail "443 must listen for tcp and udp"
    # The whole boot transaction: an ordering cycle through an hx unit makes systemd delete a start
    # job at boot (it once deleted systemd-tmpfiles-setup.service).
    cyc=$(systemd-analyze verify default.target 2>&1 | grep -E 'ordering cycle|deleted to break' || true)
    [ -z "$cyc" ] || fail "ordering cycle in the boot transaction: $cyc"
    out=$(systemd-analyze verify /usr/local/lib/systemd/system/hx-privd.service /usr/local/lib/systemd/system/hx-privd.socket \
        /usr/local/lib/systemd/system/hx-gatewayd.service /usr/local/lib/systemd/system/hx-gatewayd-admin.socket \
        /usr/local/lib/systemd/system/hx-gatewayd-public.socket /usr/local/lib/systemd/system/hx-host-firewall.service \
        /usr/local/lib/systemd/system/hx-privd-rescue.service 2>&1 || true)
    echo "$out" | grep -qi 'error\|failed\|unknown' && fail "systemd-analyze verify: $out"
    ls -l /etc/hx/creds
    [ ! -e /var/lib/hx/pepper.key ] || fail "pepper.key exists: the pepper is not sealed"
    for c in pepper identity; do
        [ "$(stat -c '%a %U' /etc/hx/creds/$c.cred)" = "600 root" ] || fail "$c.cred is not 0600 root"
    done
    # gatewayd is socket-activated: the client's first connection starts it; its credential
    # directory exists once it runs.
    if [ "$(systemctl is-active hx-gatewayd.service)" = active ]; then
        ls -l /run/credentials/hx-gatewayd.service/identity
        getfacl -p /run/credentials/hx-gatewayd.service/identity 2>&1 || true
    fi
    pass "units active, 443 tcp+udp, systemd-analyze verify clean, credentials sealed (pepper.cred, identity.cred 0600 root), no pepper.key"
    ;;

snapshot)
    out=${1:?snapshot <file>}
    cd /
    find etc/hx usr/local/lib/systemd/system etc/systemd/system usr/local/lib/sysusers.d usr/local/lib/tmpfiles.d \
        etc/logrotate.d usr/lib/hx usr/lib/hx-rescue -xdev \( -type f -o -type l \) 2>/dev/null | sort |
        while read -r f; do
            case $f in
            */install-state.json | etc/hx/host-firewall.nft) ;;
            *)
                if [ -L "$f" ]; then
                    echo "L $f $(readlink "$f")"
                else
                    echo "$(sha256sum "$f" | cut -d' ' -f1) $(stat -c '%a %U:%G %Y' "$f") $f"
                fi
                ;;
            esac
        done >"$out"
    pass "snapshot of $(wc -l <"$out") files"
    ;;

rescue)
    v=$(readlink /usr/lib/hx/current)
    rm -rf /usr/lib/hx/9.9.9
    cp -a "/usr/lib/hx/$v" /usr/lib/hx/9.9.9
    printf '#!/bin/sh\nexit 1\n' >/usr/lib/hx/9.9.9/hx-privd
    chmod 0755 /usr/lib/hx/9.9.9/hx-privd
    printf '9.9.9\n' >/usr/lib/hx/9.9.9/VERSION
    ln -sfn "$v" /usr/lib/hx/previous
    ln -sfn 9.9.9 /usr/lib/hx/current
    now=$(date +%s)
    umask 077
    if [ -s /var/lib/hx/updates-state ] && ! grep -q '^{}$' /var/lib/hx/updates-state; then
        # keep what is there; only the pending record is ours
        sed 's/}$//' /var/lib/hx/updates-state >/var/lib/hx/updates-state.new
        printf ',"pending":{"version":"9.9.9","previous":"%s","started_unix":%s,"attempts":0,"gateway_pid":1}}' "$v" "$now" >>/var/lib/hx/updates-state.new
        mv /var/lib/hx/updates-state.new /var/lib/hx/updates-state
    else
        printf '{"pending":{"version":"9.9.9","previous":"%s","started_unix":%s,"attempts":0,"gateway_pid":1}}' "$v" "$now" >/var/lib/hx/updates-state
    fi
    chmod 0600 /var/lib/hx/updates-state
    systemctl restart hx-privd.service || true
    i=0
    while [ $i -lt 75 ]; do
        if [ "$(readlink /usr/lib/hx/current)" = "$v" ] && [ "$(systemctl is-active hx-privd.service)" = active ]; then
            if ! grep -q '"pending":{' /var/lib/hx/updates-state; then
                rm -rf /usr/lib/hx/9.9.9
                systemctl reset-failed hx-privd.service hx-privd.socket || true
                pass "OnFailure rolled hx-privd back: current 9.9.9 -> $v after ~$((i * 2)) s, pending cleared"
                exit 0
            fi
        fi
        i=$((i + 1))
        sleep 2
    done
    journalctl -u hx-privd.service -u hx-privd-rescue.service --no-pager -n 40 >&2 || true
    fail "no rollback after 150 s (current=$(readlink /usr/lib/hx/current))"
    ;;

reboot-check)
    [ "$(systemctl is-active hx-privd.socket)" = active ] || fail "hx-privd.socket is not active after the reboot"
    nft list table inet hx >/dev/null 2>&1 || fail "table inet hx is not loaded after the reboot"
    # design: table inet hx exists before incus.service starts, so no desktop runs unfiltered
    fw=$(systemctl show hx-host-firewall.service -p ActiveEnterTimestampMonotonic --value)
    ic=$(systemctl show incus.service -p ActiveEnterTimestampMonotonic --value)
    [ "$(systemctl is-active hx-host-firewall.service)" = active ] || fail "hx-host-firewall.service did not run at boot"
    [ "${fw:-0}" -gt 0 ] || fail "hx-host-firewall.service has no start time"
    [ "${ic:-0}" -eq 0 ] || [ "$fw" -le "$ic" ] || fail "incus.service ($ic) started before the firewall ($fw)"
    i=0
    while [ $i -lt 60 ]; do
        st=$(incus list hx-main -c s --format csv 2>/dev/null || true)
        [ "$st" = RUNNING ] && break
        i=$((i + 1))
        sleep 2
    done
    [ "${st:-}" = RUNNING ] || fail "the desktop did not start by itself after the reboot (state: ${st:-none})"
    incus config device show hx-main | grep -q 'type: proxy' || fail "the session link (proxy device) is gone"
    pass "after reboot: table inet hx loaded before incus.service (firewall $fw, incus $ic), desktop RUNNING, proxy device present"
    ;;

leftovers)
    mode=${1:?leftovers <keep|destroy>}
    left=''
    for p in /usr/lib/hx /usr/lib/hx-rescue /var/lib/hx /var/log/hx /run/hx /var/lib/hx-gatewayd \
        /usr/local/lib/systemd/system/hx-privd.service /usr/local/lib/systemd/system/hx-privd.socket \
        /usr/local/lib/systemd/system/hx-gatewayd.service /usr/local/lib/systemd/system/hx-gatewayd-admin.socket \
        /usr/local/lib/systemd/system/hx-gatewayd-public.socket /usr/local/lib/systemd/system/hx-privd-rescue.service \
        /usr/local/lib/sysusers.d/hx-gatewayd.conf /usr/local/lib/tmpfiles.d/hx.conf /etc/logrotate.d/hx-audit \
        /etc/systemd/system/hx-gatewayd-public.socket.d /var/lib/hx-uninstall.json; do
        if [ -e "$p" ] || [ -L "$p" ]; then left="$left $p"; fi
    done
    [ "$mode" = destroy ] && [ -e /etc/hx ] && left="$left /etc/hx"
    getent passwd hx-gatewayd >/dev/null 2>&1 && left="$left user:hx-gatewayd"
    units=$(systemctl list-unit-files 'hx-*' --no-legend 2>/dev/null | awk '{print $1}')
    if [ "$mode" = keep ]; then
        # keep mode keeps the firewall ruleset and its two units
        units=$(echo "$units" | grep -v '^hx-host-firewall.service$\|^hx-docker-user.service$' || true)
    fi
    [ -z "$units" ] || left="$left units:$(echo "$units" | tr '\n' ',')"
    [ -z "$left" ] || fail "leftovers after uninstall ($mode):$left"
    if [ "$mode" = destroy ]; then
        nft list table inet hx >/dev/null 2>&1 && fail "table inet hx is still loaded"
        ours=$(for c in "list" "profile list" "network list" "storage list" "network acl list"; do incus $c -f csv -c n 2>/dev/null; done | grep '^hx' || true)
        [ -z "$ours" ] || fail "inner Incus objects left: $ours"
    else
        incus list hx-main -c n --format csv | grep -q '^hx-main$' || fail "keep mode must keep the desktop"
    fi
    pass "no leftover after uninstall ($mode)"
    ;;

*)
    fail "unknown phase $phase"
    ;;
esac
