#!/bin/bash
# The host-ruleset checklist of crates/hx-provision/README.md ("Host ruleset: installer (1E)
# verification checklist"), items 1 to 5, run INSIDE the VM as root against the desktop `hx-main`.
# Item 6 (persistence across a reboot) is `vm-cell.sh reboot-check`.
#
#   checklist.sh [private] [docker]
#     private   the install used --allow-private-networks: item 3's probes must now SUCCEED (item 5)
#               while item 1 and the DNAT drop still hold
#     docker    Docker runs on the host with a published port: that port must stay unreachable
#
# Needs python3 on the VM (installed here when missing). Everything it starts is removed again.
set -euo pipefail

private=0 docker=0
for a in "$@"; do
    case $a in private) private=1 ;; docker) docker=1 ;; *) echo "unknown argument $a" >&2; exit 2 ;; esac
done

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

command -v python3 >/dev/null 2>&1 || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-minimal >/dev/null; }

gw=$(incus network get hxbr0 ipv4.address | cut -d/ -f1)
pub=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n 1)
[ -n "$gw" ] && [ -n "$pub" ] || fail "cannot find the gateway ($gw) or the public address ($pub)"

dx() { incus exec hx-main -- bash -c "$1"; }
# True when the desktop can open a TCP connection to $1:$2 within 5 s.
tcp_ok() { dx "timeout 5 bash -c 'exec 3<>/dev/tcp/$1/$2' 2>/dev/null"; }

pids=''
cleanup() {
    for p in $pids; do kill "$p" 2>/dev/null || true; done
    ip netns del hx1e-peer 2>/dev/null || true
    ip link del hx1e-v0 2>/dev/null || true
    if [ "$docker" = 1 ]; then docker rm -f hx1e-pub >/dev/null 2>&1 || true; fi
    rm -f /tmp/hx1e-udp.rx
}
trap cleanup EXIT

# ---- item 1: input drop ----
python3 -m http.server 9099 --bind 0.0.0.0 >/dev/null 2>&1 &
pids="$pids $!"
python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 9098))
s.settimeout(40)
try:
    d, a = s.recvfrom(100)
    open("/tmp/hx1e-udp.rx", "wb").write(d)
except Exception:
    pass
' &
pids="$pids $!"
sleep 1
timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/9099' || fail "control: the host listener on 9099 does not answer on loopback"
if tcp_ok "$gw" 9099; then fail "item 1: the desktop reached a host TCP listener on the gateway address $gw"; fi
if tcp_ok "$pub" 9099; then fail "item 1: the desktop reached a host TCP listener on the public address $pub"; fi
dx "echo hx1e > /dev/udp/$gw/9098" 2>/dev/null || true
sleep 3
[ ! -s /tmp/hx1e-udp.rx ] || fail "item 1: a datagram from the desktop reached a host UDP listener"
pass "item 1: input drop (TCP to $gw and $pub:9099 times out, a UDP datagram to $gw:9098 is not received)"

# ---- item 2: DHCP and DNS still work ----
dx "ip -4 -o addr show eth0 | grep -q inet" || fail "item 2: the desktop has no IPv4 lease"
dx "getent hosts example.com" >/dev/null || fail "item 2: the desktop cannot resolve example.com through the gateway"
pass "item 2: the desktop has a lease and resolves names through the gateway"

# ---- item 3 / 5: forward drop to private ranges (a netns peer on 172.31.77.0/24) ----
ip netns add hx1e-peer
ip link add hx1e-v0 type veth peer name hx1e-v1 netns hx1e-peer
ip addr add 172.31.77.1/24 dev hx1e-v0
ip link set hx1e-v0 up
ip netns exec hx1e-peer ip addr add 172.31.77.2/24 dev hx1e-v1
ip netns exec hx1e-peer ip link set hx1e-v1 up
ip netns exec hx1e-peer ip link set lo up
ip netns exec hx1e-peer ip route add default via 172.31.77.1
ip netns exec hx1e-peer python3 -m http.server 8080 --bind 172.31.77.2 >/dev/null 2>&1 &
pids="$pids $!"
sleep 1
ip netns exec hx1e-peer bash -c 'timeout 3 bash -c "exec 3<>/dev/tcp/172.31.77.2/8080"' || fail "control: the peer listener does not answer inside its namespace"
if [ "$private" = 1 ]; then
    tcp_ok 172.31.77.2 8080 || fail "item 5: with allow_private_networks the desktop must reach 172.31.77.2"
    pass "item 5: with allow_private_networks the private-range probe succeeds"
    if tcp_ok "$gw" 9099; then fail "item 5: item 1 must still hold with allow_private_networks"; fi
    pass "item 5: item 1 still holds with allow_private_networks"
else
    if tcp_ok 172.31.77.2 8080; then fail "item 3: the desktop reached 172.31.77.2 (a private address behind the host)"; fi
    pass "item 3: forward drop (172.31.77.2:8080 behind the host is unreachable from the desktop)"
fi

# ---- item 3: a host port published with Docker (DNAT) is unreachable ----
if [ "$docker" = 1 ]; then
    docker run -d --name hx1e-pub -p 8099:80 busybox httpd -f -p 80 >/dev/null
    sleep 2
    # Any HTTP answer will do: busybox httpd has no index page and answers 404 (curl -f called that
    # a failure). 000 means no connection.
    code=$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:8099/" || true)
    [ -n "$code" ] && [ "$code" != 000 ] || fail "control: the published Docker port does not answer on the host"
    if tcp_ok "$pub" 8099; then fail "item 3: the desktop reached a Docker-published host port"; fi
    pass "item 3: a port published with Docker is unreachable from the desktop"
fi

# ---- item 4: the internet through NAT still works ----
dx "curl -fsS -m 20 -o /dev/null https://example.com" || fail "item 4: the desktop cannot reach the internet through NAT"
pass "item 4: HTTPS to a public address works through NAT"
