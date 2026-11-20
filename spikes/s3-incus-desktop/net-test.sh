#!/usr/bin/env bash
# Network isolation test: a container must not reach 169.254.169.254 or the host's own addresses.
# Uses an Incus network ACL on a bridge. Run as root on the server (or as a member of incus-admin).
#
# Usage: net-test.sh
# Environment:
#   BR=hxbr0         bridge to test. If it already exists it is KEPT (the ACL is detached again at the end);
#                    if it does not exist a throwaway bridge (named s3-br0 by default) is created and deleted.
#   PORT=9443        port of a listener this script opens on 0.0.0.0 as the stand-in for the agent port.
#                    Pick a port nothing else uses: other services on the host are not touched.
#   HOST_TCP_PORTS=  extra ports to probe on the host's public IPv4 (only probed, never opened)
# Prints PASS/FAIL lines. Cleans up s3-net-target, s3-isolate and the listeners.
set -uo pipefail
BR=${BR:-s3-br0} ACL=s3-isolate T=s3-net-target PORT=${PORT:-9443}
SUBNET=10.77.4
created_br=0

cleanup() {
  [ -n "${srv:-}" ] && kill "$srv" 2>/dev/null
  [ -n "${msrv:-}" ] && kill "$msrv" 2>/dev/null
  [ "$have_fake_meta" = 1 ] && ip addr del 169.254.169.254/32 dev lo 2>/dev/null
  incus delete -f "$T" 2>/dev/null
  incus network set "$BR" security.acls= security.acls.default.egress.action= 2>/dev/null
  incus network acl delete "$ACL" 2>/dev/null
  [ "$created_br" = 1 ] && incus network delete "$BR" 2>/dev/null
  [ "${docker_rules:-0}" = 1 ] && { iptables -D DOCKER-USER -i "$BR" -j ACCEPT 2>/dev/null; iptables -D DOCKER-USER -o "$BR" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; }
}
have_fake_meta=0
trap cleanup EXIT

if incus network show "$BR" >/dev/null 2>&1; then
  gw=$(incus network get "$BR" ipv4.address | cut -d/ -f1)
else
  gw=$SUBNET.1; created_br=1
  incus network create "$BR" ipv4.address=$gw/24 ipv4.nat=true ipv6.address=none >/dev/null
fi
host_ips=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | grep -v "^$gw$" | tr '\n' ' ')
host_ip6=$(ip -6 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | grep -v '^fd42' | head -3 | tr '\n' ' ')
echo "bridge=$BR gateway=$gw host_ipv4s=[$host_ips] host_ipv6s=[$host_ip6] test_port=$PORT"

# A host running Docker has FORWARD policy DROP: containers lose IPv4 egress unless DOCKER-USER accepts the bridge.
if iptables -S DOCKER-USER >/dev/null 2>&1 && ! iptables -S DOCKER-USER | grep -q -- "-i $BR -j ACCEPT"; then
  docker_rules=1
  echo "host Docker detected: adding temporary DOCKER-USER accept rules for $BR"
  iptables -I DOCKER-USER -o "$BR" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -I DOCKER-USER -i "$BR" -j ACCEPT
fi

incus launch --quiet images:ubuntu/24.04 "$T" --network "$BR" >/dev/null
incus exec $T -- sh -c 'for i in $(seq 60); do s=$(systemctl is-system-running 2>/dev/null); [ "$s" = running -o "$s" = degraded ] && exit 0; sleep 1; done; exit 1'
sleep 3

# Does the provider answer on the metadata address? If not, add it to the host loopback as a stand-in.
if [ "$(curl -s -m 3 -o /dev/null -w '%{http_code}' http://169.254.169.254/)" = 000 ] && [ "$(id -u)" = 0 ]; then
  ip addr add 169.254.169.254/32 dev lo; have_fake_meta=1
  (cd /tmp && exec python3 -m http.server 80 --bind 169.254.169.254 >/dev/null 2>&1) & msrv=$!
  echo "provider does not answer on 169.254.169.254: using a stand-in on the host loopback"
else
  echo "provider answers on 169.254.169.254 from the host (real metadata service)"
fi
(cd /tmp && exec python3 -m http.server "$PORT" --bind 0.0.0.0 >/dev/null 2>&1) & srv=$!
sleep 2

probe() { # name url expect(reach|block)
  code=$(incus exec $T -- curl -s -m 5 -o /dev/null -w '%{http_code}' "$2" 2>/dev/null); code=${code:-000}
  if [ "$3" = reach ]; then [ "$code" != 000 ] && echo "PASS  $1 reachable ($code)" || echo "FAIL  $1 not reachable ($code)"
  else [ "$code" = 000 ] && echo "PASS  $1 blocked" || echo "FAIL  $1 reachable ($code)"; fi
}
checks() { # phase expectation
  echo "--- $1"
  probe "metadata 169.254.169.254:80" http://169.254.169.254/ "$2"
  probe "host via bridge gateway $gw:$PORT" http://$gw:$PORT/ "$2"
  for h in $host_ips; do probe "host address $h:$PORT" http://$h:$PORT/ "$2"; done
  for h in $host_ip6; do probe "host address [$h]:$PORT" "http://[$h]:$PORT/" "$2"; done
}

checks "baseline, no ACL (expect everything reachable)" reach

# Rules are evaluated drop > reject > allow, whatever the order.
incus network acl create $ACL >/dev/null
incus network acl rule add $ACL egress action=drop destination=169.254.169.254/32 description="cloud metadata"
incus network acl rule add $ACL egress action=drop destination=fd00:ec2::254/128 description="cloud metadata (AWS IPv6)"
incus network acl rule add $ACL egress action=drop destination=$gw/32 description="host via the bridge gateway"
for h in $host_ips; do incus network acl rule add $ACL egress action=drop destination=$h/32 description="host address"; done
for h in $host_ip6; do incus network acl rule add $ACL egress action=drop destination=$h/128 description="host address"; done
incus network acl rule add $ACL egress action=allow description="everything else"
incus network set $BR security.acls=$ACL security.acls.default.egress.action=allow
sleep 2
checks "with ACL $ACL on $BR (expect everything blocked)" block

echo "--- what must still work"
c=$(incus exec $T -- curl -s -m 10 -o /dev/null -w '%{http_code}' https://deb.debian.org/ 2>/dev/null)
[ "$c" = 200 ] && echo "PASS  internet over HTTPS ($c)" || echo "FAIL  internet over HTTPS ($c)"
incus exec $T -- getent hosts deb.debian.org >/dev/null && echo "PASS  DNS resolution" || echo "FAIL  DNS resolution"
incus exec $T -- sh -c 'ip -4 addr show eth0 | grep -q "inet 10\."' && echo "PASS  DHCP lease kept"
echo "--- nft rules generated by Incus for the ACL: nft list table inet incus"
