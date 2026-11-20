#!/usr/bin/env bash
# Does the bridge ACL (net-test.sh) also bind Docker containers nested in a desktop container?
# Needs a container with Docker (docker-test.sh) running on the bridge BR. Run as root.
# Usage: acl-docker-test.sh <container> [bridge=hxbr0] [test-port=9443]
c=$1 BR=${2:-hxbr0} PORT=${3:-9443} ACL=s3-isolate-docker
gw=$(incus network get "$BR" ipv4.address | cut -d/ -f1)
pub=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | grep -v "^$gw$" | grep -v '^172\.17\.' | head -1)
(cd /tmp && exec python3 -m http.server "$PORT" --bind 0.0.0.0 >/dev/null 2>&1) & srv=$!
sleep 1
incus network acl create $ACL >/dev/null
incus network acl rule add $ACL egress action=drop destination=169.254.169.254/32
incus network acl rule add $ACL egress action=drop destination="$gw"/32
incus network acl rule add $ACL egress action=drop destination="$pub"/32
incus network acl rule add $ACL egress action=allow
d() { incus exec "$c" -- runuser -l desk -c "$1"; }
probe() { # name url expect
  out=$(d "docker run --rm busybox:1.37 wget -q -T 5 -O /dev/null $2 && echo reach || echo blocked" 2>/dev/null | tail -1)
  echo "$1 [$3 expected]: $out"
}
probe "docker container -> metadata" http://169.254.169.254/ reach
probe "docker container -> gateway $gw:$PORT" http://$gw:$PORT/ reach
probe "docker container -> host public $pub:$PORT" http://$pub:$PORT/ reach
probe "docker container -> internet (example.com)" http://example.com/ reach
incus network set "$BR" security.acls=$ACL security.acls.default.egress.action=allow
sleep 2
probe "WITH ACL: docker container -> metadata" http://169.254.169.254/ blocked
probe "WITH ACL: docker container -> gateway $gw:$PORT" http://$gw:$PORT/ blocked
probe "WITH ACL: docker container -> host public $pub:$PORT" http://$pub:$PORT/ blocked
probe "WITH ACL: docker container -> internet (example.com)" http://example.com/ reach
d 'docker pull -q alpine:3 >/dev/null && echo "WITH ACL: docker pull ok"'
incus network set "$BR" security.acls= security.acls.default.egress.action=
incus network acl delete $ACL
kill $srv
