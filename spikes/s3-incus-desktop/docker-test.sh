#!/usr/bin/env bash
# Docker-in-container checks: hello-world, then a small compose app with a named volume.
# Usage: docker-test.sh <container>   (container already built with addons/docker.toml)
set -uo pipefail
c=$1
asuser() { incus exec "$c" -- runuser -l desk -c "$1"; }
t() { local s=$(date +%s.%N); "$@"; local rc=$?; echo "  -> rc=$rc $(echo "$(date +%s.%N) - $s" | bc)s"; return $rc; }

echo "## incus config"
incus config get "$c" security.nesting; incus config get "$c" security.syscalls.intercept.mknod; incus config get "$c" security.syscalls.intercept.setxattr
echo "## docker version + storage driver"
asuser 'docker version --format "client={{.Client.Version}} server={{.Server.Version}}"'
asuser 'docker info --format "driver={{.Driver}} backing={{range .DriverStatus}}{{index . 0}}={{index . 1}} {{end}} cgroup={{.CgroupDriver}}/{{.CgroupVersion}} rootless={{.SecurityOptions}}"'
echo "## hello-world"
t asuser 'docker run --rm hello-world | head -4'
echo "## compose app with a named volume"
asuser 'mkdir -p ~/compose-test && cat > ~/compose-test/compose.yml <<EOF
services:
  init:
    image: busybox:1.37
    command: ["sh", "-c", "[ -f /data/index.html ] || echo persisted-ok > /data/index.html"]
    volumes: ["data:/data"]
  web:
    image: nginx:alpine
    depends_on: { init: { condition: service_completed_successfully } }
    ports: ["18080:80"]
    volumes: ["data:/usr/share/nginx/html:ro"]
volumes:
  data: {}
EOF'
t asuser 'cd ~/compose-test && docker compose up -d 2>&1 | tail -8'
sleep 3
echo "curl: $(asuser 'curl -s -m 5 localhost:18080')"
t asuser 'cd ~/compose-test && docker compose down 2>&1 | tail -4'
t asuser 'cd ~/compose-test && docker compose up -d 2>&1 | tail -3'
sleep 3
echo "curl after down/up (volume persisted?): $(asuser 'curl -s -m 5 localhost:18080')"
asuser 'cd ~/compose-test && docker compose down -v 2>&1 | tail -2'
echo "## same compose app with network_mode: host (workaround when bridge networking fails)"
asuser 'cd ~/compose-test && sed -e "/ports:/d" -e "s/^    image: \(.*\)$/    image: \1\n    network_mode: host/" compose.yml > compose-host.yml && docker compose -f compose-host.yml up -d 2>&1 | tail -4'
sleep 3
echo "curl (host mode): $(asuser 'curl -s -m 5 localhost:80')"
asuser 'cd ~/compose-test && docker compose -f compose-host.yml down 2>&1 | tail -2; docker compose -f compose-host.yml up -d 2>&1 | tail -1; sleep 3; echo "curl after down/up (volume persisted?): $(curl -s -m 5 localhost:80)"; docker compose -f compose-host.yml down -v 2>&1 | tail -1'
echo "## hello-world with --network host"
asuser 'docker run --rm --network host hello-world | head -2'
echo "## mknod / setxattr under Docker (intercepted syscalls)"
asuser 'docker run --rm --network host --cap-add MKNOD busybox:1.37 sh -c "mknod /tmp/n c 1 3 && echo mknod-ok"'
asuser 'docker run --rm --network host busybox:1.37 sh -c "touch /tmp/f && echo hi >/tmp/f && (setfattr 2>/dev/null; true) && echo xattr-cmd-skipped"' >/dev/null 2>&1 || true
echo "## image pull of a layer with xattrs/device nodes (debian:stable-slim)"
t asuser 'docker run --rm --network host debian:stable-slim sh -c "ls -l /dev/null && echo debian-ok"'
echo "## errors in dockerd journal"
incus exec "$c" -- journalctl -u docker --no-pager -p warning -n 15 || true
echo "## filesystem of /var/lib/docker"
incus exec "$c" -- sh -c 'df -hT /var/lib/docker | tail -1; docker info 2>/dev/null | grep -iE "storage driver|backing|supports d_type|native overlay|userxattr"'
