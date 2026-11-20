#!/usr/bin/env bash
# Runs on the CLIENT machine: Configuration B (real internet). Server in s2-desktop on the VPS, reached through the Incus
# UDP proxy device (vps-ctl.sh proxy-add), client = target/release/s2-client on this machine; every server-side command
# goes over ssh. Usage: wan-matrix.sh <host> [user]   (HOST is the VPS address)
HOST=${1:?host}
USER_=${2:-administrator}
cd "$(dirname "$0")/.." || exit 1
R=results/vps
run() { # tag scenario profile [extra args]
  local tag=$1 sc=$2 prof=$3; shift 3
  [ -f $R/$tag/meta.json ] && grep -q '"client_rc": 0' $R/$tag/meta.json && return 0
  for try in 1 2; do
    python3 scripts/run_vps.py --client local --ssh "$USER_@$HOST" --addr "$HOST:47433" --scenario "$sc" --config fps120 --profile "$prof" \
      --tag "$tag" --label "B: client on the local machine over the internet (server in s2-desktop via UDP proxy)" "$@" && grep -q '"client_rc": 0' $R/$tag/meta.json && return 0
    echo "retry $tag"; sleep 5
  done
}
for rep in 1 2 3; do
  for sc in typing scroll drag video; do run B_${sc}_fps120_r$rep $sc lan; done
  run B_idle_fps120_r$rep idle lan --dur 30
done
# netem profiles (BN_*) were tried and DISCARDED: through the Incus userspace proxy device the server's replies reach the
# proxy over loopback inside the container, so `tc netem` on the container eth0 shapes nothing (the runs were unconstrained).
# Shaping the VPS uplink instead would touch host networking shared with Docker, which was out of bounds.
echo "== done $(date +%T)"
