#!/usr/bin/env bash
# Runs ON the VPS: the Configuration A (client on the VPS, over hxbr0) measurement matrix. Usage: vps-matrix.sh <set>...
#   A1   containers unpinned (all 4 vCPU shared by server, desktop and client): fps120 + base x 4 scenarios x 3, idle x 3
#   A2   desktop container pinned to cores 1-3, client container pinned to core 0: fps120 x 4 scenarios x 3, idle x 3
#   X    encoder variants on A1 sharing, fps120 + {noir,t1,t2} x 4 scenarios x 3 (intra refresh / slice-thread trade-off)
#   V    VBV buffer 4 frames instead of 1 (scroll/drag/video x3, plus fidelity runs)
#   FID  fidelity runs (frame dumps): fps120 and fps120-vui x typing/scroll/drag/video, one run each
# Each run is results/vps/<set>_<scenario>_<config>_r<k>/ (see run_vps.py). Resumable: finished runs are skipped.
cd "$(dirname "$0")/.." || exit 1
inc() { sudo -n incus "$@"; }
R=results/vps

run() { # set scenario config rep [extra run_vps args...]
  local set=$1 sc=$2 cfg=$3 rep=$4; shift 4
  local tag=${set}_${sc}_${cfg}_r${rep}
  [ -f $R/$tag/meta.json ] && grep -q '"client_rc": 0' $R/$tag/meta.json && return 0
  for try in 1 2; do
    python3 scripts/run_vps.py --client lan --scenario "$sc" --config "$cfg" --tag "$tag" --label "$LABEL" "$@" && grep -q '"client_rc": 0' $R/$tag/meta.json && return 0
    echo "retry $tag" && sleep 5
  done
}

shared() { inc config unset s2-desktop limits.cpu; inc config unset s2-client limits.cpu; LABEL="A1: both containers unpinned on 4 vCPU"; }
pinned() { inc config set s2-desktop limits.cpu 1-3; inc config set s2-client limits.cpu 0; LABEL="A2: s2-desktop pinned to cores 1-3, s2-client pinned to core 0"; }

for set in "$@"; do
  echo "== $set $(date +%T)"
  case $set in
    A1)
      shared
      for rep in 1 2 3; do
        for sc in typing scroll drag video; do for cfg in fps120 base; do run A1 $sc $cfg $rep; done; done
        run A1 idle base $rep --dur 30
      done ;;
    A2)
      pinned
      for rep in 1 2 3; do
        for sc in typing scroll drag video; do run A2 $sc fps120 $rep; done
        run A2 idle fps120 $rep --dur 30
      done
      shared ;;
    X)
      shared
      for rep in 1 2 3; do
        for sc in typing scroll drag video; do for cfg in fps120-noir fps120-t1 fps120-t2; do run X $sc $cfg $rep; done; done
      done ;;
    FID)
      shared
      for sc in typing scroll drag video; do for cfg in fps120 fps120-vui; do run FID $sc $cfg 1 --dump --dump-every 40; done; done ;;
    V)  # VBV buffer of 4 frames instead of 1: latency/bitrate (3 repeats) and fidelity of the transient frames
      shared
      for rep in 1 2 3; do for sc in scroll drag video; do run V $sc fps120-vbv4n $rep; done; done
      for sc in scroll drag video; do run FID $sc fps120-vbv4 1 --dump --dump-every 40; done ;;
  esac
done
echo "== done $(date +%T)"
