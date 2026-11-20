#!/usr/bin/env bash
# btrfs snapshot behaviour: time, space cost, copy-on-write growth, restore, delete.
# Usage: snapshot-test.sh <container> [pool=default]
set -uo pipefail
c=$1 pool=${2:-default}
used() { incus storage info "$pool" --bytes | awk '/space used:/{print $3}' | tr -d '"'; }
mib() { echo $(( ($1) / 1048576 )); }
now() { date +%s.%N; }
span() { echo "scale=2; ($2 - $1)/1" | bc; }

echo "pool_driver=$(incus storage get "$pool" source >/dev/null 2>&1; incus storage show "$pool" | awk '/^driver:/{print $2}')"
echo "pool_source=$(incus storage show "$pool" | awk '/source:/{print $2}')"
u0=$(used); echo "pool_used_before_mib=$(mib "$u0")"

t=$(now); incus snapshot create "$c" s3-snap0; echo "snapshot_create_s=$(span "$t" "$(now)")"
u1=$(used); echo "pool_used_after_snap0_mib=$(mib "$u1") delta=$(mib $((u1-u0)))"

echo "writing 1 GiB of incompressible data in the container"
incus exec "$c" -- sh -c 'dd if=/dev/urandom of=/home/desk/blob bs=1M count=1024 status=none && sync'
u2=$(used); echo "pool_used_after_write_mib=$(mib "$u2") delta=$(mib $((u2-u1)))"

t=$(now); incus snapshot create "$c" s3-snap1; echo "snapshot_create_with_1GiB_s=$(span "$t" "$(now)")"
u3=$(used); echo "pool_used_after_snap1_mib=$(mib "$u3") delta=$(mib $((u3-u2)))"

echo "modify 100 MiB inside the blob (CoW divergence), then delete the file"
incus exec "$c" -- sh -c 'dd if=/dev/urandom of=/home/desk/blob bs=1M count=100 conv=notrunc status=none && sync'
u4=$(used); echo "pool_used_after_modify_mib=$(mib "$u4") delta=$(mib $((u4-u3)))"
incus exec "$c" -- sh -c 'rm /home/desk/blob && sync'
u5=$(used); echo "pool_used_after_rm_mib=$(mib "$u5") delta=$(mib $((u5-u4)))  (space is held by snap1)"

echo "snapshots:"; incus snapshot list "$c" -c nTs 2>/dev/null || incus info "$c" | sed -n '/Snapshots:/,$p'

t=$(now); incus snapshot restore "$c" s3-snap1; echo "snapshot_restore_s=$(span "$t" "$(now)")"
incus exec "$c" -- sh -c 'ls -l /home/desk/blob && echo restored-blob-present' || echo "restore check FAILED"

t=$(now); incus snapshot delete "$c" s3-snap1; incus snapshot delete "$c" s3-snap0; echo "snapshot_delete_both_s=$(span "$t" "$(now)")"
incus exec "$c" -- rm -f /home/desk/blob; sync
u6=$(used); echo "pool_used_final_mib=$(mib "$u6")"
