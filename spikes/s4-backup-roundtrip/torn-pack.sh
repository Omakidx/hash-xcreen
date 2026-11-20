#!/bin/sh
# Runs INSIDE the worker. Simulates the file a SIGKILL during a local-backend pack write can
# leave behind (rustic's local backend writes in place: create, set_len, copy): a pack-named file
# with only a prefix of its content and a zeroed tail. Then runs repair-index and check.
set -e
rm -rf /repos/L3-T
cp -a --reflink=auto "/repos/$1" /repos/L3-T
src=$(ls /repos/L3-T/data/*/* | head -30 | tail -1)
size=$(stat -c %s "$src")
d=/repos/L3-T/data/ff
mkdir -p $d
torn=$d/ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000
head -c $((size / 2)) "$src" > $torn
truncate -s "$size" $torn          # pre-sized, tail is zeros (set_len then partial write)
echo "torn pack: $torn ($size bytes, half zeroed)"
echo "--- repair-index"
RUST_LOG=warn s4 --repo /repos/L3-T repair-index 2>&1 | cut -c1-260 || true
echo "--- check (metadata)"
s4 --repo /repos/L3-T check 2>&1 | tail -2 | cut -c1-260 || true
echo "--- check --read-data all"
s4 --repo /repos/L3-T check --read-data all 2>&1 | head -8 | cut -c1-260 || true
echo "--- backup after the torn pack exists (dedup path unaffected?) skipped; pack still present:"
ls -l $torn | awk '{print $5}'
