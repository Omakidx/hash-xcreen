#!/bin/sh
# Runs INSIDE the worker. Makes /repos/$2 a copy of /repos/$1 and flips bytes in one pack, to
# prove that `check --read-data` detects corruption that the metadata-only check cannot.
set -e
rm -rf "/repos/$2"
cp -a --reflink=auto "/repos/$1" "/repos/$2"
f=$(ls /repos/$2/data/*/* | head -40 | tail -1)
echo "corrupting $f"
printf 'CORRUPTCORRUPTCORRUPT' | dd of="$f" bs=1 seek=1000 conv=notrunc 2>/dev/null
