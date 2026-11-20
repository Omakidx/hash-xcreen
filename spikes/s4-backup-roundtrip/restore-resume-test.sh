#!/bin/sh
# Runs INSIDE the worker. Architecture 9.8 step 2: interrupted restores resume, skipping files
# already restored. Restores a snapshot into local disk, SIGKILLs it mid-way, reruns, and
# compares what the rerun still has to restore. Also checks sparse-file handling.
# usage: restore-resume-test.sh <repo> <snapshot> <kill-after-seconds>
set -u
repo=$1; snap=$2; k=$3
rm -rf /root/rt
echo "== restore, kill after ${k}s"
s4 --repo "/repos/$repo" restore --snapshot "$snap" --dest /root/rt --sparse > /root/rt1.out 2>&1 &
pid=$!
sleep "$k"
pkill -9 -f "repos/$repo restore" || true
wait $pid 2>/dev/null || true
cat /root/rt1.out | cut -c1-300
echo "files on disk after kill: $(find /root/rt -type f | wc -l)"
echo "== rerun (trusts size+mtime)"
s4 --repo "/repos/$repo" restore --snapshot "$snap" --dest /root/rt --sparse 2>&1 | cut -c1-300
echo "== rerun with --verify (content check of existing files)"
s4 --repo "/repos/$repo" restore --snapshot "$snap" --dest /root/rt --sparse --verify 2>&1 | cut -c1-300
echo "== sparse file: apparent vs allocated KiB"
ls -l /root/rt/home/alice/special/sparse.img | awk '{print $5/1024 " KiB apparent"}'
du -k /root/rt/home/alice/special/sparse.img
