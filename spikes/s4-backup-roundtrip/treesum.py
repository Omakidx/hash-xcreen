#!/usr/bin/env python3
"""Deterministic description of a directory tree for round-trip comparison.

usage: treesum.py ROOT [EXCLUDE_LIST_FILE] > out.txt
One line per entry: path | type | mode | uid | gid | size | mtime_ns | nlink | sha256 | symlink
target | xattrs (name=hex(value), sorted; includes system.posix_acl_* and security.capability).
EXCLUDE_LIST_FILE holds rootfs-relative paths (`/home/a/.cache`), whole subtrees are skipped.
Hard-link relationships are reported separately as groups of paths sharing an inode.
"""
import hashlib, os, stat, sys
from concurrent.futures import ThreadPoolExecutor

root = sys.argv[1].rstrip("/")
excl = set()
if len(sys.argv) > 2:
    excl = {l.rstrip("\n") for l in open(sys.argv[2]) if l.strip()}

def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()

def xattrs(path):
    out = []
    try:
        for n in os.listxattr(path, follow_symlinks=False):
            try:
                out.append(f"{n}={os.getxattr(path, n, follow_symlinks=False).hex()}")
            except OSError as e:
                out.append(f"{n}=ERR{e.errno}")
    except OSError:
        pass
    return ",".join(sorted(out))

entries = []
inodes = {}
def walk(d, rel):
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return
    for n in names:
        p = f"{d}/{n}"
        r = f"{rel}/{n}"
        if r in excl:
            continue
        st = os.lstat(p)
        entries.append((r, p, st))
        if stat.S_ISDIR(st.st_mode):
            walk(p, r)

walk(root, "")
# root dir itself
entries.insert(0, ("/", root, os.lstat(root)))

def describe(e):
    r, p, st = e
    m = st.st_mode
    t = "d" if stat.S_ISDIR(m) else "l" if stat.S_ISLNK(m) else "f" if stat.S_ISREG(m) else "p" if stat.S_ISFIFO(m) else "s" if stat.S_ISSOCK(m) else "o"
    h = ""
    tgt = ""
    if t == "f":
        try:
            h = sha(p)
        except OSError as ex:
            h = f"ERR{ex.errno}"
    elif t == "l":
        tgt = os.readlink(p)
    return "|".join([r, t, oct(stat.S_IMODE(m)), str(st.st_uid), str(st.st_gid),
                     str(st.st_size if t == "f" else 0),
                     str(st.st_mtime_ns if t != "d" else 0), str(st.st_nlink if t == "f" else 1), h, tgt, xattrs(p)])

with ThreadPoolExecutor(8) as ex:
    lines = list(ex.map(describe, entries))
for l in lines:
    print(l)
for r, p, st in entries:
    if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
        inodes.setdefault(st.st_ino, []).append(r)
for g in sorted(sorted(v) for v in inodes.values()):
    print("HARDLINK|" + "|".join(g))
