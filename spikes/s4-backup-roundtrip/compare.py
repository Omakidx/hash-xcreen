#!/usr/bin/env python3
"""Compare two treesum.py outputs: source snapshot (excludes already removed) vs restored tree.

usage: compare.py SRC.txt RESTORED.txt [EXCLUDE_LIST]
Expected differences, reported separately and not counted as failures: extra entries that are
the recreated mount points (/proc /sys /dev /run /tmp /var/tmp) or things below them, and
directory mtimes (not compared by treesum). Any other missing, extra or differing line is a
failure. Exit code 0 on success.
"""
import sys

src, dst = sys.argv[1], sys.argv[2]
excl = [l.strip() for l in open(sys.argv[3])] if len(sys.argv) > 3 else []

def load(p):
    d, hl = {}, []
    for l in open(p, errors="replace"):
        l = l.rstrip("\n")
        if l.startswith("HARDLINK|"):
            hl.append(l)
        else:
            d[l.split("|", 1)[0]] = l
    return d, hl

a, ah = load(src)
b, bh = load(dst)
mount = ("/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp")
missing = sorted(set(a) - set(b))
extra = sorted(k for k in set(b) - set(a) if not k.startswith(mount) and not any(k.startswith(e + "/") or k == e for e in excl))
extra_ok = sorted(k for k in set(b) - set(a) if k not in extra)
diff = sorted(k for k in set(a) & set(b) if a[k] != b[k])
# Entries below excluded dirs that exist in dst only as recreated empty mountpoints are fine.
print(f"source entries      : {len(a)}")
print(f"restored entries    : {len(b)}")
print(f"identical entries   : {len(set(a) & set(b)) - len(diff)}")
print(f"missing in restored : {len(missing)}")
print(f"different           : {len(diff)}")
print(f"unexpected extra    : {len(extra)}")
print(f"expected extra (recreated mount points): {extra_ok}")
print(f"hard-link groups    : src={len(ah)} restored={len(bh)} equal={sorted(ah) == sorted(bh)}")
for k in missing[:15]:
    print("MISSING", k)
for k in diff[:15]:
    print("DIFF src ", a[k][:300])
    print("DIFF dst ", b[k][:300])
for k in extra[:15]:
    print("EXTRA", k)
ok = not missing and not diff and not extra and sorted(ah) == sorted(bh)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
