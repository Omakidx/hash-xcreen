#!/usr/bin/env python3
"""Host idle baseline (runs on the VPS): per-state CPU percentages over N seconds from /proc/stat, loadavg, memory."""
import sys, time


def read():
    d = {}
    for l in open("/proc/stat"):
        if l.startswith("cpu"):
            f = l.split()
            d[f[0]] = list(map(int, f[1:9]))  # user nice system idle iowait irq softirq steal
    return d


n = float(sys.argv[1]) if len(sys.argv) > 1 else 30
la0 = open("/proc/loadavg").read().strip()
a = read()
time.sleep(n)
b = read()
print("loadavg_start:", la0)
print("loadavg_end:", open("/proc/loadavg").read().strip())
names = ["user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"]
for k in sorted(a):
    dv = [y - x for x, y in zip(a[k], b[k])]
    t = sum(dv) or 1
    print(k, " ".join(f"{nm}={100 * v / t:.2f}%" for nm, v in zip(names, dv)), f"busy={100 * (t - dv[3] - dv[4]) / t:.2f}%")
for l in open("/proc/meminfo"):
    if l.split(":")[0] in ("MemTotal", "MemAvailable"):
        print(l.strip())
