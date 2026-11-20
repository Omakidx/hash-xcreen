#!/usr/bin/env python3
"""Encoder-config comparison: groups lan_<scenario>_<config>[_rN] runs and averages across repeats."""
import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyze

base = os.path.join(analyze.SPIKE, "results")
groups = {}
for d in sorted(os.listdir(base)):
    m = re.match(r"lan_(typing|scroll|video|drag)_([a-z0-9-]+?)(?:_r\d)?$", d)
    if m and os.path.exists(os.path.join(base, d, "client-summary.json")):
        groups.setdefault((m.group(1), m.group(2)), []).append(analyze.analyse(d))

print("| scenario | config | runs | total p50 (ms) | total p95 (ms) | total p99 (ms) | encode p50 / p95 (ms) | Mbps | fps | server cores | host busy 12-15 % |")
print("|---|---|---|---|---|---|---|---|---|---|---|")
for (sc, cfg), rs in sorted(groups.items()):
    avg = lambda f: sum(f(r) for r in rs) / len(rs)
    print(f"| {sc} | {cfg} | {len(rs)} | {avg(lambda r: r['st']['total'][0]):.1f} | {avg(lambda r: r['st']['total'][1]):.1f} | {avg(lambda r: r['st']['total'][2]):.1f} | "
          f"{avg(lambda r: r['st']['enc'][0]):.1f} / {avg(lambda r: r['st']['enc'][1]):.1f} | {avg(lambda r: r['mbps']):.2f} | {avg(lambda r: r['fps']):.0f} | {avg(lambda r: r['srv_cpu']):.2f} | {avg(lambda r: r['meta']['host_busy_cores_12_15_pct']):.0f} |")
