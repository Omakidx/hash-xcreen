#!/usr/bin/env python3
"""Congestion-control table for the constrained-profile runs:  cc_table.py [substring ...]"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyze

base = os.path.join(analyze.SPIKE, "results")
pats = sys.argv[1:] or ["rtt", "mobile", "recovery"]
print("| run | fps | Mbps | min target kbps | cancel events | streams cancelled | encoder restarts | client resync jumps | frames dropped before key | max reorder stall (ms) | total p50 / p95 (ms) |")
print("|---|---|---|---|---|---|---|---|---|---|---|")
for d in sorted(os.listdir(base)):
    if not any(p in d for p in pats) or not os.path.exists(os.path.join(base, d, "client-summary.json")):
        continue
    o = analyze.analyse(d)
    s = o["summ"]
    print(f"| {d} | {o['fps']:.1f} | {o['mbps']:.2f} | {o['kbps_min']} | {o['cancels']:.0f} | {o['cancelled_streams']:.0f} | {o['enc_restarts']:.0f} | {s['resync_jumps']} | {s['dropped_before_key']} | {s['max_gap_stall_ms']:.0f} | {o['st']['total'][0]:.0f} / {o['st']['total'][1]:.0f} |")
