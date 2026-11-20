#!/usr/bin/env python3
"""Print the server-side congestion timeline of a run:  timeline.py <run> [step_s]"""
import csv, json, os, sys

SPIKE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
run = sys.argv[1]
step = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
d = os.path.join(SPIKE, "results", run)
rows = list(csv.DictReader(open(os.path.join(d, "server-stats.csv"))))
s = json.load(open(os.path.join(d, "client-summary.json")))
t0 = s["t0_ns"]
nxt = -1.0
for x in rows:
    t = (int(x["ts_ns"]) - t0) / 1e9
    if t < nxt or t > 41:
        continue
    nxt = t + step
    print(f"t={t:5.1f}s kbps={x['kbps']:>6} fps_cap={x['fps_cap']:>3} lag={x['lag_ms']:>4}ms rtt={x['rtt_ms']:>4}ms inflight={x['inflight']:>3} cancels={x['cancels']} cancelled_streams={x['cancelled_streams']} enc_restarts={x['enc_restarts']}")
print({k: s[k] for k in ("fps", "rx_mbps", "streams_reset", "resync_jumps", "dropped_before_key", "max_gap_stall_ms")})
