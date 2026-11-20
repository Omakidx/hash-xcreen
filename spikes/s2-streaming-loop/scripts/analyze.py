#!/usr/bin/env python3
"""Summarise results/*/ into markdown tables.  analyze.py [glob-substring ...]"""
import csv, glob, json, os, sys

SPIKE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def pct(v, p):
    if not v:
        return float("nan")
    v = sorted(v)
    k = (len(v) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(v) - 1)
    return v[f] + (v[c] - v[f]) * (k - f)


def ms(x):
    return x / 1e6


def load(run):
    d = os.path.join(SPIKE, "results", run)
    meta = json.load(open(os.path.join(d, "meta.json")))
    summ = json.load(open(os.path.join(d, "client-summary.json")))
    rows = list(csv.DictReader(open(os.path.join(d, "client-frames.csv"))))
    srv = list(csv.DictReader(open(os.path.join(d, "server-stats.csv"))))
    return meta, summ, rows, srv


def at(srv, t, key):
    """Linear interpolation of cumulative counter `key` at monotonic time t."""
    pts = [(int(r["ts_ns"]), float(r[key])) for r in srv]
    if not pts:
        return 0.0
    if t <= pts[0][0]:
        return pts[0][1]
    for (t0, v0), (t1, v1) in zip(pts, pts[1:]):
        if t0 <= t <= t1:
            return v0 + (v1 - v0) * (t - t0) / max(t1 - t0, 1)
    return pts[-1][1]


def analyse(run):
    meta, s, rows, srv = load(run)
    t0, t1 = s["t0_ns"], s["t1_ns"]
    wall = (t1 - t0) / 1e9
    r = {k: [int(x[k]) for x in rows] for k in rows[0].keys()} if rows else {}
    out = {"run": run, "wall": wall, "frames": s["frames"], "fps": s["fps"], "mbps": s["rx_mbps"], "client_cpu": s["client_cpu_cores"]}
    if rows:
        st = {
            "cap": [ms(a - b) for a, b in zip(r["t_capture"], r["t_damage"])],
            "conv": [ms(a - b) for a, b in zip(r["t_convert"], r["t_capture"])],
            "encq": [ms(a - b) for a, b in zip(r["t_enc_start"], r["t_convert"])],
            "enc": [ms(a - b) for a, b in zip(r["t_enc_end"], r["t_enc_start"])],
            "sendq": [ms(a - b) for a, b in zip(r["t_send"], r["t_enc_end"])],
            "net": [ms(a - b) for a, b in zip(r["t_recv"], r["t_send"])],
            "decq": [ms(a - b) for a, b in zip(r["t_dec_start"], r["t_recv"])],
            "dec": [ms(a - b) for a, b in zip(r["t_dec_end"], r["t_dec_start"])],
            "total": [ms(a - b) for a, b in zip(r["t_dec_end"], r["t_damage"])],
        }
        out["st"] = {k: (pct(v, 50), pct(v, 95), pct(v, 99)) for k, v in st.items()}
        out["size_kb_avg"] = sum(r["len"]) / len(r["len"]) / 1024
        out["key_frames"] = sum(1 for f in r["flags"] if f & 1)
    out["srv_cpu"] = (at(srv, t1, "proc_cpu_ns") - at(srv, t0, "proc_cpu_ns")) / 1e9 / wall
    out["cg_cpu"] = (at(srv, t1, "cg_cpu_us") - at(srv, t0, "cg_cpu_us")) / 1e6 / wall
    for k in ("captures", "frames_enc", "cancels", "cancelled_streams", "rate_changes", "enc_restarts"):
        out[k] = at(srv, t1, k) - at(srv, t0, k)
    w = [x for x in srv if t0 <= int(x["ts_ns"]) <= t1]
    out["kbps_min"] = min((int(x["kbps"]) for x in w), default=0)
    out["lag_max"] = max((int(x["lag_ms"]) for x in w), default=0)
    out["rtt_avg"] = sum(int(x["rtt_ms"]) for x in w) / max(len(w), 1)
    out["meta"] = meta
    out["summ"] = s
    return out


def main():
    pats = sys.argv[1:]
    base = os.path.join(SPIKE, "results")
    runs = sorted(os.listdir(base))
    runs += sorted(f"{d}/{x}" for d in list(runs) if os.path.isdir(os.path.join(base, d)) for x in os.listdir(os.path.join(base, d)) if os.path.isdir(os.path.join(base, d, x)))
    runs = [x for x in runs if os.path.exists(os.path.join(SPIKE, "results", x, "client-summary.json")) and (not pats or any(p in x for p in pats))]
    print("| run | fps | Mbps | cap p50/p95/p99 | conv | enc | net | dec | total p50/p95/p99 | KB/frame | srv cores | container cores | client cores | host busy 12-15 % | loadavg |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for run in runs:
        try:
            o = analyse(run)
        except Exception as e:  # noqa
            print(f"| {run} | error: {e} |")
            continue
        f = lambda k: "/".join(f"{x:.1f}" for x in o["st"][k]) if "st" in o else "-"
        print(f"| {run} | {o['fps']:.1f} | {o['mbps']:.2f} | {f('cap')} | {f('conv')} | {f('enc')} | {f('net')} | {f('dec')} | {f('total')} | {o.get('size_kb_avg', 0):.1f} | {o['srv_cpu']:.2f} | {o['cg_cpu']:.2f} | {o['client_cpu']:.2f} | {o['meta']['host_busy_cores_12_15_pct']} | {o['meta']['loadavg_mid'].split()[0]} |")


if __name__ == "__main__":
    main()
