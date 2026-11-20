#!/usr/bin/env python3
"""Tables for results/vps/*: pools the repeats of each group and applies the client->server clock offset.

  analyze_vps.py [--md] [substring ...]      group = tag without the trailing _rN

Clock handling. LAN runs (client in a container on the VPS) share CLOCK_MONOTONIC with the server, so the offset is 0;
the NTP-style probe estimate is still computed and printed as a validation of the method (true value 0).
WAN runs estimate offset theta = server - client from client-clock.csv (t1 client send, t2 server receive, t3 server
send, t4 client receive; theta = ((t2-t1)+(t3-t4))/2, delay = (t4-t1)-(t3-t2)). Only the 10 % lowest-delay samples are
used and a straight line theta(t) is fitted to them (drift). Worst-case error bound = min delay / 2 (all of the delay
asymmetry on one leg); for netem runs the known asymmetry (delay on the return leg only) is corrected; the empirical scatter of the selected samples is reported as well.
Client-clock timestamps are mapped to the server clock as t_client + theta(t).
"""
import csv, glob, json, math, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from analyze import pct, at  # noqa: E402

SPIKE = os.path.dirname(HERE)
BASE = os.path.join(SPIKE, "results", "vps")


def clock_fit(path, lan):
    """Return dict(theta_fn, theta_med_ms, delay_min_ms, bound_ms, drift_ppm, scatter_ms, n)."""
    rows = []
    if os.path.exists(path):
        for r in csv.DictReader(open(path)):
            t1, t2, t3, t4 = (int(r[k]) for k in ("t1", "t2", "t3", "t4"))
            rows.append((t1, ((t2 - t1) + (t3 - t4)) / 2, (t4 - t1) - (t3 - t2)))
    if not rows:
        return {"theta": lambda t: 0.0, "theta_ms": 0.0, "delay_min_ms": float("nan"), "bound_ms": float("nan"), "drift_ppm": 0.0, "scatter_ms": 0.0, "n": 0}
    rows.sort(key=lambda r: r[2])
    k = max(8, len(rows) // 10)
    sel = sorted(rows[:k])
    t0 = sel[0][0]
    xs = [(r[0] - t0) / 1e9 for r in sel]
    ys = [r[1] for r in sel]
    n = len(sel)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx if sxx > 1 else 0.0  # ns per s
    icpt = my - slope * mx
    res = [y - (icpt + slope * x) for x, y in zip(xs, ys)]
    scatter = math.sqrt(sum(e * e for e in res) / n)
    fn = (lambda t: icpt + slope * (t - t0) / 1e9)
    return {"theta": fn, "theta_ms": my / 1e6, "delay_min_ms": rows[0][2] / 1e6, "bound_ms": rows[0][2] / 2e6,
            "drift_ppm": slope / 1e3, "scatter_ms": scatter / 1e6, "n": len(rows)}


def load(run):
    d = os.path.join(BASE, run)
    meta = json.load(open(os.path.join(d, "meta.json")))
    summ = json.load(open(os.path.join(d, "client-summary.json")))
    rows = list(csv.DictReader(open(os.path.join(d, "client-frames.csv"))))
    srv = list(csv.DictReader(open(os.path.join(d, "server-stats.csv"))))
    clk = clock_fit(os.path.join(d, "client-clock.csv"), meta["client"] == "lan")
    return meta, summ, rows, srv, clk


def analyse(run):
    meta, s, rows, srv, clk = load(run)
    lan = meta["client"] == "lan"
    # netem delays only the server->client direction (container egress), so the probe's return leg is longer by the
    # configured delay and the NTP estimate is low by delay/2: add it back (exact for fixed delays; for `mobile`,
    # whose delay is 40 ms +- 30 ms, the lowest-delay samples carry a smaller delay, so the result is only indicative).
    m = re.search(r"delay (\d+)ms", meta.get("netem") or "")
    bias = int(m.group(1)) * 1e6 / 2 if (m and not lan) else 0.0
    off = (lambda t: 0.0) if lan else (lambda t: clk["theta"](t) + bias)
    t0, t1 = s["t0_ns"], s["t1_ns"]
    wall = (t1 - t0) / 1e9
    st = {k: [] for k in ("cap", "conv", "encq", "enc", "sendq", "net", "decq", "dec", "total")}
    sizes = 0
    for r in rows:
        v = {k: int(x) for k, x in r.items()}
        o = off(v["t_recv"])
        st["cap"].append((v["t_capture"] - v["t_damage"]) / 1e6)
        st["conv"].append((v["t_convert"] - v["t_capture"]) / 1e6)
        st["encq"].append((v["t_enc_start"] - v["t_convert"]) / 1e6)
        st["enc"].append((v["t_enc_end"] - v["t_enc_start"]) / 1e6)
        st["sendq"].append((v["t_send"] - v["t_enc_end"]) / 1e6)
        st["net"].append((v["t_recv"] + o - v["t_send"]) / 1e6)
        st["decq"].append((v["t_dec_start"] - v["t_recv"]) / 1e6)
        st["dec"].append((v["t_dec_end"] - v["t_dec_start"]) / 1e6)
        st["total"].append((v["t_dec_end"] + o - v["t_damage"]) / 1e6)
        sizes += v["len"]
    ts0 = t0 + off(t0)
    ts1 = t1 + off(t1)
    out = {"run": run, "meta": meta, "summ": s, "clk": clk, "st": st, "wall": wall, "n": len(rows)}
    out["kb_frame"] = sizes / max(len(rows), 1) / 1024
    out["srv_cpu"] = (at(srv, ts1, "proc_cpu_ns") - at(srv, ts0, "proc_cpu_ns")) / 1e9 / wall
    out["cg_cpu"] = (at(srv, ts1, "cg_cpu_us") - at(srv, ts0, "cg_cpu_us")) / 1e6 / wall
    w = [x for x in srv if ts0 <= int(x["ts_ns"]) <= ts1]
    out["rtt_ms"] = sum(int(x["rtt_ms"]) for x in w) / max(len(w), 1)
    out["kbps_min"] = min((int(x["kbps"]) for x in w), default=0)
    for k in ("cancels", "cancelled_streams", "enc_restarts"):
        out[k] = at(srv, ts1, k) - at(srv, ts0, k)
    return out


def group_key(run):
    return re.sub(r"_r\d+$", "", run)


def fmt3(v):
    return "/".join(f"{pct(v, p):.1f}" for p in (50, 95, 99)) if v else "-"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    runs = sorted(d for d in os.listdir(BASE) if os.path.exists(os.path.join(BASE, d, "client-summary.json")) and (not args or any(p in d for p in args)))
    groups = {}
    for r in runs:
        try:
            groups.setdefault(group_key(r), []).append(analyse(r))
        except Exception as e:  # noqa
            print(f"<!-- {r}: {e} -->")
    print("| group | runs | fps | Mbit/s | cap | conv | enc | net | dec | **total p50/p95/p99** | per-run total p95 | KB/frame | server cores | container cores | client cores | VPS load / steal % |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for g, rs in groups.items():
        pooled = {k: [x for r in rs for x in r["st"][k]] for k in rs[0]["st"]}
        mean = lambda f: sum(f(r) for r in rs) / len(rs)  # noqa: E731
        p95s = "/".join(f"{pct(r['st']['total'], 95):.1f}" if r["st"]["total"] else "-" for r in rs)
        loads = "/".join(r["meta"]["vps_loadavg_mid"].split()[0] for r in rs)
        steal = max(r["meta"]["vps_steal_pct"] for r in rs)
        tot = fmt3(pooled["total"]) if pooled["total"] else f"0 frames"
        print(f"| {g} | {len(rs)} | {mean(lambda r: r['summ']['fps']):.1f} | {mean(lambda r: r['summ']['rx_mbps']):.2f} | {fmt3(pooled['cap'])} | {fmt3(pooled['conv'])} | {fmt3(pooled['enc'])} | {fmt3(pooled['net'])} | {fmt3(pooled['dec'])} | **{tot}** | {p95s} | {mean(lambda r: r['kb_frame']):.1f} | {mean(lambda r: r['srv_cpu']):.2f} | {mean(lambda r: r['cg_cpu']):.2f} | {mean(lambda r: r['summ']['client_cpu_cores']):.2f} | {loads} / {steal:.2f} |")
    print()
    print("Clock probes (offset = server - client; validation for LAN runs, true value 0):")
    print()
    print("| group | runs | offset ms (per run) | min delay ms | worst-case bound ms | scatter ms | drift ppm | samples |")
    print("|---|---|---|---|---|---|---|---|")
    for g, rs in groups.items():
        c = [r["clk"] for r in rs]
        if not c[0]["n"]:
            continue
        print(f"| {g} | {len(rs)} | {', '.join(f'{x['theta_ms']:.2f}' for x in c)} | {min(x['delay_min_ms'] for x in c):.2f} | {max(x['bound_ms'] for x in c):.2f} | {max(x['scatter_ms'] for x in c):.2f} | {', '.join(f'{x['drift_ppm']:.1f}' for x in c)} | {c[0]['n']} |")


if __name__ == "__main__":
    main()
