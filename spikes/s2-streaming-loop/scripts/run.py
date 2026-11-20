#!/usr/bin/env python3
"""Spike S2 measurement harness (runs on the host).

  run.py --profile lan --scenario typing --config base [--dur 20] [--tag x]

Starts s2-server in the container, applies a tc netem profile inside the container, runs the
scenario with xdotool, runs s2-client on the host pinned to cores 0-3, and stores everything
under results/<tag>/. See scripts/analyze.py for the tables.
"""
import argparse, json, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
SPIKE = os.path.dirname(HERE)
C = "s2-desktop"

PROFILES = {
    "lan": None,
    # video direction is the container egress, so delay here equals the RTT contribution
    "rtt50": "delay 50ms rate 50mbit limit 1000",
    "rtt150-loss": "delay 150ms rate 10mbit loss 1% limit 1000",
    "mobile": "delay 40ms 30ms distribution normal loss 0.5% rate 20mbit limit 1000",
}

CONFIGS = {
    # name -> server args
    "base": [],  # ultrafast, 4 sliced threads, intra refresh on, crf 23, 20 Mbps VBV cap, 60 fps
    "t2": ["--threads", "2"],
    "t1": ["--threads", "1"],
    "noir": ["--intra-refresh", "0"],
    "t1-noir": ["--threads", "1", "--intra-refresh", "0"],
    "nocc": ["--cc", "0"],
    "superfast": ["--preset", "superfast"],
    "fps120": ["--fps", "120"],
    "nocursor": ["--cursor", "0"],
    "k10": ["--kbps", "10000"],
    "k50": ["--kbps", "50000"],
}


def incus(*args, check=True, capture=True, **kw):
    cmd = ["sg", "incus-admin", "-c", " ".join(__import__("shlex").quote(a) for a in ("incus",) + args)]
    return subprocess.run(cmd, check=check, capture_output=capture, text=True, **kw)


def cexec(cmd, user=None, check=True):
    args = ["exec", C, "--"]
    if user:
        args += ["su", user, "-c", cmd]
    else:
        args += ["bash", "-c", cmd]
    return incus(*args, check=check)


def read_stat():
    cpus = {}
    for line in open("/proc/stat"):
        if line.startswith("cpu") and line[3].isdigit():
            f = line.split()
            v = list(map(int, f[1:]))
            idle = v[3] + v[4]
            cpus[int(f[0][3:])] = (sum(v), idle)
    return cpus


def busy(a, b, ids):
    t = sum(b[i][0] - a[i][0] for i in ids)
    idle = sum(b[i][1] - a[i][1] for i in ids)
    return 100.0 * (t - idle) / t if t else 0.0


def wait_quiet(limit_s, thr_sel=40.0, thr_all=45.0):
    """Block until cores 12-15 and the whole host are quiet (other agents are compiling)."""
    end = time.time() + limit_s
    while time.time() < end:
        a = read_stat()
        time.sleep(2)
        b = read_stat()
        if busy(a, b, [12, 13, 14, 15]) < thr_sel and busy(a, b, list(range(16))) < thr_all:
            return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default="lan")
    ap.add_argument("--scenario", default="typing")
    ap.add_argument("--config", default="base")
    ap.add_argument("--dur", type=float, default=20)
    ap.add_argument("--warmup", type=float, default=3)
    ap.add_argument("--tag", default=None)
    ap.add_argument("--extra", default="", help="extra server args")
    ap.add_argument("--wait", type=float, default=60, help="max seconds to wait for a quiet host before each attempt")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--clear-at", type=float, default=0, help="seconds into the measured window at which netem is removed (recovery test)")
    a = ap.parse_args()
    for attempt in range(1, a.retries + 1):
        quiet = wait_quiet(a.wait)
        meta = run_once(a)
        meta["attempt"] = attempt
        meta["quiet_before"] = quiet
        noisy = meta["host_busy_cores_12_15_pct"] > 75 or meta["host_busy_all_pct"] > 80 or meta["client_rc"] != 0
        meta["noisy"] = noisy
        json.dump(meta, open(os.path.join(SPIKE, "results", meta["tag"], "meta.json"), "w"), indent=1)
        print(meta["tag"], "attempt", attempt, "noisy" if noisy else "clean", meta["host_busy_cores_12_15_pct"], meta["host_busy_all_pct"], meta["loadavg_mid"], flush=True)
        if not noisy:
            break


def run_once(a):
    tag = a.tag or f"{a.profile}_{a.scenario}_{a.config}"
    out = os.path.join(SPIKE, "results", tag)
    os.makedirs(out, exist_ok=True)

    ip = incus("list", C, "-f", "csv", "-c", "4").stdout.split()[0]
    # network profile (container egress == server->client video direction)
    cexec("tc qdisc del dev eth0 root 2>/dev/null; true")
    if PROFILES[a.profile]:
        cexec(f"tc qdisc add dev eth0 root netem {PROFILES[a.profile]}")

    # server
    cexec("pkill s2-server; sleep 0.5; true")
    sargs = " ".join(CONFIGS[a.config] + a.extra.split())
    cexec(f"cd /home/desk && DISPLAY=:10 S2_DEBUG=1 nohup ./s2-server --stats /tmp/st.csv {sargs} > /tmp/server.log 2>&1 &", user="desk")
    for _ in range(50):
        if "listening" in cexec("cat /tmp/server.log", check=False).stdout:
            break
        time.sleep(0.2)

    cexec(f"/home/desk/scenario.sh prep {a.scenario}", user="desk")
    time.sleep(1)
    total = a.warmup + a.dur
    la0 = open("/proc/loadavg").read().strip()
    s0 = read_stat()
    cl = subprocess.Popen(
        ["taskset", "-c", "0-3", os.path.join(SPIKE, "target/release/s2-client"), "--server", f"{ip}:4433",
         "--warmup", str(a.warmup), "--duration", str(a.dur), "--out", os.path.join(out, "client")],
        stdout=open(os.path.join(out, "client.log"), "w"), stderr=subprocess.STDOUT)
    time.sleep(0.7)
    sc = subprocess.Popen(["sg", "incus-admin", "-c", f"incus exec {C} -- su desk -c '/home/desk/scenario.sh run {a.scenario} {int(total + 4)}'"])
    time.sleep(a.warmup + 0.7)
    s1 = read_stat()  # start of the measured window (approx.)
    la_mid = open("/proc/loadavg").read().strip()
    if a.clear_at:
        time.sleep(a.clear_at)
        cexec("tc qdisc del dev eth0 root 2>/dev/null; true")
        time.sleep(max(a.dur - a.clear_at, 0))
    else:
        time.sleep(a.dur)
    s2 = read_stat()
    la1 = open("/proc/loadavg").read().strip()
    try:
        rc = cl.wait(timeout=30)
    except subprocess.TimeoutExpired:
        cl.kill()
        rc = -9
    sc.wait(timeout=30)
    incus("file", "pull", f"{C}/tmp/st.csv", os.path.join(out, "server-stats.csv"))
    incus("file", "pull", f"{C}/tmp/server.log", os.path.join(out, "server.log"))
    cexec("pkill s2-server; pkill -x mpv; tc qdisc del dev eth0 root 2>/dev/null; true")
    meta = {
        "profile": a.profile, "scenario": a.scenario, "config": a.config, "extra": a.extra, "client_rc": rc,
        "loadavg_start": la0, "loadavg_mid": la_mid, "loadavg_end": la1,
        "host_busy_cores_12_15_pct": round(busy(s1, s2, [12, 13, 14, 15]), 1),
        "host_busy_cores_0_3_pct": round(busy(s1, s2, [0, 1, 2, 3]), 1),
        "host_busy_all_pct": round(busy(s1, s2, list(range(16))), 1),
        "netem": PROFILES[a.profile], "server_args": sargs, "tag": tag,
    }
    return meta


if __name__ == "__main__":
    main()
