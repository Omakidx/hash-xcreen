#!/usr/bin/env python3
"""Spike S2 VPS harness. One run = fresh s2-server in container s2-desktop + one s2-client + one scenario.

  run_vps.py --client lan   --scenario typing --config fps120 --tag A1_typing_fps120_r1      (runs ON the VPS)
  run_vps.py --client local --ssh administrator@HOST --addr HOST:47433 --scenario video ...  (runs on the client machine)

--client lan   : client in container s2-client on the VPS (over hxbr0). CLOCK_MONOTONIC is the same clock as the server's.
--client local : client is a local process; every server-side command goes through ssh, the server is reached through
                 an Incus UDP proxy device (see vps-ctl.sh). Clocks differ: analyze_vps.py applies the offset estimated
                 from the NTP-style datagram probes the client logs (client-clock.csv).

Results land in results/vps/<tag>/ (meta.json, client-*.csv/json, server-stats.csv, server.log, optional dump tarballs).
"""
import argparse, json, os, shlex, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
SPIKE = os.path.dirname(HERE)
SRV, CLI = "s2-desktop", "s2-client"

PROFILES = {
    "lan": None,
    "rtt50": "delay 50ms rate 50mbit limit 1000",
    "rtt150-loss": "delay 150ms rate 10mbit loss 1% limit 1000",
    "mobile": "delay 40ms 30ms distribution normal loss 0.5% rate 20mbit limit 1000",
}
CONFIGS = {
    "base": [],  # ultrafast, 4 sliced threads, intra refresh, crf 23, 20 Mbit/s VBV cap, 60 fps pacing cap
    "fps120": ["--fps", "120"],
    "fps120-noir": ["--fps", "120", "--intra-refresh", "0"],
    "fps120-t1": ["--fps", "120", "--threads", "1", "--sliced", "0"],
    "fps120-t2": ["--fps", "120", "--threads", "2"],
    "fps120-vui": ["--fps", "120", "--vui", "1"],
    "nocc": ["--fps", "120", "--cc", "0"],
}

SSH = None  # "user@host" when the server is remote


def srv(cmd, check=True, capture=True, text=True, **kw):
    """Run a command on the VPS (locally when this script runs there, via ssh otherwise)."""
    if SSH:
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=10", SSH, " ".join(shlex.quote(c) for c in cmd)]
    return subprocess.run(cmd, check=check, capture_output=capture, text=text, **kw)


def srv_popen(cmd, **kw):
    if SSH:
        cmd = ["ssh", "-o", "BatchMode=yes", SSH, " ".join(shlex.quote(c) for c in cmd)]
    return subprocess.Popen(cmd, **kw)


def cexec(c, cmd, user=None, check=True, text=True):
    args = ["sudo", "-n", "incus", "exec", c, "--"]
    args += (["su", user, "-c", cmd] if user else ["bash", "-c", cmd])
    return srv(args, check=check, text=text)


def stop_units():
    """Stop the transient units of a run (server, apps, scenario driver) and clear failed state."""
    cexec(SRV, "systemctl stop s2-srv s2-app s2-scn 2>/dev/null; systemctl reset-failed 2>/dev/null; true")
    srv(["sudo", "-n", "bash", "/home/administrator/s2/scripts/vps-kill.sh"])
    time.sleep(0.5)


def pull(c, path, dest, check=True):
    r = srv(["sudo", "-n", "incus", "exec", c, "--", "cat", path], check=check, text=False)
    if r.returncode == 0:
        open(dest, "wb").write(r.stdout)
    return r.returncode == 0


def parse_stat(txt):
    cpus = {}
    for line in txt.splitlines():
        if line.startswith("cpu") and line[3].isdigit():
            f = line.split()
            v = list(map(int, f[1:9]))
            cpus[int(f[0][3:])] = v  # user nice system idle iowait irq softirq steal
    return cpus


def read_stat():
    return parse_stat(srv(["cat", "/proc/stat"]).stdout)


def local_stat():
    return parse_stat(open("/proc/stat").read())


def busy(a, b, ids=None):
    ids = ids or list(a.keys())
    dv = [sum(b[i][k] - a[i][k] for i in ids) for k in range(8)]
    t = sum(dv) or 1
    return {"busy": 100.0 * (t - dv[3] - dv[4]) / t, "steal": 100.0 * dv[7] / t, "iowait": 100.0 * dv[4] / t}


def loadavg():
    return srv(["cat", "/proc/loadavg"]).stdout.strip()


def main():
    global SSH
    ap = argparse.ArgumentParser()
    ap.add_argument("--client", choices=["lan", "local"], default="lan")
    ap.add_argument("--ssh", default=None)
    ap.add_argument("--addr", default=None, help="server addr for --client local (host:port of the proxy device)")
    ap.add_argument("--profile", default="lan")
    ap.add_argument("--scenario", default="typing")
    ap.add_argument("--config", default="fps120")
    ap.add_argument("--dur", type=float, default=20)
    ap.add_argument("--warmup", type=float, default=3)
    ap.add_argument("--tag", default=None)
    ap.add_argument("--label", default="", help="free text, e.g. the CPU sharing setup, stored in meta.json")
    ap.add_argument("--extra", default="", help="extra server args")
    ap.add_argument("--dump", action="store_true", help="fidelity run: dump source (server) and decoded (client) frames")
    ap.add_argument("--dump-every", type=int, default=40)
    ap.add_argument("--client-cpus", default="", help="taskset list for a local client")
    a = ap.parse_args()
    SSH = a.ssh
    tag = a.tag or f"{a.client}_{a.profile}_{a.scenario}_{a.config}"
    out = os.path.join(SPIKE, "results", "vps", tag)
    os.makedirs(out, exist_ok=True)

    cexec(SRV, "tc qdisc del dev eth0 root 2>/dev/null; true")
    if PROFILES[a.profile]:
        cexec(SRV, f"tc qdisc add dev eth0 root netem {PROFILES[a.profile]}")
    stop_units()
    cexec(SRV, "rm -rf /tmp/dump /tmp/st.csv /tmp/server.log /tmp/s2-ready; mkdir -p /tmp/dump; chmod 777 /tmp/dump; touch /tmp/server.log; chmod 666 /tmp/server.log; true")
    if a.client == "lan":
        cexec(CLI, "pkill -x s2-client; rm -rf /tmp/c; mkdir -p /tmp/c; true")
        ip = srv(["sudo", "-n", "incus", "list", SRV, "-f", "csv", "-c", "4"]).stdout.split()[0]
        addr = f"{ip}:4433"
    else:
        addr = a.addr

    sargs = CONFIGS[a.config] + a.extra.split()
    if a.dump:
        sargs += ["--dump", "/tmp/dump", "--dump-every", str(a.dump_every)]
    sargs = " ".join(sargs)
    cexec(SRV, f"systemd-run -q --unit=s2-srv --uid=desk -E DISPLAY=:10 -E S2_DEBUG=1 -p WorkingDirectory=/home/desk "
               f"-p StandardOutput=file:/tmp/server.log -p StandardError=file:/tmp/server.log /home/desk/s2-server --stats /tmp/st.csv {sargs}")
    for _ in range(50):
        if "listening" in cexec(SRV, "cat /tmp/server.log", check=False).stdout:
            break
        time.sleep(0.2)
    cexec(SRV, f"systemd-run -q --unit=s2-app --uid=desk -E DISPLAY=:10 -E HOLD=1 /home/desk/scenario.sh prep {a.scenario}")
    for _ in range(100):
        if cexec(SRV, "test -e /tmp/s2-ready", check=False).returncode == 0:
            break
        time.sleep(0.2)
    time.sleep(1)

    total = a.warmup + a.dur
    cargs = ["--server", addr, "--warmup", str(a.warmup), "--duration", str(a.dur)]
    if a.client == "lan":
        cdir = "/tmp/c"
        cargs += ["--out", f"{cdir}/client"] + (["--dump", f"{cdir}", "--dump-every", str(a.dump_every)] if a.dump else [])
        ccmd = ["sudo", "-n", "incus", "exec", CLI, "--", "/root/s2-client"] + cargs
        if SSH:
            raise SystemExit("--client lan must run on the VPS")
        cl = subprocess.Popen(ccmd, stdout=open(os.path.join(out, "client.log"), "w"), stderr=subprocess.STDOUT)
    else:
        os.makedirs(os.path.join(out, "cdump"), exist_ok=True)
        cargs += ["--out", os.path.join(out, "client")] + (["--dump", os.path.join(out, "cdump"), "--dump-every", str(a.dump_every)] if a.dump else [])
        pre = ["taskset", "-c", a.client_cpus] if a.client_cpus else []
        cl = subprocess.Popen(pre + [os.path.join(SPIKE, "target/release/s2-client")] + cargs,
                              stdout=open(os.path.join(out, "client.log"), "w"), stderr=subprocess.STDOUT)
    la0 = loadavg()
    local_la0 = open("/proc/loadavg").read().strip()
    time.sleep(0.7)
    sc = srv_popen(["sudo", "-n", "incus", "exec", SRV, "--", "systemd-run", "-q", "--wait", "--collect", "--unit=s2-scn", "--uid=desk", "-E", "DISPLAY=:10",
                    "/home/desk/scenario.sh", "run", a.scenario, str(int(total + 4))])
    time.sleep(a.warmup + 0.7)
    s1 = read_stat()
    ls1 = local_stat() if a.client == "local" else None
    la_mid = loadavg()
    local_la_mid = open("/proc/loadavg").read().strip()
    time.sleep(a.dur)
    s2 = read_stat()
    ls2 = local_stat() if a.client == "local" else None
    la1 = loadavg()
    local_la1 = open("/proc/loadavg").read().strip()
    try:
        rc = cl.wait(timeout=40)
    except subprocess.TimeoutExpired:
        cl.kill()
        rc = -9
    try:
        sc.wait(timeout=40)
    except subprocess.TimeoutExpired:
        sc.kill()

    pull(SRV, "/tmp/st.csv", os.path.join(out, "server-stats.csv"))
    pull(SRV, "/tmp/server.log", os.path.join(out, "server.log"))
    if a.client == "lan":
        for ext in ("frames.csv", "summary.json", "clock.csv"):
            pull(CLI, f"/tmp/c/client-{ext}", os.path.join(out, f"client-{ext}"), check=False)
    if a.dump:
        srv_tar = os.path.join(out, "src-dump.tgz")
        r = srv(["sudo", "-n", "incus", "exec", SRV, "--", "tar", "czf", "-", "-C", "/tmp/dump", "."], text=False)
        open(srv_tar, "wb").write(r.stdout)
        if a.client == "lan":
            r = srv(["sudo", "-n", "incus", "exec", CLI, "--", "bash", "-c", "cd /tmp/c && tar czf - dec-*"], text=False)
            open(os.path.join(out, "dec-dump.tgz"), "wb").write(r.stdout)
        else:
            subprocess.run(["tar", "czf", os.path.join(out, "dec-dump.tgz"), "-C", os.path.join(out, "cdump"), "."], check=True)
            subprocess.run(["rm", "-rf", os.path.join(out, "cdump")])
    stop_units()
    cexec(SRV, "tc qdisc del dev eth0 root 2>/dev/null; rm -rf /tmp/dump; true")
    if a.client == "lan":
        cexec(CLI, "rm -rf /tmp/c; true")

    vb = busy(s1, s2)
    meta = {
        "client": a.client, "profile": a.profile, "scenario": a.scenario, "config": a.config, "extra": a.extra,
        "label": a.label, "client_rc": rc, "tag": tag, "server_args": sargs, "netem": PROFILES[a.profile],
        "vps_loadavg_start": la0, "vps_loadavg_mid": la_mid, "vps_loadavg_end": la1,
        "vps_busy_all_pct": round(vb["busy"], 1), "vps_steal_pct": round(vb["steal"], 2), "vps_iowait_pct": round(vb["iowait"], 2),
        "vps_busy_per_core_pct": [round(busy(s1, s2, [i])["busy"], 1) for i in sorted(s1)],
        "local_loadavg_start": local_la0, "local_loadavg_mid": local_la_mid, "local_loadavg_end": local_la1,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    if ls1:
        lb = busy(ls1, ls2)
        meta["local_busy_all_pct"] = round(lb["busy"], 1)
        meta["local_ncpu"] = len(ls1)
    json.dump(meta, open(os.path.join(out, "meta.json"), "w"), indent=1)
    print(tag, "rc", rc, "vps busy", meta["vps_busy_all_pct"], "steal", meta["vps_steal_pct"], "load", la_mid.split()[0], flush=True)


if __name__ == "__main__":
    main()
