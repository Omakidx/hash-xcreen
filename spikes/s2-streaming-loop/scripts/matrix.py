#!/usr/bin/env python3
"""Run the whole S2 measurement matrix sequentially (resumable: skips runs whose meta.json says clean)."""
import json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SPIKE = os.path.dirname(HERE)
ACTIVE = ["typing", "scroll", "video", "drag"]

runs = []
# LAN, default config, all scenarios
runs.append(("lan", "idle", "base", 30))
for sc in ACTIVE:
    runs.append(("lan", sc, "base", 20))
# LAN encoder configuration comparison (trimmed after the shared-host constraint)
for cfg in ["t2", "t1", "noir"]:
    for sc in ACTIVE:
        runs.append(("lan", sc, cfg, 20))
for sc in ["typing", "scroll"]:
    runs.append(("lan", sc, "superfast", 20))
# Constrained profiles, default config (plus congestion control off for contrast on video)
runs.append(("rtt50", "typing", "base", 20))
for prof in ["rtt50", "rtt150-loss", "mobile"]:
    for sc in ["scroll", "video", "drag"]:
        runs.append((prof, sc, "base", 20))
    runs.append((prof, "video", "nocc", 20))

only = sys.argv[1:]
for prof, sc, cfg, dur in runs:
    tag = f"{prof}_{sc}_{cfg}"
    if only and not any(o in tag for o in only):
        continue
    meta = os.path.join(SPIKE, "results", tag, "meta.json")
    if os.path.exists(meta) and not json.load(open(meta)).get("noisy", True):
        continue
    subprocess.run([sys.executable, os.path.join(HERE, "run.py"), "--profile", prof, "--scenario", sc, "--config", cfg,
                    "--dur", str(dur), "--tag", tag, "--wait", "60", "--retries", "2"], check=False)
