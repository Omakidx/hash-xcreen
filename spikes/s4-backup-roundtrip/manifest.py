#!/usr/bin/env python3
"""Build the backup manifest (architecture 9.4 step 3) from a mounted snapshot.

Runs in the worker with the snapshot mounted at /src (root of the tree is /src/rootfs).
Prints JSON on stdout. Stored as the rustic snapshot description so it travels, encrypted,
with the repository.
"""
import json, os, re, subprocess, sys, time

root = "/src/rootfs"

def kv(path):
    d = {}
    try:
        for line in open(path):
            if "=" in line:
                k, v = line.rstrip().split("=", 1)
                d[k] = v.strip('"')
    except OSError:
        pass
    return d

osr = kv(f"{root}/etc/os-release")
pk = []
try:
    cur = {}
    for line in open(f"{root}/var/lib/dpkg/status", errors="replace"):
        if line.startswith("Package: "):
            cur = {"n": line[9:].strip()}
        elif line.startswith("Version: ") and cur:
            cur["v"] = line[9:].strip()
        elif line.startswith("Status: ") and cur and "installed" in line and "not-installed" not in line:
            cur["ok"] = True
        elif line == "\n" and cur.get("ok"):
            pk.append((cur["n"], cur.get("v", "")))
            cur = {}
except OSError:
    pass

cfg = []
try:
    for line in open("/src/backup.yaml"):
        if re.match(r"\s*(volatile\.|image\.)", line):
            continue
        cfg.append(line.rstrip())
except OSError:
    pass

users = []
try:
    for line in open(f"{root}/etc/passwd"):
        f = line.split(":")
        if int(f[2]) >= 1000 and f[0] != "nobody":
            users.append({"name": f[0], "uid": int(f[2]), "home": f[5]})
except OSError:
    pass

print(json.dumps({
    "backup_format_version": 1,
    "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "distro": {"id": osr.get("ID"), "version": osr.get("VERSION_ID"), "pretty": osr.get("PRETTY_NAME")},
    "desktop": "xfce4",
    "preset": "s4-spike",
    "agent_version": os.environ.get("S4_AGENT_VERSION", "s4-spike-0"),
    "users": users,
    "package_count": len(pk),
    "packages": sorted(pk),
    "container_config": cfg,
}, separators=(",", ":")))
