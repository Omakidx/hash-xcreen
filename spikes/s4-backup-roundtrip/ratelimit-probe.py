#!/usr/bin/env python3
"""Try to provoke a REAL Drive rate-limit reply (429, or 403 rateLimitExceeded / userRateLimitExceeded) by
creating empty folders in bursts with many threads, inside a probe folder under the spike folder, then delete them.
Prints a histogram of status codes and (reason, message) pairs. Uses drivectl's token handling; prints no credentials.

usage: ratelimit-probe.py [threads=16] [count=300]
"""
import json, sys, threading, time, collections
sys.path.insert(0, __import__("os").path.dirname(__file__))
import drivectl as d

threads = int(sys.argv[1]) if len(sys.argv) > 1 else 16
count = int(sys.argv[2]) if len(sys.argv) > 2 else 300
d.access()  # refresh once, before the burst

st, root = d.api("POST", "/files", {"fields": "id"}, json.dumps(
    {"name": "ratelimit-probe", "mimeType": "application/vnd.google-apps.folder"}).encode(),
    {"Content-Type": "application/json"})
assert st == 200, (st, root)
pid = root["id"]
hist, ids, lock = collections.Counter(), [], threading.Lock()
retry_after = []


def worker(n):
    for i in range(n):
        t0 = time.time()
        st, r = d.api("POST", "/files", {"fields": "id"}, json.dumps(
            {"name": f"p{threading.get_ident()}-{i}", "mimeType": "application/vnd.google-apps.folder",
             "parents": [pid]}).encode(), {"Content-Type": "application/json"})
        with lock:
            if st == 200:
                hist[(200, "", "")] += 1
                ids.append(r["id"])
            else:
                e = r.get("error", {})
                hist[(st, (e.get("errors") or [{}])[0].get("reason", ""), e.get("message", r.get("raw", ""))[:80])] += 1


t = time.time()
ts = [threading.Thread(target=worker, args=(count // threads,)) for _ in range(threads)]
[x.start() for x in ts]
[x.join() for x in ts]
el = time.time() - t
print(json.dumps({"threads": threads, "requests": count - count % threads, "seconds": round(el, 1),
                  "req_per_s": round((count - count % threads) / el, 1),
                  "replies": [{"status": k[0], "reason": k[1], "message": k[2], "n": v} for k, v in hist.items()]}))


def rm(batch):
    for i in batch:
        d.api("DELETE", f"/files/{i}")


chunks = [ids[i::threads] for i in range(threads)]
ts = [threading.Thread(target=rm, args=(c,)) for c in chunks]
[x.start() for x in ts]
[x.join() for x in ts]
print(json.dumps({"cleanup_http": d.api("DELETE", f"/files/{pid}")[0]}))
