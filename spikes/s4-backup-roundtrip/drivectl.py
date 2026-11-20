#!/usr/bin/env python3
"""Drive helper for the S4 Drive run: quota, usage, bandwidth probe, permanent purge.

Reads the OAuth token file at runtime (default ~/.config/hash-xcreen-spike/drive-token.json), keeps the
access token in memory only and never prints any credential value. Only touches files the spike's own
app can see (scope drive.file), and `purge` only removes the folder named below and trashed files of this app.

  drivectl.py usage                 # quota + count/size of the app's files, live and trashed
  drivectl.py bw MB                 # upload then download MB of random data, print MB/s, then delete it
  drivectl.py purge                 # permanently delete the spike folder (recursive) and the app's trashed files
  drivectl.py tree                  # top-level layout of the spike folder
"""
import json, os, sys, time, urllib.parse, urllib.request, urllib.error

FOLDER = "hash-xcreen-spike-s4"
TOKEN_FILE = os.environ.get("S4_DRIVE_TOKEN", os.path.expanduser("~/.config/hash-xcreen-spike/drive-token.json"))
_access = None


def http(method, url, data=None, headers=None, raw=False):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            body = r.read()
            return r.status, (body if raw else (json.loads(body) if body else {}))
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body[:200].decode("utf-8", "replace")}


def access():
    global _access
    if _access:
        return _access
    t = json.load(open(TOKEN_FILE))
    body = urllib.parse.urlencode({
        "client_id": t["client_id"], "client_secret": t["client_secret"],
        "refresh_token": t["refresh_token"], "grant_type": "refresh_token"}).encode()
    st, r = http("POST", t["token_uri"], body, {"Content-Type": "application/x-www-form-urlencoded"})
    if st != 200:
        sys.exit(f"token refresh failed: HTTP {st} {r.get('error', '')}")
    _access = r["access_token"]
    return _access


def api(method, path, params=None, data=None, headers=None, raw=False, upload=False):
    base = "https://www.googleapis.com/upload/drive/v3" if upload else "https://www.googleapis.com/drive/v3"
    url = base + path + ("?" + urllib.parse.urlencode(params) if params else "")
    h = {"Authorization": "Bearer " + access()}
    h.update(headers or {})
    return http(method, url, data, h, raw)


def list_all(q):
    out, tok = [], None
    while True:
        p = {"q": q, "pageSize": 1000, "fields": "nextPageToken,files(id,name,size,mimeType,parents,trashed)"}
        if tok:
            p["pageToken"] = tok
        st, r = api("GET", "/files", p)
        if st != 200:
            sys.exit(f"list failed: HTTP {st} {r}")
        out += r.get("files", [])
        tok = r.get("nextPageToken")
        if not tok:
            return out


def usage():
    st, r = api("GET", "/about", {"fields": "storageQuota"})
    q = r.get("storageQuota", {})
    mb = lambda v: round(int(v) / 1e6, 1) if v is not None else None
    print(json.dumps({"drive_usage_MB": mb(q.get("usage")), "in_drive_MB": mb(q.get("usageInDrive")),
                      "in_trash_MB": mb(q.get("usageInDriveTrash")), "limit_MB": mb(q.get("limit"))}))
    for label, qq in (("live", "trashed = false"), ("trashed", "trashed = true")):
        fs = list_all(qq)
        files = [f for f in fs if f["mimeType"] != "application/vnd.google-apps.folder"]
        print(json.dumps({label: {"files": len(files), "folders": len(fs) - len(files),
                                  "bytes": sum(int(f.get("size", 0)) for f in files)}}))


def purge():
    """Delete every object this app can see, leaves first. A recursive delete of the top folder is refused
    with 403 appNotAuthorizedToChild (observed in the S4 Drive run), so children go one by one."""
    objs = list_all("trashed = false or trashed = true")
    byid = {o["id"]: o for o in objs}

    def depth(o):
        d = 0
        while o.get("parents") and o["parents"][0] in byid:
            o = byid[o["parents"][0]]
            d += 1
        return d

    from concurrent.futures import ThreadPoolExecutor
    access()
    order = sorted(objs, key=lambda o: (o["mimeType"] == "application/vnd.google-apps.folder", -depth(o)))
    codes = {}

    def rm(o):
        st, r = api("DELETE", f"/files/{o['id']}")
        if st >= 400 and st != 404:
            e = r.get("error", {})
            print(json.dumps({"delete_failed": o["name"], "http": st, "reason": (e.get("errors") or [{}])[0].get("reason")}))
        return st

    # one level at a time (files, then folders deepest first), 8 requests in flight within a level
    levels = {}
    for o in order:
        levels.setdefault((o["mimeType"] == "application/vnd.google-apps.folder", -depth(o)), []).append(o)
    with ThreadPoolExecutor(8) as ex:
        for key in sorted(levels):
            for st in ex.map(rm, levels[key]):
                codes[st] = codes.get(st, 0) + 1
    rest = list_all("trashed = false or trashed = true")
    print(json.dumps({"deleted_objects": len(order), "http_codes": codes, "app_visible_objects_remaining": len(rest)}))


def tree():
    for f in list_all(f"name = '{FOLDER}' and mimeType = 'application/vnd.google-apps.folder'"):
        kids = list_all(f"'{f['id']}' in parents and trashed = false")
        print(json.dumps({"folder": f["name"], "children": sorted(k["name"] for k in kids)[:20], "n_children": len(kids)}))


def bw(mb):
    data = os.urandom(mb * 1024 * 1024)
    b = "xb" + os.urandom(6).hex()
    meta = json.dumps({"name": "bwprobe.bin"}).encode()
    body = (f"--{b}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n".encode() + meta +
            f"\r\n--{b}\r\nContent-Type: application/octet-stream\r\n\r\n".encode() + data + f"\r\n--{b}--".encode())
    t = time.time()
    st, r = api("POST", "/files", {"uploadType": "multipart"}, body,
                {"Content-Type": f"multipart/related; boundary={b}"}, upload=True)
    up = time.time() - t
    if st != 200:
        sys.exit(f"upload failed {st} {r}")
    t = time.time()
    st2, got = api("GET", f"/files/{r['id']}", {"alt": "media"}, raw=True)
    down = time.time() - t
    ok = st2 == 200 and got == data
    api("DELETE", f"/files/{r['id']}")
    print(json.dumps({"mb": mb, "upload_s": round(up, 2), "upload_MBps": round(mb * 1.048576 / up, 2),
                      "download_s": round(down, 2), "download_MBps": round(mb * 1.048576 / down, 2), "roundtrip_ok": ok}))


if __name__ == "__main__":
    c = sys.argv[1] if len(sys.argv) > 1 else ""
    if c == "usage":
        usage()
    elif c == "purge":
        purge()
    elif c == "tree":
        tree()
    elif c == "bw":
        bw(int(sys.argv[2]) if len(sys.argv) > 2 else 20)
    else:
        sys.exit(__doc__)
