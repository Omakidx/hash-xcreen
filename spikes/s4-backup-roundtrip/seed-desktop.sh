#!/usr/bin/env bash
# Spike S4: seed a desktop container with realistic data. Runs INSIDE the container as root.
# Usage: seed-desktop.sh install   # packages + user (slow, network)
#        seed-desktop.sh seed      # data files + SQLite writer (idempotent-ish)
#        seed-desktop.sh day       # simulate a day of use (second backup input)
#        seed-desktop.sh bulk MB   # add MB of new random data (interruption test)
set -euo pipefail
U=alice
H=/home/$U
as_user() { runuser -u "$U" -- "$@"; }

rand_mb() { head -c "$(($1 * 1024 * 1024))" /dev/urandom > "$2"; }

install_pkgs() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq xfce4 xfce4-terminal xserver-xorg-video-dummy xserver-xorg-core \
    dbus-x11 sqlite3 python3 acl attr libcap2-bin xvfb x11-utils xdotool >/dev/null
  id "$U" >/dev/null 2>&1 || useradd -m -s /bin/bash -u 1001 "$U"
  echo "$U:s4-dummy-password" | chpasswd
  # dummy-driver Xorg config (virtual desktop-sized display)
  mkdir -p /etc/X11/xorg.conf.d
  cat > /etc/X11/xorg.conf.d/10-dummy.conf <<'XC'
Section "Device"
  Identifier "dummy"
  Driver "dummy"
  VideoRam 256000
EndSection
Section "Monitor"
  Identifier "mon"
  HorizSync 5-1000
  VertRefresh 5-200
  Modeline "1920x1080" 173.00 1920 2048 2248 2576 1080 1083 1088 1120 -hsync +vsync
EndSection
Section "Screen"
  Identifier "scr"
  Device "dummy"
  Monitor "mon"
  DefaultDepth 24
  SubSection "Display"
    Depth 24
    Modes "1920x1080"
  EndSubSection
EndSection
XC
}

seed_chat() {
  # Claude Code
  as_user mkdir -p "$H/.claude/projects/-home-alice-proj-a" "$H/.claude/projects/-home-alice-proj-b" "$H/.claude/todos"
  python3 - <<'PY'
import json, random, uuid, os
random.seed(4)
words = "refactor function test build deploy rust borrow lifetime config socket buffer latency encode decode stream container snapshot backup restore daemon".split()
def line(i):
    return json.dumps({"type": random.choice(["user","assistant"]), "uuid": str(uuid.UUID(int=random.getrandbits(128))), "i": i,
        "message": {"content": " ".join(random.choice(words) for _ in range(random.randint(30, 400)))}})
for proj, n in (("-home-alice-proj-a", 6), ("-home-alice-proj-b", 4)):
    for s in range(n):
        p = f"/home/alice/.claude/projects/{proj}/{uuid.UUID(int=random.getrandbits(128))}.jsonl"
        with open(p, "w") as f:
            for i in range(random.randint(2000, 4000)):
                f.write(line(i) + "\n")
PY
  echo '{"theme":"dark","model":"dummy"}' > "$H/.claude/settings.json"
  echo '{"userID":"dummy-user","projects":{}}' > "$H/.claude.json"
  echo '{"claudeAiOauth":{"accessToken":"dummy-access","refreshToken":"dummy-refresh","expiresAt":0}}' > "$H/.claude/.credentials.json"
  chmod 600 "$H/.claude/.credentials.json"
  # Codex
  as_user mkdir -p "$H/.codex/sessions/2026/11/19"
  python3 - <<'PY'
import json, random
random.seed(5)
w = "plan patch apply diff sandbox shell approval model token".split()
for k in range(3):
    with open(f"/home/alice/.codex/sessions/2026/11/19/rollout-{k}.jsonl", "w") as f:
        for i in range(2500):
            f.write(json.dumps({"i": i, "text": " ".join(random.choice(w) for _ in range(random.randint(20, 200)))}) + "\n")
PY
  echo '{"OPENAI_API_KEY":null,"tokens":{"access_token":"dummy","refresh_token":"dummy"}}' > "$H/.codex/auth.json"
  chmod 600 "$H/.codex/auth.json"
  echo 'model = "dummy"' > "$H/.codex/config.toml"
  as_user mkdir -p "$H/.gemini" "$H/.cursor"
  echo '{"dummy":true}' > "$H/.gemini/settings.json"
}

seed_electron() {
  local A="$H/.config/SlackLike"
  as_user mkdir -p "$A/Local Storage/leveldb" "$A/IndexedDB/https_app.example_0.indexeddb.leveldb" "$A/Session Storage" \
    "$A/Cache/Cache_Data" "$A/Code Cache/js" "$A/GPUCache" "$A/DawnCache" "$A/Network"
  for i in 1 2 3; do rand_mb 2 "$A/Local Storage/leveldb/00000$i.ldb"; done
  echo "MANIFEST-000004" > "$A/Local Storage/leveldb/CURRENT"
  echo "leveldb log" > "$A/Local Storage/leveldb/LOG"
  : > "$A/Local Storage/leveldb/LOCK"
  for i in 1 2; do rand_mb 3 "$A/IndexedDB/https_app.example_0.indexeddb.leveldb/00000$i.ldb"; done
  rand_mb 1 "$A/Session Storage/000003.log"
  echo '{"zoom":1}' > "$A/Preferences"
  for i in $(seq 1 40); do rand_mb 3 "$A/Cache/Cache_Data/f_$i"; done          # 120 MB
  for i in $(seq 1 20); do rand_mb 2 "$A/Code Cache/js/c_$i"; done             # 40 MB
  rand_mb 30 "$A/GPUCache/data_1"; rand_mb 10 "$A/DawnCache/data_0"            # 40 MB
  # VS Code style
  as_user mkdir -p "$H/.config/Code/User" "$H/.config/Code/Cache" "$H/.config/Code/CachedData"
  echo '{"editor.fontSize":14}' > "$H/.config/Code/User/settings.json"
  rand_mb 20 "$H/.config/Code/CachedData/blob"; rand_mb 10 "$H/.config/Code/Cache/blob"
}

seed_browser() {
  local P="$H/.config/chromium/Default"
  as_user mkdir -p "$P/Cache" "$P/Extensions" "$P/Service Worker/CacheStorage" "$P/Code Cache/js" "$P/GPUCache"
  python3 - <<'PY'
import sqlite3
for n in ("History", "Cookies", "Login Data", "Web Data"):
    c = sqlite3.connect(f"/home/alice/.config/chromium/Default/{n}")
    c.execute("create table t(id integer primary key, v text)")
    c.executemany("insert into t(v) values (?)", [("row %d %s" % (i, "x" * 200),) for i in range(3000)])
    c.commit(); c.close()
PY
  for i in 1 2 3 4 5; do rand_mb 5 "$P/Extensions/ext_$i.crx"; done
  for i in $(seq 1 30); do rand_mb 3 "$P/Cache/data_$i"; done   # 90 MB, a browser cache (not in exclude list by exact rule -> kept unless matched)
  for i in $(seq 1 10); do rand_mb 3 "$P/Code Cache/js/cc_$i"; done; rand_mb 20 "$P/GPUCache/data_1"; rand_mb 20 "$P/Service Worker/CacheStorage/sw.bin"
  as_user mkdir -p "$H/.local/share/app-data" "$H/Documents" "$H/projects" "$H/.local/share/Trash/files"
  rand_mb 15 "$H/.local/share/app-data/store.bin"
  rand_mb 5 "$H/.local/share/Trash/files/old.bin"
  # realistic documents
  python3 - <<'PY'
import random
random.seed(9)
w = "the quick brown fox jumps over lazy dog report invoice meeting notes budget".split()
for i in range(300):
    with open(f"/home/alice/Documents/doc_{i}.txt", "w") as f:
        f.write(" ".join(random.choice(w) for _ in range(random.randint(500, 5000))))
PY
}

seed_cache() {
  as_user mkdir -p "$H/.cache/thumbnails" "$H/.cache/pip" "$H/.cache/mozilla"
  for i in $(seq 1 60); do rand_mb 3 "$H/.cache/thumbnails/t_$i"; done        # 180 MB
  rand_mb 40 "$H/.cache/pip/wheel.bin"
  rand_mb 20 /var/tmp/vt.bin; rand_mb 20 /tmp/t.bin
  mkdir -p /var/log/app && rand_mb 10 /var/log/app/big.log
}

seed_special() {
  # ownership, permissions, xattrs, ACLs, hardlinks, symlinks, fifo, setuid, sticky, sparse
  local D="$H/special"
  as_user mkdir -p "$D"
  echo data > "$D/acl.txt"; setfacl -m u:root:r-- -m u:1001:rw- -m g:daemon:r-- "$D/acl.txt"
  echo data > "$D/xattr.txt"; setfattr -n user.s4.tag -v "hello" "$D/xattr.txt"
  echo data > "$D/orig"; ln "$D/orig" "$D/hardlink"; ln -s orig "$D/symlink"; ln -s /nonexistent "$D/dangling"
  mkfifo "$D/fifo"; chmod 640 "$D/orig"
  chown root:daemon "$D/orig.root" 2>/dev/null || { echo rootfile > "$D/orig.root"; chown root:daemon "$D/orig.root"; chmod 4750 "$D/orig.root"; }
  mkdir -p "$D/sticky"; chmod 1777 "$D/sticky"
  truncate -s 50M "$D/sparse.img"; printf 'tail' | dd of="$D/sparse.img" bs=1 seek=40M conv=notrunc 2>/dev/null
  touch -d '2020-01-02 03:04:05' "$D/xattr.txt"
  cp /usr/bin/ping /usr/local/bin/s4-ping 2>/dev/null && setcap cap_net_raw+ep /usr/local/bin/s4-ping || true
  mkdir -p /etc/s4 && echo 'conf' > /etc/s4/app.conf && setfattr -n user.s4.etc -v 1 /etc/s4/app.conf
}

start_sqlite_writer() {
  mkdir -p "$H/.local/share/db"
  cat > /usr/local/bin/s4-sqlite-writer.py <<'PY'
import sqlite3, time, os
c = sqlite3.connect("/home/alice/.local/share/db/live.sqlite", isolation_level=None)
c.execute("pragma journal_mode=wal")
c.execute("create table if not exists ev(id integer primary key, ts real, payload text)")
i = 0
while True:
    c.execute("begin")
    for _ in range(20):
        c.execute("insert into ev(ts,payload) values (?,?)", (time.time(), os.urandom(200).hex()))
    c.execute("commit")
    i += 1
    time.sleep(0.02)
PY
  chown -R "$U:$U" "$H/.local/share/db"
  pkill -f s4-sqlite-writer || true
  nohup runuser -u "$U" -- python3 /usr/local/bin/s4-sqlite-writer.py >/var/log/s4-writer.log 2>&1 &
  disown || true
}

seed() {
  seed_chat; seed_electron; seed_browser; seed_cache; seed_special; start_sqlite_writer
  chown -R "$U:$U" "$H" 2>/dev/null || true
  # re-assert special ownership broken by recursive chown
  chown root:daemon "$H/special/orig.root"; chmod 4750 "$H/special/orig.root"
  chmod 640 "$H/special/orig"
  setfacl -m u:root:r-- -m g:daemon:r-- "$H/special/acl.txt"
  chmod 600 "$H/.claude/.credentials.json" "$H/.codex/auth.json"
  sync; du -sh / --exclude=/proc --exclude=/sys 2>/dev/null | tail -1
}

day() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq htop gimp-data ncdu >/dev/null   # a few packages
  # edit / create files
  for i in $(seq 1 40); do echo "new doc $i $(date +%s%N)" | as_user tee "$H/Documents/day_$i.txt" >/dev/null; done
  python3 - <<'PY'
import json, random, glob
random.seed(77)
w = "refactor function test build deploy rust borrow lifetime config socket buffer latency".split()
for p in glob.glob("/home/alice/.claude/projects/*/*.jsonl")[:4] + glob.glob("/home/alice/.codex/sessions/*/*/*/*.jsonl"):
    with open(p, "a") as f:
        for i in range(600):
            f.write(json.dumps({"i": i, "text": " ".join(random.choice(w) for _ in range(random.randint(30, 300)))}) + "\n")
PY
  # new session
  python3 -c "
import json,random
random.seed(78)
with open('/home/alice/.claude/projects/-home-alice-proj-a/new-session-day.jsonl','w') as f:
    for i in range(3000): f.write(json.dumps({'i':i,'t':' '.join(random.choice(['a','bb','ccc','dddd']) for _ in range(80))})+'\n')"
  # churn browser profile: rewrite DBs, cache rotation
  python3 - <<'PY'
import sqlite3
for n in ("History", "Cookies"):
    c = sqlite3.connect(f"/home/alice/.config/chromium/Default/{n}")
    c.executemany("insert into t(v) values (?)", [("day row %d %s" % (i, "y" * 200),) for i in range(1500)])
    c.commit(); c.close()
PY
  rm -f "$H"/.config/chromium/Default/Cache/data_{1..10}
  for i in $(seq 31 40); do rand_mb 3 "$H/.config/chromium/Default/Cache/data_$i"; done   # 30 MB cache churn
  # Electron app: levelDB rewrites + big cache churn
  rm -f "$H/.config/SlackLike/Cache/Cache_Data"/f_{1..20}
  for i in $(seq 41 60); do rand_mb 3 "$H/.config/SlackLike/Cache/Cache_Data/f_$i"; done
  rand_mb 2 "$H/.config/SlackLike/Local Storage/leveldb/000004.ldb"
  rand_mb 40 "$H/.cache/thumbnails/day.bin"
  # more sqlite writes happen continuously from the writer
  chown -R "$U:$U" "$H"; chown root:daemon "$H/special/orig.root"; chmod 4750 "$H/special/orig.root"
  sync
}

bulk() {
  mkdir -p "$H/bulk"
  for i in $(seq 1 "$1"); do rand_mb 1 "$H/bulk/b_$i"; done
  chown -R "$U:$U" "$H/bulk"; sync
}

case "${1:-}" in
  install) install_pkgs ;;
  seed) seed ;;
  day) day ;;
  bulk) bulk "${2:-1000}" ;;
  *) echo "usage: $0 install|seed|day|bulk MB"; exit 2 ;;
esac
