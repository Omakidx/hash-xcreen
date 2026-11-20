#!/usr/bin/env bash
# Generate a long text document for the scrolling scenario (runs in the container as root).
python3 - <<'PY' > /home/desk/long.txt
for i in range(4000):
    print(f"Line {i:05d}: The quick brown fox jumps over the lazy dog; remote desktop streaming spike S2 payload text {i*7919%10007}")
PY
chown desk /home/desk/long.txt
