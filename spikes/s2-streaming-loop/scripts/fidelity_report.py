#!/usr/bin/env python3
"""Pixel-fidelity report for the FID_* runs.

  fidelity_report.py <work-dir> [run-substring ...]

Each results/vps/<run>/ holds src-dump.tgz (raw BGRA source frames captured on the server, `s2-server --dump`) and
dec-dump.tgz (raw I420 frames as decoded by `s2-client --dump`). The tarballs are not committed (hundreds of MB): they are
unpacked into <work-dir>, compared with target/release/s2-fidelity (PSNR / SSIM / colour checks, matched by frame number),
and a side-by-side crop PNG (source | decoded | |difference| x8, 4x nearest-neighbour zoom) is written to
results/vps/crops/<run>.png. A per-frame CSV is saved as results/vps/<run>/fidelity.csv. Needs Pillow (no numpy).
"""
import os, subprocess, sys, tarfile

from PIL import Image, ImageChops

HERE = os.path.dirname(os.path.abspath(__file__))
SPIKE = os.path.dirname(HERE)
BASE = os.path.join(SPIKE, "results", "vps")
BIN = os.path.join(SPIKE, "target", "release", "s2-fidelity")
CW, CH, ZOOM = 128, 72, 4


def main():
    work = sys.argv[1]
    pats = sys.argv[2:]
    os.makedirs(os.path.join(BASE, "crops"), exist_ok=True)
    runs = sorted(d for d in os.listdir(BASE) if d.startswith("FID_") and (not pats or any(p in d for p in pats)))
    for run in runs:
        d = os.path.join(BASE, run)
        if not os.path.exists(os.path.join(d, "dec-dump.tgz")):
            continue
        w = os.path.join(work, run)
        for kind in ("src", "dec"):
            os.makedirs(os.path.join(w, kind), exist_ok=True)
            with tarfile.open(os.path.join(d, f"{kind}-dump.tgz")) as t:
                t.extractall(os.path.join(w, kind), filter="data")
        fmt = open(os.path.join(w, "dec", "dec-format.txt")).read().strip() if os.path.exists(os.path.join(w, "dec", "dec-format.txt")) else "?"
        r = subprocess.run([BIN, "--src", os.path.join(w, "src"), "--dec", os.path.join(w, "dec"), "--out", os.path.join(d, "fidelity.csv"),
                            "--crops", w, "--crop-w", str(CW), "--crop-h", str(CH)], capture_output=True, text=True)
        print(f"### {run}\ndecoder-reported: {fmt}\n{r.stdout.strip()}\n")
        if r.returncode:
            print(r.stderr[-500:])
            continue
        a = Image.open(os.path.join(w, "crop-src.ppm")).convert("RGB")
        b = Image.open(os.path.join(w, "crop-dec.ppm")).convert("RGB")
        diff = ImageChops.difference(a, b).point(lambda v: min(255, v * 8))
        z = lambda im: im.resize((CW * ZOOM, CH * ZOOM), Image.NEAREST)  # noqa: E731
        sheet = Image.new("RGB", (3 * CW * ZOOM + 8, CH * ZOOM), (255, 0, 255))
        for i, im in enumerate((a, b, diff)):
            sheet.paste(z(im), (i * (CW * ZOOM + 4), 0))
        sheet.save(os.path.join(BASE, "crops", run + ".png"), optimize=True)


if __name__ == "__main__":
    main()
