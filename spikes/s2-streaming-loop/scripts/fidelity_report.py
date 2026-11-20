#!/usr/bin/env python3
"""Pixel-fidelity report for the FID_* runs.

  fidelity_report.py <work-dir> [run-substring ...]

Each results/vps/<run>/ holds src-dump.tgz (raw BGRA source frames captured on the server, `s2-server --dump`) and
dec-dump.tgz (raw I420 frames as decoded by `s2-client --dump`). The tarballs are not committed (hundreds of MB): they are
unpacked into <work-dir>, compared with target/release/s2-fidelity (PSNR / SSIM / colour checks, matched by frame number),
and for the VUI-tagged runs side-by-side crop PNGs (source | decoded | |difference| x8, 4x nearest-neighbour zoom) are
written to results/vps/crops/: <run>.png for the median-PSNR frame and <run>-worst.png for the worst frame.
A per-frame CSV is saved as results/vps/<run>/fidelity.csv. Needs Pillow (no numpy).
"""
import os, subprocess, sys, tarfile

from PIL import Image, ImageChops

HERE = os.path.dirname(os.path.abspath(__file__))
SPIKE = os.path.dirname(HERE)
BASE = os.path.join(SPIKE, "results", "vps")
BIN = os.path.join(SPIKE, "target", "release", "s2-fidelity")
CW, CH, ZOOM = 128, 72, 4


def sheet(w, out):
    a = Image.open(os.path.join(w, "crop-src.ppm")).convert("RGB")
    b = Image.open(os.path.join(w, "crop-dec.ppm")).convert("RGB")
    diff = ImageChops.difference(a, b).point(lambda v: min(255, v * 8))
    sh = Image.new("RGB", (3 * CW * ZOOM + 8, CH * ZOOM), (255, 0, 255))
    for i, im in enumerate((a, b, diff)):
        sh.paste(im.resize((CW * ZOOM, CH * ZOOM), Image.NEAREST), (i * (CW * ZOOM + 4), 0))
    sh.save(out, optimize=True)


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
        ff = os.path.join(w, "dec", "dec-format.txt")
        fmt = open(ff).read().strip() if os.path.exists(ff) else "?"
        print(f"### {run}\ndecoder-reported: {fmt}")
        for pick in ("median", "worst"):
            r = subprocess.run([BIN, "--src", os.path.join(w, "src"), "--dec", os.path.join(w, "dec"), "--out", os.path.join(d, "fidelity.csv"),
                                "--crops", w, "--crop-w", str(CW), "--crop-h", str(CH), "--crop-pick", pick], capture_output=True, text=True)
            if r.returncode:
                print(r.stderr[-500:])
                break
            if pick == "median":
                print(r.stdout.strip())
            else:
                print([ln for ln in r.stdout.splitlines() if ln.startswith("crop")][0])
            if "vui" in run:
                sheet(w, os.path.join(BASE, "crops", run + ("" if pick == "median" else "-worst") + ".png"))
        print()


if __name__ == "__main__":
    main()
