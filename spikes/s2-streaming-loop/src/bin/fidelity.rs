//! s2-fidelity: compares source frames dumped by `s2-server --dump` (raw BGRA, captured from Xorg) with the
//! decoded frames dumped by `s2-client --dump` (raw planar I420 as decoded by libavcodec), matched by frame number.
//!
//! Per frame: PSNR and SSIM of the decoded picture converted to RGB (BT.709 limited range, bilinear chroma upsampling)
//! against the source RGB; PSNR of the Y/U/V planes against the source converted to I420 the same way the server does
//! (isolates codec loss from colour conversion); mean colour bias; the decoded value of pure-white source pixels; and
//! PSNR when the same decoded planes are interpreted with the wrong matrix or range (what a mismatching client shows).
//! Optionally writes PPM crops (source / decoded) of the busiest region of the median frame for side-by-side figures.
//! Throwaway spike tooling.

#![allow(clippy::chunks_exact_to_as_chunks)] // throwaway tooling: plain chunks_exact(3) is clearer here

use anyhow::{Context, Result, bail};
use s2::Args;
use std::fmt::Write as _;
use std::fs;

#[derive(Clone, Copy)]
enum Mat {
    Bt709Limited,
    Bt601Limited,
    Bt709Full,
}

fn clamp8(v: f32) -> u8 {
    v.round().clamp(0.0, 255.0) as u8
}

/// Bilinear 2x upsampling of a chroma plane (sample centres at the middle of the 2x2 luma block, as MPEG-2/H.264 4:2:0
/// "left" siting is approximated by centred siting) to `w x h`.
fn upsample(plane: &[u8], cw: usize, ch: usize, w: usize, h: usize) -> Vec<f32> {
    let mut out = vec![0f32; w * h];
    for y in 0..h {
        let sy = (y as f32 + 0.5) / 2.0 - 0.5;
        let y0 = sy.floor();
        let fy = sy - y0;
        let (ya, yb) = ((y0 as isize).clamp(0, ch as isize - 1) as usize, (y0 as isize + 1).clamp(0, ch as isize - 1) as usize);
        for x in 0..w {
            let sx = (x as f32 + 0.5) / 2.0 - 0.5;
            let x0 = sx.floor();
            let fx = sx - x0;
            let (xa, xb) = ((x0 as isize).clamp(0, cw as isize - 1) as usize, (x0 as isize + 1).clamp(0, cw as isize - 1) as usize);
            let p = |xx: usize, yy: usize| plane[yy * cw + xx] as f32;
            let top = p(xa, ya) * (1.0 - fx) + p(xb, ya) * fx;
            let bot = p(xa, yb) * (1.0 - fx) + p(xb, yb) * fx;
            out[y * w + x] = top * (1.0 - fy) + bot * fy;
        }
    }
    out
}

fn yuv_to_rgb(y: &[u8], u: &[f32], v: &[f32], w: usize, h: usize, m: Mat) -> Vec<u8> {
    let mut out = vec![0u8; w * h * 3];
    for i in 0..w * h {
        let (yy, uu, vv) = (y[i] as f32, u[i] - 128.0, v[i] - 128.0);
        let (r, g, b) = match m {
            Mat::Bt709Limited => {
                let c = 1.164_383 * (yy - 16.0);
                (c + 1.792_741 * vv, c - 0.213_249 * uu - 0.532_909 * vv, c + 2.112_402 * uu)
            }
            Mat::Bt601Limited => {
                let c = 1.164_383 * (yy - 16.0);
                (c + 1.596_027 * vv, c - 0.391_762 * uu - 0.812_968 * vv, c + 2.017_232 * uu)
            }
            Mat::Bt709Full => (yy + 1.5748 * vv, yy - 0.187_324 * uu - 0.468_124 * vv, yy + 1.8556 * uu),
        };
        out[i * 3] = clamp8(r);
        out[i * 3 + 1] = clamp8(g);
        out[i * 3 + 2] = clamp8(b);
    }
    out
}

fn psnr_mse(mse: f64) -> f64 {
    if mse <= 1e-12 { 99.0 } else { 10.0 * (255.0f64 * 255.0 / mse).log10() }
}

fn psnr_u8(a: &[u8], b: &[u8]) -> f64 {
    let s: f64 = a.iter().zip(b).map(|(x, y)| (*x as f64 - *y as f64).powi(2)).sum();
    psnr_mse(s / a.len() as f64)
}

/// BT.709 luma of full-range RGB, 0..255 as f64.
fn luma_f(rgb: &[u8]) -> Vec<f64> {
    rgb.chunks_exact(3).map(|p| 0.2126 * p[0] as f64 + 0.7152 * p[1] as f64 + 0.0722 * p[2] as f64).collect()
}

/// Mean SSIM, 7x7 uniform window (stride 1), population statistics, L = 255.
fn ssim(a: &[f64], b: &[f64], w: usize, h: usize) -> f64 {
    const K: usize = 7;
    let (c1, c2) = ((0.01f64 * 255.0).powi(2), (0.03f64 * 255.0).powi(2));
    let integral = |f: &dyn Fn(usize) -> f64| -> Vec<f64> {
        let mut s = vec![0f64; (w + 1) * (h + 1)];
        for y in 0..h {
            let mut row = 0.0;
            for x in 0..w {
                row += f(y * w + x);
                s[(y + 1) * (w + 1) + x + 1] = s[y * (w + 1) + x + 1] + row;
            }
        }
        s
    };
    let sa = integral(&|i| a[i]);
    let sb = integral(&|i| b[i]);
    let saa = integral(&|i| a[i] * a[i]);
    let sbb = integral(&|i| b[i] * b[i]);
    let sab = integral(&|i| a[i] * b[i]);
    let win = |s: &Vec<f64>, x: usize, y: usize| s[(y + K) * (w + 1) + x + K] - s[y * (w + 1) + x + K] - s[(y + K) * (w + 1) + x] + s[y * (w + 1) + x];
    let n = (K * K) as f64;
    let mut tot = 0.0;
    let mut cnt = 0u64;
    for y in 0..=h - K {
        for x in 0..=w - K {
            let (ma, mb) = (win(&sa, x, y) / n, win(&sb, x, y) / n);
            let va = win(&saa, x, y) / n - ma * ma;
            let vb = win(&sbb, x, y) / n - mb * mb;
            let cov = win(&sab, x, y) / n - ma * mb;
            tot += ((2.0 * ma * mb + c1) * (2.0 * cov + c2)) / ((ma * ma + mb * mb + c1) * (va + vb + c2));
            cnt += 1;
        }
    }
    tot / cnt as f64
}

/// Source RGB to I420 planes (BT.709 limited), 2x2 box-averaged chroma: the reference the encoder was given.
fn rgb_to_i420(rgb: &[u8], w: usize, h: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut y = vec![0u8; w * h];
    for i in 0..w * h {
        let (r, g, b) = (rgb[i * 3] as f32, rgb[i * 3 + 1] as f32, rgb[i * 3 + 2] as f32);
        y[i] = clamp8(16.0 + (0.2126 * r + 0.7152 * g + 0.0722 * b) * 219.0 / 255.0);
    }
    let (cw, ch) = (w / 2, h / 2);
    let mut u = vec![0u8; cw * ch];
    let mut v = vec![0u8; cw * ch];
    for cy in 0..ch {
        for cx in 0..cw {
            let (mut r, mut g, mut b) = (0f32, 0f32, 0f32);
            for (dx, dy) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
                let i = ((cy * 2 + dy) * w + cx * 2 + dx) * 3;
                r += rgb[i] as f32;
                g += rgb[i + 1] as f32;
                b += rgb[i + 2] as f32;
            }
            let (r, g, b) = (r / 4.0, g / 4.0, b / 4.0);
            u[cy * cw + cx] = clamp8(128.0 + (-0.1146 * r - 0.3854 * g + 0.5 * b) * 224.0 / 255.0);
            v[cy * cw + cx] = clamp8(128.0 + (0.5 * r - 0.4542 * g - 0.0458 * b) * 224.0 / 255.0);
        }
    }
    (y, u, v)
}

#[allow(clippy::too_many_arguments)]
fn write_ppm(path: &str, rgb: &[u8], w: usize, rx: usize, ry: usize, rw: usize, rh: usize) -> Result<()> {
    let mut buf = format!("P6\n{rw} {rh}\n255\n").into_bytes();
    for y in ry..ry + rh {
        buf.extend_from_slice(&rgb[(y * w + rx) * 3..(y * w + rx + rw) * 3]);
    }
    fs::write(path, buf)?;
    Ok(())
}

struct FrameResult {
    frame: u32,
    psnr_rgb: f64,
    psnr_luma: f64,
    ssim_luma: f64,
    psnr_y: f64,
    psnr_u: f64,
    psnr_v: f64,
    bias: [f64; 3],
    white: Option<[f64; 3]>,
    psnr_601: f64,
    psnr_full: f64,
    max_err: u8,
}

fn busiest_region(rgb: &[u8], w: usize, h: usize, rw: usize, rh: usize) -> (usize, usize) {
    let l = luma_f(rgb);
    let mut g = vec![0u32; w * h];
    for y in 1..h {
        for x in 1..w {
            g[y * w + x] = ((l[y * w + x] - l[y * w + x - 1]).abs() + (l[y * w + x] - l[(y - 1) * w + x]).abs()) as u32;
        }
    }
    let mut s = vec![0u64; (w + 1) * (h + 1)];
    for y in 0..h {
        let mut row = 0u64;
        for x in 0..w {
            row += g[y * w + x] as u64;
            s[(y + 1) * (w + 1) + x + 1] = s[y * (w + 1) + x + 1] + row;
        }
    }
    let mut best = (0u64, 0usize, 0usize);
    let mut y = 0;
    while y + rh <= h {
        let mut x = 0;
        while x + rw <= w {
            let v = s[(y + rh) * (w + 1) + x + rw] + s[y * (w + 1) + x] - s[y * (w + 1) + x + rw] - s[(y + rh) * (w + 1) + x];
            if v > best.0 {
                best = (v, x, y);
            }
            x += 16;
        }
        y += 16;
    }
    (best.1, best.2)
}

fn main() -> Result<()> {
    let a = Args::parse();
    let src = a.get_str("src", ".");
    let dec = a.get_str("dec", ".");
    let (w, h): (usize, usize) = (a.get("w", 1920), a.get("h", 1080));
    let out_csv = a.get_str("out", "");
    let crop_dir = a.get_str("crops", "");
    let (cw_, ch_): (usize, usize) = (a.get("crop-w", 160), a.get("crop-h", 90));
    let skip_first: u32 = a.get("skip-first", 0);

    let mut frames: Vec<u32> = fs::read_dir(&dec)?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str()?.strip_prefix("dec-")?.strip_suffix(".yuv")?.parse::<u32>().ok())
        .filter(|n| std::path::Path::new(&format!("{src}/src-{n:06}.bgra")).exists() && *n >= skip_first)
        .collect();
    frames.sort_unstable();
    if frames.is_empty() {
        bail!("no matching frame pairs in src={src} dec={dec}");
    }
    let mut res = Vec::new();
    let mut rgbs: Vec<(u32, Vec<u8>, Vec<u8>)> = Vec::new();
    for &n in &frames {
        let bgra = fs::read(format!("{src}/src-{n:06}.bgra"))?;
        let yuv = fs::read(format!("{dec}/dec-{n:06}.yuv"))?;
        anyhow::ensure!(bgra.len() == w * h * 4, "bad source size for frame {n}");
        anyhow::ensure!(yuv.len() == w * h * 3 / 2, "bad decoded size for frame {n}");
        let srgb: Vec<u8> = bgra.chunks_exact(4).flat_map(|p| [p[2], p[1], p[0]]).collect();
        let (yp, rest) = yuv.split_at(w * h);
        let (up, vp) = rest.split_at(w * h / 4);
        let (cw, ch) = (w / 2, h / 2);
        let uu = upsample(up, cw, ch, w, h);
        let vv = upsample(vp, cw, ch, w, h);
        let drgb = yuv_to_rgb(yp, &uu, &vv, w, h, Mat::Bt709Limited);
        let psnr_rgb = psnr_u8(&srgb, &drgb);
        let (sl, dl) = (luma_f(&srgb), luma_f(&drgb));
        let psnr_luma = psnr_mse(sl.iter().zip(&dl).map(|(x, y)| (x - y).powi(2)).sum::<f64>() / sl.len() as f64);
        let ssim_luma = ssim(&sl, &dl, w, h);
        let (ry, ru, rv) = rgb_to_i420(&srgb, w, h);
        let mut bias = [0f64; 3];
        let mut max_err = 0u8;
        for (s, d) in srgb.chunks_exact(3).zip(drgb.chunks_exact(3)) {
            for c in 0..3 {
                bias[c] += d[c] as f64 - s[c] as f64;
                max_err = max_err.max(d[c].abs_diff(s[c]));
            }
        }
        for b in bias.iter_mut() {
            *b /= (w * h) as f64;
        }
        let mut wsum = [0f64; 3];
        let mut wn = 0u64;
        for (s, d) in srgb.chunks_exact(3).zip(drgb.chunks_exact(3)) {
            if s == [255, 255, 255] {
                for c in 0..3 {
                    wsum[c] += d[c] as f64;
                }
                wn += 1;
            }
        }
        let white = (wn > 1000).then(|| [wsum[0] / wn as f64, wsum[1] / wn as f64, wsum[2] / wn as f64]);
        let p601 = psnr_u8(&srgb, &yuv_to_rgb(yp, &uu, &vv, w, h, Mat::Bt601Limited));
        let pfull = psnr_u8(&srgb, &yuv_to_rgb(yp, &uu, &vv, w, h, Mat::Bt709Full));
        res.push(FrameResult {
            frame: n,
            psnr_rgb,
            psnr_luma,
            ssim_luma,
            psnr_y: psnr_u8(&ry, yp),
            psnr_u: psnr_u8(&ru, up),
            psnr_v: psnr_u8(&rv, vp),
            bias,
            white,
            psnr_601: p601,
            psnr_full: pfull,
            max_err,
        });
        if !crop_dir.is_empty() {
            rgbs.push((n, srgb, drgb));
        }
        eprintln!("frame {n}: psnr_rgb {psnr_rgb:.2} ssim {ssim_luma:.4}");
    }

    let mut csv = String::from("frame,psnr_rgb,psnr_luma,ssim_luma,psnr_yplane,psnr_uplane,psnr_vplane,bias_r,bias_g,bias_b,white_r,white_g,white_b,psnr_rgb_if_bt601,psnr_rgb_if_full_range,max_abs_err\n");
    for r in &res {
        let wh = r.white.map(|w| format!("{:.2},{:.2},{:.2}", w[0], w[1], w[2])).unwrap_or_else(|| ",,".into());
        let _ = writeln!(
            csv,
            "{},{:.3},{:.3},{:.5},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{},{:.3},{:.3},{}",
            r.frame, r.psnr_rgb, r.psnr_luma, r.ssim_luma, r.psnr_y, r.psnr_u, r.psnr_v, r.bias[0], r.bias[1], r.bias[2], wh, r.psnr_601, r.psnr_full, r.max_err
        );
    }
    if !out_csv.is_empty() {
        fs::write(&out_csv, &csv).with_context(|| out_csv.clone())?;
    }
    let mean = |f: &dyn Fn(&FrameResult) -> f64| res.iter().map(f).sum::<f64>() / res.len() as f64;
    let min = |f: &dyn Fn(&FrameResult) -> f64| res.iter().map(f).fold(f64::INFINITY, f64::min);
    println!(
        "frames={} psnr_rgb mean={:.2} min={:.2} | psnr_luma mean={:.2} | ssim_luma mean={:.4} min={:.4} | plane psnr Y={:.2} U={:.2} V={:.2} | bias RGB={:.2},{:.2},{:.2} | psnr_if_bt601 mean={:.2} | psnr_if_full_range mean={:.2}",
        res.len(),
        mean(&|r| r.psnr_rgb),
        min(&|r| r.psnr_rgb),
        mean(&|r| r.psnr_luma),
        mean(&|r| r.ssim_luma),
        min(&|r| r.ssim_luma),
        mean(&|r| r.psnr_y),
        mean(&|r| r.psnr_u),
        mean(&|r| r.psnr_v),
        mean(&|r| r.bias[0]),
        mean(&|r| r.bias[1]),
        mean(&|r| r.bias[2]),
        mean(&|r| r.psnr_601),
        mean(&|r| r.psnr_full)
    );
    let whites: Vec<[f64; 3]> = res.iter().filter_map(|r| r.white).collect();
    if !whites.is_empty() {
        let m = |c: usize| whites.iter().map(|w| w[c]).sum::<f64>() / whites.len() as f64;
        println!("pure-white source pixels decode to mean RGB {:.2},{:.2},{:.2}", m(0), m(1), m(2));
    }

    if !crop_dir.is_empty() {
        // median-PSNR frame, busiest region of its source
        let mut order: Vec<usize> = (0..res.len()).collect();
        order.sort_by(|&i, &j| res[i].psnr_rgb.partial_cmp(&res[j].psnr_rgb).unwrap());
        let mi = order[order.len() / 2];
        let (n, srgb, drgb) = &rgbs[mi];
        let (rx, ry) = if a.get::<i64>("crop-x", -1) >= 0 { (a.get("crop-x", 0usize), a.get("crop-y", 0usize)) } else { busiest_region(srgb, w, h, cw_, ch_) };
        fs::create_dir_all(&crop_dir)?;
        write_ppm(&format!("{crop_dir}/crop-src.ppm"), srgb, w, rx, ry, cw_, ch_)?;
        write_ppm(&format!("{crop_dir}/crop-dec.ppm"), drgb, w, rx, ry, cw_, ch_)?;
        println!("crop frame {n} at x={rx} y={ry} {cw_}x{ch_} (psnr_rgb {:.2})", res[mi].psnr_rgb);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn white_and_black_roundtrip_bt709_limited() {
        let (w, h) = (16usize, 16usize);
        let mut rgb = vec![255u8; w * h * 3];
        for p in rgb.chunks_exact_mut(3).take(w * h / 2) {
            p.copy_from_slice(&[0, 0, 0]);
        }
        let (y, u, v) = rgb_to_i420(&rgb, w, h);
        assert_eq!((y[w * h - 1], y[0]), (235, 16));
        let uu = upsample(&u, w / 2, h / 2, w, h);
        let vv = upsample(&v, w / 2, h / 2, w, h);
        let back = yuv_to_rgb(&y, &uu, &vv, w, h, Mat::Bt709Limited);
        assert_eq!(&back[(w * h - 1) * 3..], &[255, 255, 255]);
        assert_eq!(&back[..3], &[0, 0, 0]);
        // wrong interpretations visibly differ
        let full = yuv_to_rgb(&y, &uu, &vv, w, h, Mat::Bt709Full);
        assert!(full[(w * h - 1) * 3] < 240 && full[0] >= 14);
    }

    #[test]
    fn identical_images_score_perfectly() {
        let a: Vec<f64> = (0..64 * 64).map(|i| (i % 251) as f64).collect();
        assert!((ssim(&a, &a, 64, 64) - 1.0).abs() < 1e-9);
        assert_eq!(psnr_u8(&[1, 2, 3], &[1, 2, 3]), 99.0);
        assert!((psnr_u8(&[0; 4], &[1; 4]) - 48.13).abs() < 0.01);
    }
}
