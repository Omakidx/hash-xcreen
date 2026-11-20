//! BGRA to YUV 4:2:0 conversion, BT.709 limited range (the colour tags the encoder writes).

use super::EncodeError;
use yuvutils_rs::{
    YuvBiPlanarImageMut, YuvChromaSubsampling, YuvConversionMode, YuvPlanarImageMut, YuvRange,
    YuvStandardMatrix, bgra_to_yuv_nv12, bgra_to_yuv420,
};

/// Planar layout of a [`YuvFrame`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum YuvFormat {
    /// Three planes: Y, U, V.
    I420,
    /// Two planes: Y, then interleaved UV.
    Nv12,
}

/// One plane of a [`YuvFrame`].
#[derive(Clone, Copy, Debug)]
pub struct Plane<'a> {
    pub data: &'a [u8],
    /// Bytes from one row to the next.
    pub stride: usize,
    /// Meaningful bytes in each row (the rest of the stride is padding).
    pub row_bytes: usize,
    pub rows: usize,
}

enum Planes {
    I420(YuvPlanarImageMut<'static, u8>),
    Nv12(YuvBiPlanarImageMut<'static, u8>),
}

/// A reusable YUV 4:2:0 picture with even dimensions. Allocate once, convert into it for
/// every frame.
pub struct YuvFrame {
    planes: Planes,
    width: u32,
    height: u32,
}

impl YuvFrame {
    /// Allocate a zeroed picture. Width and height must be non-zero and even (4:2:0).
    pub fn new(format: YuvFormat, width: u32, height: u32) -> Result<Self, EncodeError> {
        check_dimensions(width, height)?;
        let planes = match format {
            YuvFormat::I420 => Planes::I420(YuvPlanarImageMut::alloc(
                width,
                height,
                YuvChromaSubsampling::Yuv420,
            )),
            YuvFormat::Nv12 => Planes::Nv12(YuvBiPlanarImageMut::alloc(
                width,
                height,
                YuvChromaSubsampling::Yuv420,
            )),
        };
        Ok(Self {
            planes,
            width,
            height,
        })
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn format(&self) -> YuvFormat {
        match self.planes {
            Planes::I420(_) => YuvFormat::I420,
            Planes::Nv12(_) => YuvFormat::Nv12,
        }
    }

    pub fn plane_count(&self) -> usize {
        match self.planes {
            Planes::I420(_) => 3,
            Planes::Nv12(_) => 2,
        }
    }

    /// Plane `index` (0 = Y). Panics if `index >= plane_count()`.
    pub fn plane(&self, index: usize) -> Plane<'_> {
        let (w, h) = (self.width as usize, self.height as usize);
        match (&self.planes, index) {
            (Planes::I420(p), 0) => Plane {
                data: p.y_plane.borrow(),
                stride: p.y_stride as usize,
                row_bytes: w,
                rows: h,
            },
            (Planes::I420(p), 1) => Plane {
                data: p.u_plane.borrow(),
                stride: p.u_stride as usize,
                row_bytes: w / 2,
                rows: h / 2,
            },
            (Planes::I420(p), 2) => Plane {
                data: p.v_plane.borrow(),
                stride: p.v_stride as usize,
                row_bytes: w / 2,
                rows: h / 2,
            },
            (Planes::Nv12(p), 0) => Plane {
                data: p.y_plane.borrow(),
                stride: p.y_stride as usize,
                row_bytes: w,
                rows: h,
            },
            (Planes::Nv12(p), 1) => Plane {
                data: p.uv_plane.borrow(),
                stride: p.uv_stride as usize,
                row_bytes: w,
                rows: h / 2,
            },
            _ => panic!("plane index {index} out of range"),
        }
    }
}

pub(crate) fn check_dimensions(width: u32, height: u32) -> Result<(), EncodeError> {
    if width == 0 || height == 0 || !width.is_multiple_of(2) || !height.is_multiple_of(2) {
        return Err(EncodeError::Config(format!(
            "{width}x{height}: width and height must be even and non-zero"
        )));
    }
    Ok(())
}

/// Largest even picture that fits a source of `width` x `height` (odd edges are cropped).
pub fn even_size(width: u32, height: u32) -> (u32, u32) {
    (width & !1, height & !1)
}

/// Convert little-endian BGRX/BGRA pixels (`src_stride` bytes per row) into `dst`, BT.709
/// limited range. The source must be at least as large as `dst`; extra columns and rows
/// are ignored (odd edges are cropped by the caller choosing an even `dst`). The alpha
/// byte is ignored.
pub fn convert_bgrx(src: &[u8], src_stride: usize, dst: &mut YuvFrame) -> Result<(), EncodeError> {
    let (w, h) = (dst.width as usize, dst.height as usize);
    if src_stride < w * 4 {
        return Err(EncodeError::Config(format!(
            "source stride {src_stride} is smaller than {w} pixels of 4 bytes"
        )));
    }
    if src.len() < src_stride * (h - 1) + w * 4 {
        return Err(EncodeError::Config(format!(
            "source buffer of {} bytes is too small for {w}x{h} at stride {src_stride}",
            src.len()
        )));
    }
    let stride = u32::try_from(src_stride)
        .map_err(|_| EncodeError::Config("source stride too large".to_string()))?;
    let result = match &mut dst.planes {
        Planes::I420(p) => bgra_to_yuv420(
            p,
            src,
            stride,
            YuvRange::Limited,
            YuvStandardMatrix::Bt709,
            YuvConversionMode::Balanced,
        ),
        Planes::Nv12(p) => bgra_to_yuv_nv12(
            p,
            src,
            stride,
            YuvRange::Limited,
            YuvStandardMatrix::Bt709,
            YuvConversionMode::Balanced,
        ),
    };
    result.map_err(|e| EncodeError::Convert(format!("{e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: u32 = 32;
    const H: u32 = 16;

    fn solid(b: u8, g: u8, r: u8) -> Vec<u8> {
        std::iter::repeat_n([b, g, r, 0xff], (W * H) as usize)
            .flatten()
            .collect()
    }

    /// BT.709 limited-range reference, from the definition (not from the library).
    fn reference(r: u8, g: u8, b: u8) -> (f64, f64, f64) {
        let (r, g, b) = (
            f64::from(r) / 255.0,
            f64::from(g) / 255.0,
            f64::from(b) / 255.0,
        );
        let (kr, kb) = (0.2126, 0.0722);
        let y = kr * r + (1.0 - kr - kb) * g + kb * b;
        (
            16.0 + 219.0 * y,
            128.0 + 224.0 * (b - y) / (2.0 * (1.0 - kb)),
            128.0 + 224.0 * (r - y) / (2.0 * (1.0 - kr)),
        )
    }

    fn sample(frame: &YuvFrame) -> (u8, u8, u8) {
        let y = frame.plane(0).data[0];
        match frame.format() {
            YuvFormat::I420 => (y, frame.plane(1).data[0], frame.plane(2).data[0]),
            YuvFormat::Nv12 => {
                let uv = frame.plane(1).data;
                (y, uv[0], uv[1])
            }
        }
    }

    fn check(format: YuvFormat) {
        let colours: [(&str, (u8, u8, u8)); 8] = [
            ("black", (0, 0, 0)),
            ("white", (255, 255, 255)),
            ("grey", (128, 128, 128)),
            ("red", (255, 0, 0)),
            ("green", (0, 255, 0)),
            ("blue", (0, 0, 255)),
            ("yellow", (255, 255, 0)),
            ("teal", (0, 128, 128)),
        ];
        let mut frame = YuvFrame::new(format, W, H).expect("frame");
        for (name, (r, g, b)) in colours {
            convert_bgrx(&solid(b, g, r), (W * 4) as usize, &mut frame).expect("convert");
            let (y, u, v) = sample(&frame);
            let (ey, eu, ev) = reference(r, g, b);
            for (got, want, plane) in [(y, ey, "Y"), (u, eu, "U"), (v, ev, "V")] {
                assert!(
                    (f64::from(got) - want).abs() <= 2.0,
                    "{format:?} {name} {plane}: got {got}, expected {want:.1}"
                );
            }
        }
    }

    #[test]
    fn bt709_limited_i420() {
        check(YuvFormat::I420);
    }

    #[test]
    fn bt709_limited_nv12() {
        check(YuvFormat::Nv12);
    }

    #[test]
    fn white_and_black_hit_the_limited_range_ends() {
        let mut frame = YuvFrame::new(YuvFormat::I420, W, H).expect("frame");
        convert_bgrx(&solid(255, 255, 255), (W * 4) as usize, &mut frame).expect("convert");
        let (y, u, v) = sample(&frame);
        assert!((233..=237).contains(&y) && (126..=130).contains(&u) && (126..=130).contains(&v));
        convert_bgrx(&solid(0, 0, 0), (W * 4) as usize, &mut frame).expect("convert");
        let (y, ..) = sample(&frame);
        assert!((15..=17).contains(&y));
    }

    #[test]
    fn padded_source_stride_and_larger_source_are_honoured() {
        // 40x20 source with 8 spare bytes per row, converted into the top-left 32x16.
        let stride = 40 * 4 + 8;
        let mut src = vec![0u8; stride * 20];
        for row in src.chunks_mut(stride) {
            for px in row[..40 * 4].chunks_mut(4) {
                px.copy_from_slice(&[0, 0, 255, 255]); // red
            }
        }
        let mut frame = YuvFrame::new(YuvFormat::I420, W, H).expect("frame");
        convert_bgrx(&src, stride, &mut frame).expect("convert");
        let (y, u, v) = sample(&frame);
        let (ey, eu, ev) = reference(255, 0, 0);
        assert!((f64::from(y) - ey).abs() <= 2.0);
        assert!((f64::from(u) - eu).abs() <= 2.0);
        assert!((f64::from(v) - ev).abs() <= 2.0);
    }

    #[test]
    fn rejects_bad_input_without_panicking() {
        assert!(YuvFrame::new(YuvFormat::I420, 0, 16).is_err());
        assert!(YuvFrame::new(YuvFormat::I420, 31, 16).is_err());
        let mut frame = YuvFrame::new(YuvFormat::I420, W, H).expect("frame");
        assert!(convert_bgrx(&[0; 10], (W * 4) as usize, &mut frame).is_err());
        assert!(convert_bgrx(&solid(0, 0, 0), 8, &mut frame).is_err());
        assert_eq!(even_size(1921, 1081), (1920, 1080));
    }
}
