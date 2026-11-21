//! The bounded H.264 Annex B sanity check of `docs/ipc.md` section 15.1 (decision 8, section 22).
//!
//! The gateway never decodes session video, but it refuses a payload that is not even shaped
//! like H.264, and it reads the picture size out of **every** SPS so a hostile session cannot
//! announce one size in `stream_format` and ship another (or a size that would make the client's
//! decoder allocate gigabytes). The rules are strict on purpose, because a decoder allocates the
//! *coded* size and a parser that disagrees with it is a hole (the reviewer's four bypasses):
//!
//! * The payload must begin with an Annex B start code (`00 00 01` or `00 00 00 01`).
//! * The **whole** payload is scanned (at most [`SCAN_LIMIT`], the protocol's payload ceiling;
//!   a longer one is refused). Every NAL header has `forbidden_zero_bit` 0 and a valid type; an
//!   IDR slice (type 5) is only valid in a `KEY` frame.
//! * **Every** SPS (type 7) is parsed, at most [`MAX_SPS_PER_FRAME`] of them, and they must all
//!   announce the same size. [`check_frame`] returns that size; the caller compares it with the
//!   `stream_format` in force on any frame, key or not.
//! * Only the profiles x264 emits are accepted: 66, 77, 88 and 100. Every other profile is
//!   refused, so the parser and the decoder cannot disagree about which profiles carry the
//!   chroma fields.
//! * The **coded** size (macroblocks times 16) is capped before cropping: at most 16 384 per
//!   side and 7680 x 4320 pixels. Cropping may remove less than one macroblock per axis, so the
//!   announced (cropped) size and the allocated (coded) size cannot drift apart.
//!
//! Everything here is total: no function panics or allocates, whatever the input.

use thiserror::Error;

/// The most bytes of a payload that are inspected: the protocol's 16 MiB payload ceiling. A
/// longer payload is refused (it cannot be fully scanned).
pub const SCAN_LIMIT: usize = 16 * 1024 * 1024;
/// SPS NAL units parsed per frame; a frame carrying more is refused (each one costs a parse).
pub const MAX_SPS_PER_FRAME: u32 = 8;
/// Largest coded picture side the link accepts (`hx_ipc::link::validate::MAX_DIMENSION`).
pub const MAX_SIDE: u32 = 16_384;
/// Largest coded picture area the link accepts: 7680 x 4320.
pub const MAX_PIXELS: u64 = 33_177_600;

/// Why a payload was refused. Every variant is a link violation (`docs/ipc.md` 15.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AnnexBError {
    /// The payload does not begin with a start code.
    #[error("payload does not start with an Annex B start code")]
    NoStartCode,
    /// The payload is longer than can be scanned.
    #[error("payload too long to scan")]
    TooLong,
    /// A start code is followed by nothing.
    #[error("empty NAL unit")]
    EmptyNal,
    /// `forbidden_zero_bit` is set.
    #[error("NAL header with forbidden_zero_bit set")]
    ForbiddenBit,
    /// A NAL type outside the defined set.
    #[error("invalid NAL unit type {0}")]
    BadNalType(u8),
    /// An IDR slice in a frame that is not flagged `KEY`.
    #[error("IDR slice in a frame that is not a key frame")]
    IdrInNonKey,
    /// A key frame without an SPS.
    #[error("key frame without a parsable SPS")]
    NoSps,
    /// More SPS NAL units than [`MAX_SPS_PER_FRAME`].
    #[error("too many SPS NAL units in one frame")]
    TooManySps,
    /// Two SPS NAL units of one frame announce different sizes.
    #[error("SPS NAL units of one frame announce different sizes")]
    SpsConflict,
    /// The SPS is malformed, truncated or uses a value outside the supported range.
    #[error("malformed SPS")]
    BadSps,
    /// A profile other than 66, 77, 88 or 100.
    #[error("unsupported H.264 profile {0}")]
    UnsupportedProfile(u8),
    /// Cropping of a macroblock or more on one axis.
    #[error("SPS crops a whole macroblock or more")]
    CropTooLarge,
    /// The SPS announces a coded picture larger than the link allows.
    #[error("SPS coded picture size {width}x{height} exceeds the limit")]
    TooLarge {
        /// Coded width (macroblocks times 16).
        width: u32,
        /// Coded height.
        height: u32,
    },
}

/// The picture size an SPS announces, after cropping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpsInfo {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

/// What a successful check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checked {
    /// NAL units seen (saturating).
    pub nal_units: u32,
    /// The size every SPS of the frame announces (they all agree), if the frame has one.
    pub sps: Option<SpsInfo>,
    /// How many SPS NAL units the frame carries.
    pub sps_count: u32,
}

/// True for the NAL types an H.264 stream may carry: 1 to 15, 19 (auxiliary slice), 20 and 21
/// (SVC/MVC extensions). 0, the reserved 16 to 18 and 22 to 31 are refused.
pub fn nal_type_is_valid(t: u8) -> bool {
    matches!(t, 1..=15 | 19..=21)
}

/// Position of the next `00 00 01` at or after `from`, as the index of its first byte.
fn find_start_code(b: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 3 <= b.len() {
        // Skip quickly past bytes that cannot begin a start code.
        match b[i + 2] {
            0 => i += 1,
            1 if b[i] == 0 && b[i + 1] == 0 => return Some(i),
            _ => i += 3,
        }
    }
    None
}

/// Checks `payload` (see the module docs). `key` says the frame is flagged `KEY`: it then must
/// carry an SPS, and only a key frame may carry an IDR slice.
pub fn check_frame(payload: &[u8], key: bool) -> Result<Checked, AnnexBError> {
    if payload.len() > SCAN_LIMIT {
        return Err(AnnexBError::TooLong);
    }
    let first = match payload {
        [0, 0, 1, ..] => 0,
        [0, 0, 0, 1, ..] => 1,
        _ => return Err(AnnexBError::NoStartCode),
    };
    let mut nal_units = 0u32;
    let mut sps: Option<SpsInfo> = None;
    let mut sps_count = 0u32;
    let mut at = Some(first);
    while let Some(start) = at {
        let header_at = start + 3;
        let next = find_start_code(payload, header_at);
        // The NAL ends at the next start code (a leading zero_byte of a 4-byte code is trimmed
        // by the parser, which stops reading well before it) or at the payload's end.
        let end = next.unwrap_or(payload.len());
        let Some(&header) = (header_at < end).then(|| &payload[header_at]) else {
            return Err(AnnexBError::EmptyNal);
        };
        if header & 0x80 != 0 {
            return Err(AnnexBError::ForbiddenBit);
        }
        let t = header & 0x1f;
        if !nal_type_is_valid(t) {
            return Err(AnnexBError::BadNalType(t));
        }
        if t == 5 && !key {
            return Err(AnnexBError::IdrInNonKey);
        }
        nal_units = nal_units.saturating_add(1);
        if t == 7 {
            if sps_count >= MAX_SPS_PER_FRAME {
                return Err(AnnexBError::TooManySps);
            }
            sps_count += 1;
            let info = parse_sps(&payload[header_at + 1..end])?;
            match sps {
                None => sps = Some(info),
                Some(prev) if prev != info => return Err(AnnexBError::SpsConflict),
                Some(_) => {}
            }
        }
        at = next;
    }
    if key && sps.is_none() {
        return Err(AnnexBError::NoSps);
    }
    Ok(Checked {
        nal_units,
        sps,
        sps_count,
    })
}

/// RBSP bit reader that skips emulation-prevention bytes (`00 00 03`) on the fly.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    cur: u8,
    used: u8,
    zeros: u8,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            cur: 0,
            used: 8,
            zeros: 0,
        }
    }

    fn load(&mut self) -> Option<()> {
        loop {
            let b = *self.data.get(self.pos)?;
            self.pos += 1;
            if self.zeros >= 2 && b == 3 {
                self.zeros = 0;
                continue;
            }
            self.zeros = if b == 0 {
                self.zeros.saturating_add(1)
            } else {
                0
            };
            self.cur = b;
            self.used = 0;
            return Some(());
        }
    }

    fn bit(&mut self) -> Option<u32> {
        if self.used == 8 {
            self.load()?;
        }
        let v = (self.cur >> (7 - self.used)) & 1;
        self.used += 1;
        Some(u32::from(v))
    }

    fn flag(&mut self) -> Option<bool> {
        self.bit().map(|b| b == 1)
    }

    /// `n` bits, `n <= 32`.
    fn bits(&mut self, n: u32) -> Option<u32> {
        let mut v = 0u64;
        for _ in 0..n {
            v = (v << 1) | u64::from(self.bit()?);
        }
        u32::try_from(v).ok()
    }

    /// Unsigned exp-Golomb. Values that do not fit in 32 bits are refused.
    fn ue(&mut self) -> Option<u32> {
        let mut zeros = 0u32;
        while self.bit()? == 0 {
            zeros += 1;
            if zeros >= 32 {
                return None;
            }
        }
        let rest = self.bits(zeros)?;
        u32::try_from((1u64 << zeros) - 1 + u64::from(rest)).ok()
    }

    /// `ue` with an upper bound.
    fn ue_max(&mut self, max: u32) -> Option<u32> {
        self.ue().filter(|v| *v <= max)
    }

    /// Signed exp-Golomb.
    fn se(&mut self) -> Option<i64> {
        let k = i64::from(self.ue()?);
        Some(if k % 2 == 1 { (k + 1) / 2 } else { -(k / 2) })
    }
}

fn skip_scaling_list(r: &mut Bits<'_>, size: u32) -> Option<()> {
    let (mut last, mut next) = (8i64, 8i64);
    for _ in 0..size {
        if next != 0 {
            let delta = r.se()?;
            if !(-128..=127).contains(&delta) {
                return None;
            }
            next = (last + delta + 256).rem_euclid(256);
        }
        if next != 0 {
            last = next;
        }
    }
    Some(())
}

/// Parses an SPS NAL unit body (after its one-byte NAL header) down to the picture size.
fn parse_sps(rbsp: &[u8]) -> Result<SpsInfo, AnnexBError> {
    sps_inner(rbsp).ok_or(AnnexBError::BadSps).and_then(|r| r)
}

fn sps_inner(rbsp: &[u8]) -> Option<Result<SpsInfo, AnnexBError>> {
    let mut r = Bits::new(rbsp);
    let profile = r.bits(8)?;
    // Only what x264 writes: baseline, main, extended and high. Every other profile (including
    // the ones other decoders read chroma fields for) is refused, so no two parsers can disagree
    // about the layout.
    if !matches!(profile, 66 | 77 | 88 | 100) {
        return Some(Err(AnnexBError::UnsupportedProfile(profile as u8)));
    }
    let _constraints = r.bits(8)?;
    let _level = r.bits(8)?;
    let _sps_id = r.ue_max(31)?;
    let mut chroma_format_idc = 1u32;
    let mut separate_planes = false;
    if profile == 100 {
        chroma_format_idc = r.ue_max(3)?;
        if chroma_format_idc == 3 {
            separate_planes = r.flag()?;
        }
        r.ue_max(6)?; // bit_depth_luma_minus8
        r.ue_max(6)?; // bit_depth_chroma_minus8
        r.flag()?; // qpprime_y_zero_transform_bypass_flag
        if r.flag()? {
            let lists = if chroma_format_idc == 3 { 12 } else { 8 };
            for i in 0..lists {
                if r.flag()? {
                    skip_scaling_list(&mut r, if i < 6 { 16 } else { 64 })?;
                }
            }
        }
    }
    r.ue_max(12)?; // log2_max_frame_num_minus4
    match r.ue_max(2)? {
        0 => {
            r.ue_max(12)?; // log2_max_pic_order_cnt_lsb_minus4
        }
        1 => {
            r.flag()?;
            r.se()?;
            r.se()?;
            for _ in 0..r.ue_max(255)? {
                r.se()?;
            }
        }
        _ => {}
    }
    r.ue_max(16)?; // max_num_ref_frames
    r.flag()?; // gaps_in_frame_num_value_allowed_flag
    let width_mbs = u64::from(r.ue()?) + 1;
    let height_map_units = u64::from(r.ue()?) + 1;
    let frame_mbs_only = r.flag()?;
    if !frame_mbs_only {
        r.flag()?; // mb_adaptive_frame_field_flag
    }
    r.flag()?; // direct_8x8_inference_flag
    let (mut crop_l, mut crop_r, mut crop_t, mut crop_b) = (0u64, 0u64, 0u64, 0u64);
    if r.flag()? {
        crop_l = u64::from(r.ue()?);
        crop_r = u64::from(r.ue()?);
        crop_t = u64::from(r.ue()?);
        crop_b = u64::from(r.ue()?);
    }
    let map_mult = if frame_mbs_only { 1 } else { 2 };
    // The decoder allocates the CODED size, so that is what is capped, before any cropping.
    let coded_w = width_mbs * 16;
    let coded_h = height_map_units * 16 * map_mult;
    if coded_w > u64::from(MAX_SIDE)
        || coded_h > u64::from(MAX_SIDE)
        || coded_w * coded_h > MAX_PIXELS
    {
        return Some(Err(AnnexBError::TooLarge {
            width: u32::try_from(coded_w).unwrap_or(u32::MAX),
            height: u32::try_from(coded_h).unwrap_or(u32::MAX),
        }));
    }
    // ChromaArrayType 0 (monochrome or separate planes) crops in single pixels.
    let chroma_array_type = if separate_planes {
        0
    } else {
        chroma_format_idc
    };
    let (unit_x, unit_y) = match chroma_array_type {
        0 => (1, map_mult),
        1 => (2, 2 * map_mult),
        2 => (2, map_mult),
        _ => (1, map_mult),
    };
    // At most less than one macroblock (of the coded unit) may be cropped per axis: the announced
    // size can then never be far from the allocated one.
    let (cut_x, cut_y) = ((crop_l + crop_r) * unit_x, (crop_t + crop_b) * unit_y);
    if cut_x >= 16 || cut_y >= 16 * map_mult {
        return Some(Err(AnnexBError::CropTooLarge));
    }
    Some(Ok(SpsInfo {
        width: (coded_w - cut_x) as u32,
        height: (coded_h - cut_y) as u32,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bit writer for building SPS test vectors independently of the parser.
    #[derive(Default)]
    struct W {
        bits: Vec<u8>,
    }
    impl W {
        fn put(&mut self, v: u32, n: u32) {
            for i in (0..n).rev() {
                self.bits.push(((v >> i) & 1) as u8);
            }
        }
        fn ue(&mut self, v: u32) {
            let x = u64::from(v) + 1;
            let len = 64 - x.leading_zeros();
            for _ in 0..len - 1 {
                self.bits.push(0);
            }
            for i in (0..len).rev() {
                self.bits.push(((x >> i) & 1) as u8);
            }
        }
        fn se(&mut self, v: i32) {
            self.ue(if v > 0 {
                (2 * v - 1) as u32
            } else {
                (-2 * v) as u32
            });
        }
        fn bytes(&self) -> Vec<u8> {
            let mut out = Vec::new();
            let mut bits = self.bits.clone();
            bits.push(1); // rbsp_stop_one_bit
            while !bits.len().is_multiple_of(8) {
                bits.push(0);
            }
            for c in bits.chunks(8) {
                out.push(c.iter().fold(0, |a, b| (a << 1) | b));
            }
            // emulation prevention
            let mut ep = Vec::new();
            let mut zeros = 0;
            for b in out {
                if zeros >= 2 && b <= 3 {
                    ep.push(3);
                    zeros = 0;
                }
                zeros = if b == 0 { zeros + 1 } else { 0 };
                ep.push(b);
            }
            ep
        }
    }

    #[derive(Clone, Copy)]
    struct Sps {
        profile: u32,
        chroma: u32,
        w_mbs: u32,
        h_units: u32,
        frame_mbs_only: bool,
        crop: Option<(u32, u32, u32, u32)>,
        scaling: bool,
        poc_type: u32,
    }

    fn sps_nal(s: &Sps) -> Vec<u8> {
        let mut w = W::default();
        w.put(s.profile, 8);
        w.put(0, 8);
        w.put(40, 8);
        w.ue(0);
        if s.profile >= 100 {
            w.ue(s.chroma);
            if s.chroma == 3 {
                w.put(0, 1);
            }
            w.ue(0);
            w.ue(0);
            w.put(0, 1);
            w.put(u32::from(s.scaling), 1);
            if s.scaling {
                let lists = if s.chroma == 3 { 12 } else { 8 };
                for i in 0..lists {
                    // Every other list present; present lists use a few deltas then 0 to end.
                    let present = i % 2 == 0;
                    w.put(u32::from(present), 1);
                    if present {
                        // size 16 or 64; deltas that end the list early (next scale 0).
                        w.se(-8);
                    }
                }
            }
        }
        w.ue(4);
        w.ue(s.poc_type);
        match s.poc_type {
            0 => w.ue(4),
            1 => {
                w.put(0, 1);
                w.se(-3);
                w.se(5);
                w.ue(2);
                w.se(1);
                w.se(-1);
            }
            _ => {}
        }
        w.ue(4);
        w.put(0, 1);
        w.ue(s.w_mbs - 1);
        w.ue(s.h_units - 1);
        w.put(u32::from(s.frame_mbs_only), 1);
        if !s.frame_mbs_only {
            w.put(0, 1);
        }
        w.put(1, 1);
        match s.crop {
            Some((l, r, t, b)) => {
                w.put(1, 1);
                w.ue(l);
                w.ue(r);
                w.ue(t);
                w.ue(b);
            }
            None => w.put(0, 1),
        }
        w.put(0, 1); // vui_parameters_present_flag
        let mut nal = vec![0, 0, 0, 1, 0x67];
        nal.extend(w.bytes());
        nal
    }

    fn base() -> Sps {
        Sps {
            profile: 100,
            chroma: 1,
            w_mbs: 120,
            h_units: 68,
            frame_mbs_only: true,
            crop: Some((0, 0, 0, 4)),
            scaling: false,
            poc_type: 0,
        }
    }

    fn frame(sps: &Sps) -> Vec<u8> {
        let mut f = sps_nal(sps);
        f.extend([0, 0, 0, 1, 0x68, 0xCE, 0x3C, 0x80]);
        f.extend([0, 0, 1, 0x65, 0x88, 0x84, 0x00, 0x10]);
        f
    }

    #[test]
    fn real_1080p_sps_parses_to_1920_by_1080() {
        // x264 / ffmpeg 1080p High profile SPS and PPS.
        let mut f = vec![0, 0, 0, 1];
        f.extend([
            0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40, 0x78, 0x02, 0x27, 0xE5, 0xC0, 0x44, 0x00,
            0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xF0, 0x3C, 0x60, 0xC6, 0x58,
        ]);
        f.extend([0, 0, 0, 1, 0x68, 0xEB, 0xE3, 0xCB, 0x22, 0xC0]);
        f.extend([0, 0, 1, 0x65, 0x88, 0x84]);
        let c = check_frame(&f, true).unwrap();
        assert_eq!(
            c.sps,
            Some(SpsInfo {
                width: 1920,
                height: 1080
            })
        );
        assert_eq!(c.nal_units, 3);
    }

    #[test]
    fn constructed_sps_variants_parse_to_their_cropped_size() {
        let c = check_frame(&frame(&base()), true).unwrap();
        assert_eq!(
            c.sps,
            Some(SpsInfo {
                width: 1920,
                height: 1080
            })
        );

        let mut s = base();
        s.profile = 66; // baseline: no chroma fields at all
        s.crop = Some((0, 0, 0, 0));
        s.w_mbs = 40;
        s.h_units = 22;
        assert_eq!(
            check_frame(&frame(&s), true).unwrap().sps,
            Some(SpsInfo {
                width: 640,
                height: 352
            })
        );

        // 4:4:4 crops in single pixels, 4:2:2 crops width by 2 and height by 1.
        let mut s = base();
        s.chroma = 3;
        s.crop = Some((1, 2, 3, 4));
        s.w_mbs = 10;
        s.h_units = 10;
        assert_eq!(
            check_frame(&frame(&s), true).unwrap().sps,
            Some(SpsInfo {
                width: 160 - 3,
                height: 160 - 7
            })
        );
        s.chroma = 2;
        assert_eq!(
            check_frame(&frame(&s), true).unwrap().sps,
            Some(SpsInfo {
                width: 160 - 6,
                height: 160 - 7
            })
        );
        // Interlaced content doubles the vertical units.
        s.chroma = 1;
        s.frame_mbs_only = false;
        s.h_units = 5;
        s.crop = Some((0, 0, 1, 1));
        assert_eq!(
            check_frame(&frame(&s), true).unwrap().sps,
            Some(SpsInfo {
                width: 160,
                height: 160 - 8
            })
        );
        // Scaling matrices and the other POC types are skipped correctly.
        for poc in [0, 1, 2] {
            let mut s = base();
            s.scaling = true;
            s.poc_type = poc;
            assert_eq!(
                check_frame(&frame(&s), true).unwrap().sps,
                Some(SpsInfo {
                    width: 1920,
                    height: 1080
                }),
                "poc type {poc}"
            );
        }
    }

    #[test]
    fn oversized_pictures_are_refused() {
        let mut s = base();
        s.w_mbs = 1025; // 16 400 px
        s.crop = None;
        assert!(matches!(
            check_frame(&frame(&s), true),
            Err(AnnexBError::TooLarge { width: 16_400, .. })
        ));
        // Within the side limit but over the pixel cap: 8192 x 8192.
        let mut s = base();
        s.w_mbs = 512;
        s.h_units = 512;
        s.crop = None;
        assert!(matches!(
            check_frame(&frame(&s), true),
            Err(AnnexBError::TooLarge { .. })
        ));
        // Absurd values do not overflow.
        let mut s = base();
        s.w_mbs = u32::MAX - 1;
        s.crop = None;
        assert!(matches!(
            check_frame(&frame(&s), true),
            Err(AnnexBError::TooLarge { .. })
        ));
        // Cropping everything away is refused (more than a macroblock).
        let mut s = base();
        s.crop = Some((u32::MAX / 4, u32::MAX / 4, 0, 0));
        assert_eq!(
            check_frame(&frame(&s), true),
            Err(AnnexBError::CropTooLarge)
        );
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// SPS, PPS and an IDR stub around a real SPS NAL given as hex (without start code).
    fn with_sps(sps_hex: &str) -> Vec<u8> {
        let mut f = vec![0, 0, 0, 1];
        f.extend(hex(sps_hex));
        f.extend([0, 0, 0, 1, 0x68, 0xCE, 0x0F, 0xC8]);
        f.extend([0, 0, 1, 0x65, 0x88, 0x84, 0x3A]);
        f
    }

    // The reviewer's streams (FFmpeg 6.1 confirmed each one in the 1C security review). Their SPS
    // NAL units are embedded here; the slice data is irrelevant to this check.

    #[test]
    fn t0_the_real_x264_64x64_sps_is_accepted() {
        let f = with_sps("6742c00ada109b011000000300100000030028f1226a");
        let c = check_frame(&f, true).unwrap();
        assert_eq!(
            c.sps,
            Some(SpsInfo {
                width: 64,
                height: 64
            })
        );
        assert_eq!(c.sps_count, 1);
    }

    #[test]
    fn t1_an_8000x8000_sps_cropped_to_64x64_is_refused() {
        // FFmpeg reinitialised the decoder to 8000x8000 for this stream.
        let f = with_sps("6742c00ada007d003e9e003e06003e07011000000300100000030028f1226a");
        assert!(matches!(
            check_frame(&f, true),
            Err(AnnexBError::TooLarge {
                width: 8000,
                height: 8000
            })
        ));
        // A smaller hidden size: 4096x4096 coded, cropped to 64x64, crops more than a macroblock.
        let mut s = base();
        s.profile = 66;
        s.w_mbs = 256;
        s.h_units = 256;
        s.crop = Some((0, (4096 - 64) / 2, 0, (4096 - 64) / 2));
        assert_eq!(
            check_frame(&frame(&s), true),
            Err(AnnexBError::CropTooLarge)
        );
        // Less than a macroblock of crop still passes (the honest 1080p crop is 8 rows).
        let mut s = base();
        s.crop = Some((0, 0, 0, 7));
        assert_eq!(
            check_frame(&frame(&s), true).unwrap().sps,
            Some(SpsInfo {
                width: 1920,
                height: 1088 - 14
            })
        );
    }

    #[test]
    fn t2_every_sps_counts_not_only_the_first() {
        // The real 64x64 SPS first, then a second one with the same id announcing 8192x8192.
        let mut f = vec![0, 0, 0, 1];
        f.extend(hex("6742c00ada109b011000000300100000030028f1226a"));
        f.extend([0, 0, 0, 1]);
        f.extend(hex("6742c00ada0020000401b011000003000100000300028f1226a0"));
        f.extend([0, 0, 0, 1, 0x68, 0xCE, 0x0F, 0xC8, 0, 0, 1, 0x65, 0x88]);
        assert!(matches!(
            check_frame(&f, true),
            Err(AnnexBError::TooLarge { .. } | AnnexBError::SpsConflict)
        ));
        // Two legal SPS of different sizes in one frame conflict.
        let mut a = base();
        a.profile = 66;
        a.crop = None;
        a.w_mbs = 4;
        a.h_units = 4;
        let b = Sps {
            w_mbs: 8,
            h_units: 8,
            ..a
        };
        let mut f = sps_nal(&a);
        f.extend(sps_nal(&b));
        f.extend([0, 0, 1, 0x65, 0x88]);
        assert_eq!(check_frame(&f, true), Err(AnnexBError::SpsConflict));
        // The same size twice is fine and counted.
        let mut f = sps_nal(&a);
        f.extend(sps_nal(&a));
        f.extend([0, 0, 1, 0x65, 0x88]);
        let c = check_frame(&f, true).unwrap();
        assert_eq!(
            (c.sps_count, c.sps),
            (
                2,
                Some(SpsInfo {
                    width: 64,
                    height: 64
                })
            )
        );
        // An SPS after the old 64 KiB window is still read.
        let mut f = vec![0, 0, 1, 0x41];
        f.resize(70_000, 0xAA);
        f.extend(sps_nal(&b));
        assert_eq!(
            check_frame(&f, false).unwrap().sps,
            Some(SpsInfo {
                width: 128,
                height: 128
            })
        );
        // A flood of SPS NAL units is refused.
        let mut f = Vec::new();
        for _ in 0..=MAX_SPS_PER_FRAME {
            f.extend(sps_nal(&a));
        }
        assert_eq!(check_frame(&f, false), Err(AnnexBError::TooManySps));
        // A payload that cannot be fully scanned is refused.
        let mut f = vec![0, 0, 1, 0x41];
        f.resize(SCAN_LIMIT + 1, 0xAA);
        assert_eq!(check_frame(&f, false), Err(AnnexBError::TooLong));
    }

    #[test]
    fn t3_an_idr_slice_outside_a_key_frame_is_refused_and_a_non_key_sps_is_reported() {
        // SPS (1280x720) + IDR in a frame not flagged KEY: refused outright.
        let mut s = base();
        s.w_mbs = 80;
        s.h_units = 45;
        s.crop = None;
        assert_eq!(
            check_frame(&frame(&s), false),
            Err(AnnexBError::IdrInNonKey)
        );
        // A non-key frame carrying only an SPS is parsed, and its size is returned so the caller
        // can compare it with the format in force.
        let f = sps_nal(&s);
        assert_eq!(
            check_frame(&f, false).unwrap().sps,
            Some(SpsInfo {
                width: 1280,
                height: 720
            })
        );
    }

    #[test]
    fn t4_only_the_profiles_x264_emits_are_accepted() {
        // 144, 139, 134 and 135 made the old parser and FFmpeg disagree about the size.
        for (p, sps) in [
            (144, "67900028ac6c900c7006f320"),
            (139, "678b0028b4f0074c037190"),
            (134, "67860028aa1f00d3805772"),
            (135, "67870028e43c028201edc8"),
        ] {
            assert_eq!(
                check_frame(&with_sps(sps), true),
                Err(AnnexBError::UnsupportedProfile(p)),
                "profile {p}"
            );
        }
        // Every profile number other than the four is refused; the four are parsed.
        for p in 0..=255u8 {
            let mut f = vec![0, 0, 0, 1, 0x67, p, 0, 40];
            f.extend([0xAA; 12]);
            let r = check_frame(&f, false);
            if matches!(p, 66 | 77 | 88 | 100) {
                assert!(!matches!(r, Err(AnnexBError::UnsupportedProfile(_))), "{p}");
            } else {
                assert_eq!(r, Err(AnnexBError::UnsupportedProfile(p)), "{p}");
            }
        }
    }

    #[test]
    fn structure_rules() {
        // No start code, empty NAL, forbidden bit, bad types.
        assert_eq!(check_frame(b"", false), Err(AnnexBError::NoStartCode));
        assert_eq!(
            check_frame(&[1, 2, 3, 4], false),
            Err(AnnexBError::NoStartCode)
        );
        assert_eq!(check_frame(&[0, 0, 1], false), Err(AnnexBError::EmptyNal));
        assert_eq!(
            check_frame(&[0, 0, 1, 0x81, 0], false),
            Err(AnnexBError::ForbiddenBit)
        );
        for t in [0u8, 16, 17, 18, 22, 23, 24, 31] {
            assert_eq!(
                check_frame(&[0, 0, 1, t, 0xAA], false),
                Err(AnnexBError::BadNalType(t)),
                "type {t}"
            );
        }
        assert_eq!(
            check_frame(&[0, 0, 1, 0x41, 0xAA, 0, 0, 1, 0x1F, 1], false),
            Err(AnnexBError::BadNalType(31))
        );
        // A P frame needs no SPS; a key frame does.
        let p = [0, 0, 0, 1, 0x41, 0x9A, 0x00, 0x01];
        assert_eq!(check_frame(&p, false).unwrap().nal_units, 1);
        assert_eq!(check_frame(&p, true), Err(AnnexBError::NoSps));
        // A truncated SPS is malformed.
        assert_eq!(
            check_frame(&[0, 0, 0, 1, 0x67, 0x64, 0x00], true),
            Err(AnnexBError::BadSps)
        );
    }

    #[test]
    fn total_on_arbitrary_bytes() {
        // A cheap deterministic fuzz: never panics, whatever the bytes.
        let mut x = 0x1234_5678u32;
        for _ in 0..2_000 {
            let len = (x % 200) as usize;
            let mut v = Vec::with_capacity(len + 4);
            v.extend([0, 0, 1, 0x67]);
            for _ in 0..len {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                v.push((x >> 24) as u8);
            }
            let _ = check_frame(&v, true);
            let _ = check_frame(&v, false);
        }
    }
}
