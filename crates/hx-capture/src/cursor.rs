use std::sync::Arc;

/// A cursor image. `id` is a content hash, so equal images get equal ids across
/// reconnects and the receiver can cache shapes by id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CursorShape {
    pub id: u64,
    pub width: u16,
    pub height: u16,
    pub xhot: u16,
    pub yhot: u16,
    /// Premultiplied ARGB, row-major, `width * height` entries.
    pub argb: Vec<u32>,
}

impl CursorShape {
    pub(crate) fn new(width: u16, height: u16, xhot: u16, yhot: u16, argb: Vec<u32>) -> Self {
        // FNV-1a over geometry and pixels; cursors are small, so this is cheap.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mut feed = |bytes: &[u8]| {
            for b in bytes {
                h ^= u64::from(*b);
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        };
        for v in [width, height, xhot, yhot] {
            feed(&v.to_le_bytes());
        }
        for p in &argb {
            feed(&p.to_le_bytes());
        }
        Self {
            id: h,
            width,
            height,
            xhot,
            yhot,
            argb,
        }
    }
}

/// Pointer position in screen coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorPosition {
    pub x: i16,
    pub y: i16,
    /// When the position was read ([`crate::mono_ns`]).
    pub t_ns: u64,
}

/// Events for the cursor channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CursorEvent {
    /// The cursor image changed (or was re-requested with `refresh_cursor`).
    Shape(Arc<CursorShape>),
    Position(CursorPosition),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_content_hash() {
        let a = CursorShape::new(2, 1, 0, 0, vec![1, 2]);
        let b = CursorShape::new(2, 1, 0, 0, vec![1, 2]);
        let c = CursorShape::new(2, 1, 1, 0, vec![1, 2]);
        let d = CursorShape::new(2, 1, 0, 0, vec![1, 3]);
        assert_eq!(a.id, b.id);
        assert_ne!(a.id, c.id);
        assert_ne!(a.id, d.id);
    }
}
