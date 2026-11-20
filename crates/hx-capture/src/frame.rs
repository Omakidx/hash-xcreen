use crate::geometry::{Rect, Size};
use crate::shm::Memory;
use crossbeam_channel::Sender;

/// Layout of the bytes in [`Frame::data`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    /// Little-endian 32-bit pixels: bytes are B, G, R, then an unused byte (treat as opaque).
    Bgrx,
}

/// A pooled buffer: pixel memory plus the damage rectangles of the capture it holds.
pub(crate) struct SlotBuf {
    pub(crate) mem: Memory,
    /// X server segment id when the memory is shared with it.
    pub(crate) seg: Option<u32>,
    pub(crate) damage: Vec<Rect>,
    /// Size this slot was allocated for.
    pub(crate) size: Size,
}

/// One captured screen image. Dropping it returns the buffer to the backend's pool.
pub struct Frame {
    pub(crate) seq: u64,
    pub(crate) size: Size,
    pub(crate) stride: usize,
    pub(crate) t_damage_ns: u64,
    pub(crate) t_capture_ns: u64,
    pub(crate) buf: Option<SlotBuf>,
    pub(crate) ret: Sender<SlotBuf>,
}

impl Frame {
    /// Capture sequence number, starting at 0, counting every grab of this backend.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn size(&self) -> Size {
        self.size
    }

    pub fn format(&self) -> PixelFormat {
        PixelFormat::Bgrx
    }

    /// Bytes per row.
    pub fn stride(&self) -> usize {
        self.stride
    }

    /// `stride * height` bytes of pixels.
    pub fn data(&self) -> &[u8] {
        match &self.buf {
            Some(b) => &b.mem.as_slice()[..self.stride * self.size.height as usize],
            None => &[],
        }
    }

    /// Regions that changed since the previous capture (clipped to the frame; the whole
    /// frame after a resize, a forced capture or too many small rectangles).
    pub fn damage(&self) -> &[Rect] {
        match &self.buf {
            Some(b) => &b.damage,
            None => &[],
        }
    }

    /// Bounding box of [`Frame::damage`].
    pub fn damage_bounds(&self) -> Rect {
        self.damage()
            .iter()
            .fold(Rect::new(0, 0, 0, 0), |acc, r| acc.union(*r))
    }

    /// When the damage behind this frame first arrived ([`crate::mono_ns`]).
    pub fn t_damage_ns(&self) -> u64 {
        self.t_damage_ns
    }

    /// When the pixels were read ([`crate::mono_ns`]).
    pub fn t_capture_ns(&self) -> u64 {
        self.t_capture_ns
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            // The pool never holds more slots than its channel capacity, so this cannot
            // block; if the backend is gone the buffer is simply freed.
            let _ = self.ret.send(buf);
        }
    }
}
