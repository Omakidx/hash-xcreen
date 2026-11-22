//! A small ring of RGBA buffers, so a steady stream does not allocate a frame per picture.
//!
//! A `SharedPixelBuffer` handed to Slint stays shared with the displayed `Image`; the ring is
//! deep enough that the buffer reused next is no longer on screen. If one still is, Slint's
//! copy-on-write makes a private copy (correct, just not free).

use slint::{Rgba8Pixel, SharedPixelBuffer};

/// Ring of buffers of one size.
pub struct FramePool {
    ring: Vec<SharedPixelBuffer<Rgba8Pixel>>,
    next: usize,
    size: (u32, u32),
}

impl FramePool {
    /// A pool of `depth` buffers (at least 2).
    pub fn new(depth: usize) -> Self {
        Self {
            ring: Vec::with_capacity(depth.max(2)),
            next: 0,
            size: (0, 0),
        }
    }

    /// Buffers kept.
    pub fn depth(&self) -> usize {
        self.ring.capacity()
    }

    /// The next buffer for a `width` x `height` picture. A size change rebuilds the ring.
    pub fn take(&mut self, width: u32, height: u32) -> &mut SharedPixelBuffer<Rgba8Pixel> {
        if self.size != (width, height) {
            self.ring.clear();
            self.next = 0;
            self.size = (width, height);
        }
        let depth = self.ring.capacity();
        if self.ring.len() < depth {
            self.ring.push(SharedPixelBuffer::new(width, height));
            let i = self.ring.len() - 1;
            self.next = (i + 1) % depth;
            return &mut self.ring[i];
        }
        let i = self.next;
        self.next = (i + 1) % depth;
        &mut self.ring[i]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuses_buffers_in_a_ring_and_rebuilds_on_resize() {
        let mut p = FramePool::new(3);
        let ptrs: Vec<*const Rgba8Pixel> = (0..6)
            .map(|_| p.take(4, 2).make_mut_slice().as_ptr())
            .collect();
        assert_eq!(ptrs[0], ptrs[3]);
        assert_eq!(ptrs[1], ptrs[4]);
        assert_ne!(ptrs[0], ptrs[1]);
        let b = p.take(8, 8);
        assert_eq!((b.width(), b.height()), (8, 8));
    }
}
