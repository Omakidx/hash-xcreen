//! Serial-number arithmetic and the client-side video reorder window (protocol §6.1).

/// `a` is strictly newer than `b` in RFC 1982 serial arithmetic over `u32`.
pub fn serial_gt(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < (1 << 31)
}

/// Orders frames that completed out of order and drops stale ones.
///
/// Pure state machine; the caller supplies timing by calling [`release_lowest`](Self::release_lowest)
/// when the hold time of the oldest held frame expires.
#[derive(Debug)]
pub struct ReorderWindow<T> {
    capacity: usize,
    last_released: Option<u32>,
    held: Vec<(u32, T)>,
    dropped_stale: u64,
}

impl<T> ReorderWindow<T> {
    /// A window holding at most `capacity` out-of-order frames (minimum 1).
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            last_released: None,
            held: Vec::new(),
            dropped_stale: 0,
        }
    }

    /// Frames dropped because they were not newer than the last released one.
    pub fn dropped_stale(&self) -> u64 {
        self.dropped_stale
    }

    /// Number of frames currently held back.
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Frame number last handed to the decoder.
    pub fn last_released(&self) -> Option<u32> {
        self.last_released
    }

    fn is_stale(&self, n: u32) -> bool {
        matches!(self.last_released, Some(l) if !serial_gt(n, l))
    }

    /// Offer a completed frame. Returns the frames to decode now, in decode order.
    /// `key` is true for frames flagged `KEY` or `RESYNC`.
    pub fn push(&mut self, frame_number: u32, key: bool, item: T) -> Vec<T> {
        if self.is_stale(frame_number) || self.held.iter().any(|(n, _)| *n == frame_number) {
            self.dropped_stale += 1;
            return Vec::new();
        }
        let mut out = Vec::new();
        // Before anything is released only a key frame goes straight through: the stream starts
        // with one, and a P frame that overtook it would make it stale (protocol §6.1 rule 6).
        let contiguous = match self.last_released {
            None => false,
            Some(l) => frame_number == l.wrapping_add(1),
        };
        if key || contiguous {
            if key {
                // A key frame obsoletes everything older that is still held back.
                let before = self.held.len();
                self.held.retain(|(n, _)| serial_gt(*n, frame_number));
                self.dropped_stale += (before - self.held.len()) as u64;
            }
            self.last_released = Some(frame_number);
            out.push(item);
            self.drain_contiguous(&mut out);
            return out;
        }
        self.held.push((frame_number, item));
        // Sort in serial order from the last released frame, or, before the first release, from
        // just below the oldest held frame (frame numbers may start anywhere, wraparound included).
        let base = match self.last_released {
            Some(l) => l,
            None => {
                let oldest = self
                    .held
                    .iter()
                    .map(|(n, _)| *n)
                    .reduce(|a, b| if serial_gt(a, b) { b } else { a })
                    .unwrap_or(frame_number);
                oldest.wrapping_sub(1)
            }
        };
        self.held.sort_by_key(|(n, _)| n.wrapping_sub(base));
        if self.held.len() > self.capacity {
            out.extend(self.release_lowest());
        }
        out
    }

    /// Release the lowest held frame and any frames now contiguous with it (the hold timer
    /// expired, or the window overflowed). Missing numbers below it become stale.
    pub fn release_lowest(&mut self) -> Vec<T> {
        let mut out = Vec::new();
        if self.held.is_empty() {
            return out;
        }
        let (n, item) = self.held.remove(0);
        self.last_released = Some(n);
        out.push(item);
        self.drain_contiguous(&mut out);
        out
    }

    fn drain_contiguous(&mut self, out: &mut Vec<T>) {
        while let Some(l) = self.last_released {
            match self.held.first() {
                Some((n, _)) if *n == l.wrapping_add(1) => {
                    let (n, item) = self.held.remove(0);
                    self.last_released = Some(n);
                    out.push(item);
                }
                _ => break,
            }
        }
    }
}
