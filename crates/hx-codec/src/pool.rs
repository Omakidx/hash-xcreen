//! A small pool of reusable byte buffers, so steady-state encoding does not allocate.

use crossbeam_channel::{Receiver, Sender, bounded};
use std::ops::Deref;

/// A fixed-size pool of `Vec<u8>` buffers. Cloning shares the pool.
#[derive(Clone)]
pub struct BufPool {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    buf_capacity: usize,
}

impl BufPool {
    /// `buffers` buffers are kept for reuse, each created with `buf_capacity` bytes.
    pub fn new(buffers: usize, buf_capacity: usize) -> Self {
        let (tx, rx) = bounded(buffers.max(1));
        for _ in 0..buffers {
            let _ = tx.try_send(Vec::with_capacity(buf_capacity));
        }
        Self {
            tx,
            rx,
            buf_capacity,
        }
    }

    /// An empty buffer. If every pooled buffer is out (the consumer is holding many frames)
    /// a new one is allocated; it joins the pool when returned if there is room.
    pub fn get(&self) -> PooledBuf {
        let buf = self
            .rx
            .try_recv()
            .unwrap_or_else(|_| Vec::with_capacity(self.buf_capacity));
        PooledBuf {
            buf,
            home: Some(self.tx.clone()),
        }
    }
}

/// Bytes borrowed from a [`BufPool`]; dropping returns the buffer to the pool.
pub struct PooledBuf {
    buf: Vec<u8>,
    home: Option<Sender<Vec<u8>>>,
}

impl PooledBuf {
    /// A buffer that belongs to no pool (tests, one-off use).
    pub fn detached(buf: Vec<u8>) -> Self {
        Self { buf, home: None }
    }

    /// Replace the contents with `bytes`.
    pub fn set(&mut self, bytes: &[u8]) {
        self.buf.clear();
        self.buf.extend_from_slice(bytes);
    }

    /// Take the bytes out, leaving the buffer unpooled.
    pub fn into_vec(mut self) -> Vec<u8> {
        self.home = None;
        std::mem::take(&mut self.buf)
    }
}

impl Deref for PooledBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

impl std::fmt::Debug for PooledBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PooledBuf({} bytes)", self.buf.len())
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        if let Some(home) = self.home.take() {
            let mut buf = std::mem::take(&mut self.buf);
            buf.clear();
            let _ = home.try_send(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffers_are_recycled() {
        let pool = BufPool::new(1, 64);
        let mut a = pool.get();
        a.set(&[1, 2, 3]);
        let ptr = a.as_ptr();
        assert_eq!(&*a, &[1, 2, 3]);
        drop(a);
        let b = pool.get();
        assert!(b.is_empty());
        assert_eq!(b.as_ptr(), ptr, "the same allocation comes back");
    }

    #[test]
    fn empty_pool_still_serves_and_overflow_is_dropped() {
        let pool = BufPool::new(1, 8);
        let a = pool.get();
        let b = pool.get(); // allocated, the pool had only one
        drop(a);
        drop(b); // the pool holds one buffer; the second is freed
        assert_eq!(pool.rx.len(), 1);
    }
}
