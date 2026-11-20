//! Shared-memory and heap backing for frame buffers. The only module in this crate that
//! needs `unsafe`: one anonymous memory file mapped read-only (the display server writes
//! it through its own mapping) and the slice view over it.
#![allow(unsafe_code)]

use rustix::fd::OwnedFd;
use rustix::fs::{MemfdFlags, ftruncate, memfd_create};
use rustix::mm::{MapFlags, ProtFlags, mmap, munmap};
use std::io;
use std::ptr::NonNull;

/// A read-only mapping of an anonymous memory file.
pub(crate) struct ShmMap {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: the mapping is plain memory owned by this value; it is only read through
// `&self`, and moving it to another thread changes nothing about that.
unsafe impl Send for ShmMap {}

impl ShmMap {
    /// Create a zero-filled memory file of `len` bytes and map it read-only. The returned fd
    /// is handed to the X server (`ShmAttachFd`), which maps it read-write.
    pub(crate) fn create(len: usize) -> io::Result<(ShmMap, OwnedFd)> {
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty shared memory buffer",
            ));
        }
        let fd = memfd_create("hx-capture", MemfdFlags::CLOEXEC)?;
        ftruncate(&fd, len as u64)?;
        // SAFETY: a fresh mapping at a kernel-chosen address of a file we just sized to
        // `len`; no existing Rust object aliases it.
        let raw = unsafe {
            mmap(
                std::ptr::null_mut(),
                len,
                ProtFlags::READ,
                MapFlags::SHARED,
                &fd,
                0,
            )?
        };
        let ptr = NonNull::new(raw.cast::<u8>())
            .ok_or_else(|| io::Error::other("mmap returned a null pointer"))?;
        Ok((ShmMap { ptr, len }, fd))
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` is a live mapping of `len` readable bytes for as long as `self`
        // lives. The X server may write it, but only while a `GetImage` request is in
        // flight, and this crate reads a slot only after that request's reply arrived.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for ShmMap {
    fn drop(&mut self) {
        // SAFETY: unmapping the exact range mapped in `create`, once.
        let _ = unsafe { munmap(self.ptr.as_ptr().cast(), self.len) };
    }
}

/// Pixel memory behind a frame buffer.
pub(crate) enum Memory {
    /// Shared with the X server: reads are copy-free.
    Shm(ShmMap),
    /// Fallback when the server lacks MIT-SHM 1.2: `GetImage` replies are copied in.
    Heap(Vec<u8>),
}

impl Memory {
    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            Memory::Shm(m) => m.as_slice(),
            Memory::Heap(v) => v,
        }
    }
}
