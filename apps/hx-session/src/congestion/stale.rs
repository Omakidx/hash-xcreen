//! The resync gate: after stale frames were cancelled, everything encoded before the next
//! IDR is built on frames the client never got, so it is dropped unsent, and the IDR is
//! flagged `RESYNC`.

/// What to do with a frame the encoder has just produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameDisposition {
    /// Send it. `resync` means set the `RESYNC` flag in the media header.
    Send { resync: bool },
    /// Do not send: it depends on frames that were cancelled.
    Drop,
}

#[derive(Debug, Default)]
pub(crate) struct ResyncGate {
    armed: bool,
}

impl ResyncGate {
    pub(crate) fn arm(&mut self) {
        self.armed = true;
    }

    pub(crate) fn is_armed(&self) -> bool {
        self.armed
    }

    pub(crate) fn on_frame_ready(&mut self, idr: bool) -> FrameDisposition {
        match (self.armed, idr) {
            (false, _) => FrameDisposition::Send { resync: false },
            (true, true) => {
                self.armed = false;
                FrameDisposition::Send { resync: true }
            }
            (true, false) => FrameDisposition::Drop,
        }
    }
}
