//! Quality refinement of a static picture (architecture 6.2).
//!
//! Rate control spends at most what the VBV buffer allows on a frame. A key frame requested
//! while the buffer is empty (a busy screen, a link on a low rung of the ladder, or a resync
//! after loss) is a complete IDR whose picture is far from the screen: at 1 Mbit/s a
//! text-dense 720p IDR decodes to flat grey. The display then stops changing, so no more
//! frames are captured and the client keeps that picture for good. This was the "grey picture
//! after loss" defect of the lossy end-to-end run (testing.md 2.8).
//!
//! The cure is to keep encoding the *unchanged* picture for a short while: each such P frame
//! adds what the budget allows, and the picture converges within a bounded number of frames
//! (about 60 at 1 Mbit/s for the densest text, a handful at the usual rates). This module is
//! the pure policy; the pipeline owns the threads and the clock.

use std::time::Duration;

/// Most refinement frames after one trigger (about 1.5 s at the pass rate below).
pub const MAX_PASSES: u32 = 90;

/// Quiet time after the last capture before a refinement frame is taken, so a screen that is
/// still changing is never refined (its own frames do the job) and refinement frames are
/// spaced for the rate control.
pub const QUIET: Duration = Duration::from_millis(15);

/// A P frame of an unchanged picture at most this big has nothing left to add (an all-skip
/// 720p frame is about 50 bytes). Together with a normal QP: a tiny frame at a high QP is an
/// empty VBV buffer, not a converged picture.
pub const SETTLED_BYTES: usize = 300;

/// A frame the rate control encoded at this QP or above hit its budget: crf 23 gives 20 to 30
/// for text, a starved IDR 50 and more.
pub const STARVED_QP: u8 = 36;

/// What the encoder just produced, for [`next_left`].
#[derive(Clone, Copy, Debug)]
pub struct FrameInfo {
    /// An IDR (connect, resync, resize).
    pub idr: bool,
    /// The frame came from a refinement capture rather than from display damage.
    pub refinement: bool,
    /// Encoded size.
    pub bytes: usize,
    /// Average QP of the frame, when the encoder reports it.
    pub qp: Option<u8>,
}

impl FrameInfo {
    /// The budget, not the picture, decided this frame's quality.
    fn starved(&self) -> bool {
        match self.qp {
            Some(q) => q >= STARVED_QP,
            // Without the statistic a key frame is assumed coarse: a refinement is cheap.
            None => self.idr,
        }
    }
}

/// Refinement frames still wanted after `f`, given `left` before it.
pub fn next_left(left: u32, f: FrameInfo) -> u32 {
    if f.refinement {
        // Converged: the picture is at the rate control's normal quality, or a frame of an
        // unchanged picture has nothing left to say. A pass never re-arms itself.
        let settled = f.bytes <= SETTLED_BYTES && !f.starved();
        return if settled { 0 } else { left };
    }
    if f.starved() { MAX_PASSES } else { left }
}

/// True when a refinement capture is due: some passes are left, nothing is pending from the
/// display and the last capture is at least [`QUIET`] ago.
pub fn due(left: u32, damage_pending: bool, since_last_capture: Duration) -> bool {
    left > 0 && !damage_pending && since_last_capture >= QUIET
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(idr: bool, refinement: bool, bytes: usize, qp: Option<u8>) -> FrameInfo {
        FrameInfo {
            idr,
            refinement,
            bytes,
            qp,
        }
    }

    #[test]
    fn a_starved_key_frame_starts_a_run_and_a_settled_frame_ends_it() {
        // A small IDR at a very high QP (the lossy run's 2.8 KB grey key frame).
        let mut left = next_left(0, f(true, false, 2_800, Some(58)));
        assert_eq!(left, MAX_PASSES);
        // The run continues while the passes are still budget-bound.
        for _ in 0..5 {
            left = next_left(left - 1, f(false, true, 3_000, Some(45)));
            assert!(left > 0);
        }
        // A pass at the normal QP that still carries a lot is not done (the lossy run ended
        // its refinement on such a frame and left the top of the picture grey).
        left = next_left(left - 1, f(false, true, 12_000, Some(33)));
        assert!(left > 0);
        // A tiny pass at a high QP is an empty VBV buffer, not a converged picture.
        assert_eq!(next_left(5, f(false, true, 52, Some(45))), 5);
        // A tiny pass at the normal QP has nothing left to add: done.
        assert_eq!(next_left(5, f(false, true, 52, Some(27))), 0);
        // Without the statistic the size alone decides.
        assert_eq!(next_left(5, f(false, true, 120, None)), 0);
    }

    #[test]
    fn frames_at_the_normal_quality_do_not_start_a_run() {
        // The first IDR of a blank desktop, a typing frame.
        assert_eq!(next_left(0, f(true, false, 3_600, Some(24))), 0);
        assert_eq!(next_left(0, f(false, false, 1_500, Some(27))), 0);
        // A budget-bound damage frame does (a big scroll step).
        assert_eq!(next_left(0, f(false, false, 9_000, Some(44))), MAX_PASSES);
        // Normal damage frames during a run leave the count alone.
        assert_eq!(next_left(7, f(false, false, 900, Some(27))), 7);
        // Without the statistic only a key frame is assumed coarse.
        assert_eq!(next_left(0, f(true, false, 3_600, None)), MAX_PASSES);
        assert_eq!(next_left(0, f(false, false, 3_600, None)), 0);
    }

    #[test]
    fn a_picture_that_never_settles_is_bounded() {
        // Passes that stay starved do not re-arm themselves: the run ends when the count does.
        let mut left = next_left(0, f(true, false, 4_000, Some(51)));
        let mut taken = 0;
        while left > 0 {
            left -= 1; // the capture thread takes one pass
            taken += 1;
            left = next_left(left, f(false, true, 9_000, Some(51)));
        }
        assert_eq!(taken, MAX_PASSES);
    }

    #[test]
    fn a_pass_is_due_only_when_the_display_is_quiet() {
        let q = QUIET;
        assert!(due(3, false, q));
        assert!(!due(0, false, q));
        assert!(!due(3, true, q), "damage frames do the job");
        assert!(!due(3, false, q / 2), "spacing");
    }
}
