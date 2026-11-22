//! Presentation behind a small trait.

use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Arc, Mutex};

use super::decode::Picture;

/// Which path puts pixels on the screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresentKind {
    /// Software decode, RGBA upload into a Slint image (today).
    CpuUpload,
    /// VAAPI to DMA-BUF to OpenGL texture (spike S1, later).
    VaapiGl,
}

impl PresentKind {
    /// Text for the stats overlay.
    pub fn label(self) -> &'static str {
        match self {
            Self::CpuUpload => "CPU upload",
            Self::VaapiGl => "GPU",
        }
    }
}

/// Shows decoded pictures. Called from the decode thread; implementations hand the picture to
/// the UI thread and drop older ones that were not shown yet (latest frame wins).
pub trait Presenter: Send + Sync + 'static {
    /// Which path this is.
    fn kind(&self) -> PresentKind;
    /// Offers a picture.
    fn present(&self, pic: Picture);
}

/// A receiver of pictures on the UI thread (used by [`CpuPresenter`]).
pub type FrameSink = Arc<dyn Fn(Picture) + Send + Sync>;

/// The CPU-upload presenter: keeps the newest picture and schedules one UI-thread callback.
pub struct CpuPresenter {
    latest: Arc<Mutex<Option<Picture>>>,
    scheduled: Arc<AtomicBool>,
    sink: FrameSink,
}

impl CpuPresenter {
    /// `sink` runs on the Slint event loop and typically sets the `Image` property.
    pub fn new(sink: FrameSink) -> Self {
        Self {
            latest: Arc::default(),
            scheduled: Arc::default(),
            sink,
        }
    }
}

impl Presenter for CpuPresenter {
    fn kind(&self) -> PresentKind {
        PresentKind::CpuUpload
    }

    fn present(&self, pic: Picture) {
        if let Ok(mut g) = self.latest.lock() {
            *g = Some(pic);
        }
        if self.scheduled.swap(true, SeqCst) {
            return;
        }
        let (latest, scheduled, sink) = (
            self.latest.clone(),
            self.scheduled.clone(),
            self.sink.clone(),
        );
        let posted = slint::invoke_from_event_loop(move || {
            scheduled.store(false, SeqCst);
            let pic = latest.lock().ok().and_then(|mut g| g.take());
            if let Some(p) = pic {
                sink(p);
            }
        });
        if posted.is_err() {
            self.scheduled.store(false, SeqCst);
        }
    }
}
