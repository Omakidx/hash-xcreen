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

/// True when OpenGL would run on the CPU (Mesa's llvmpipe), where Slint's software renderer
/// shows the CPU-upload pictures at a tenth of the cost of its OpenGL renderer
/// (architecture 6.5): `LIBGL_ALWAYS_SOFTWARE` is set, or `dri` (normally `/dev/dri`) has no
/// GPU render node (`renderD*`) or does not exist. Only meaningful on Linux.
pub fn opengl_runs_on_cpu(
    always_software: Option<&std::ffi::OsStr>,
    dri: &std::path::Path,
) -> bool {
    if always_software.is_some_and(|v| !v.is_empty() && v != "0" && v != "false") {
        return true;
    }
    match std::fs::read_dir(dri) {
        Ok(entries) => !entries
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with("renderD")),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opengl_on_cpu_without_a_render_node_or_when_forced() {
        let dir = std::env::temp_dir().join(format!("hx-dri-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // No /dev/dri at all: no GPU.
        assert!(opengl_runs_on_cpu(None, &dir));
        std::fs::create_dir_all(dir.join("by-path")).unwrap();
        std::fs::write(dir.join("card0"), b"").unwrap();
        // A display card without a render node (a virtual or display-only device).
        assert!(opengl_runs_on_cpu(None, &dir));
        std::fs::write(dir.join("renderD128"), b"").unwrap();
        assert!(!opengl_runs_on_cpu(None, &dir));
        // LIBGL_ALWAYS_SOFTWARE forces it; "0", "false" and empty do not.
        assert!(opengl_runs_on_cpu(Some("1".as_ref()), &dir));
        assert!(opengl_runs_on_cpu(Some("true".as_ref()), &dir));
        for off in ["0", "false", ""] {
            assert!(!opengl_runs_on_cpu(Some(off.as_ref()), &dir), "{off:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
