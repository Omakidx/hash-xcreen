use thiserror::Error;
use x11rb::errors::{ConnectError, ConnectionError, ReplyError, ReplyOrIdError};
use x11rb::x11_utils::X11Error;

/// Everything that can go wrong while capturing. Backends never panic on display errors.
#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("cannot connect to the display: {0}")]
    Connect(#[from] ConnectError),
    #[error("display connection failed: {0}")]
    Connection(#[from] ConnectionError),
    #[error("display request failed: {0}")]
    Reply(#[from] ReplyError),
    #[error("display refused a request: {0:?}")]
    X11(X11Error),
    #[error("cannot allocate a display resource id: {0}")]
    Id(#[from] x11rb::errors::ReplyOrIdError),
    #[error("the display lacks the {0} extension (version {1}+ required)")]
    MissingExtension(&'static str, &'static str),
    #[error("unsupported screen format: {0}")]
    UnsupportedFormat(String),
    #[error("shared memory buffer: {0}")]
    SharedMemory(#[from] std::io::Error),
    #[error("cannot resize the display: {0}")]
    Resize(String),
    #[error("invalid size {width}x{height}: {reason}")]
    InvalidSize {
        width: u32,
        height: u32,
        reason: &'static str,
    },
}

impl CaptureError {
    /// True when the display connection is gone and the backend cannot recover.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            CaptureError::Connect(_) | CaptureError::Connection(_) | CaptureError::SharedMemory(_)
        )
    }
}

impl From<rustix::io::Errno> for CaptureError {
    fn from(e: rustix::io::Errno) -> Self {
        CaptureError::SharedMemory(e.into())
    }
}

// `ReplyOrIdError` also carries plain connection and X errors; flatten them.
impl CaptureError {
    pub(crate) fn from_reply_or_id(e: ReplyOrIdError) -> Self {
        match e {
            ReplyOrIdError::IdsExhausted => CaptureError::Id(ReplyOrIdError::IdsExhausted),
            ReplyOrIdError::ConnectionError(e) => CaptureError::Connection(e),
            ReplyOrIdError::X11Error(e) => CaptureError::X11(e),
        }
    }
}
