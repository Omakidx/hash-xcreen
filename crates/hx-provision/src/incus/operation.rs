//! Handles for Incus background operations (cancel and wait, ipc.md 4).

use std::fmt;

use super::error::IncusError;

/// The id of an Incus background operation (a UUID). Validated, so it is safe in a URL path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperationId(pub(crate) String);

impl OperationId {
    /// Accepts `[A-Za-z0-9-]{1,64}` (what Incus generates is a UUID).
    pub fn new(id: &str) -> Result<Self, IncusError> {
        if id.is_empty()
            || id.len() > 64
            || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(IncusError::InvalidArgument(format!(
                "`{id}` is not an operation id"
            )));
        }
        Ok(Self(id.to_string()))
    }

    /// The id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How an operation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationEnd {
    /// Completed successfully.
    Success,
    /// Failed; the daemon's message (not sanitized).
    Failed(String),
    /// Cancelled.
    Cancelled,
    /// The daemon no longer knows the operation (it finished and was purged).
    Gone,
}
