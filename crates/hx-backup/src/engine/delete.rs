//! Deleting snapshots by id.
//!
//! [`Engine::forget`] applies retention rules; the repository link's `FORGET_PRUNE` job (ipc.md §28)
//! is told exactly which snapshots to remove, because `hx-privd` chose them and allows `Remove` of a
//! `SNAPSHOT` object only for those ids (§30). This is the engine side of that.

use rustic_core::Id;

use super::{CancelToken, Engine, EngineError, Phase, SnapshotId, rustic};

impl Engine {
    /// Remove exactly these snapshots. Space is only freed by [`Engine::prune`]. An id that does not
    /// exist is an error of the backend, so a caller that wants to be idempotent lists first.
    ///
    /// # Errors
    /// [`EngineError::Cancelled`], [`EngineError::Repository`].
    pub fn delete_snapshots(
        &self,
        ids: &[SnapshotId],
        cancel: &CancelToken,
    ) -> Result<(), EngineError> {
        cancel.check()?;
        self.shared.set_phase(Phase::Forget);
        let raw = ids
            .iter()
            .map(|id| {
                id.as_str()
                    .parse::<Id>()
                    .map(Into::into)
                    .map_err(rustic("reading a snapshot id"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if raw.is_empty() {
            return Ok(());
        }
        self.repo()?
            .delete_snapshots(&raw)
            .map_err(rustic("removing snapshots"))
    }
}
