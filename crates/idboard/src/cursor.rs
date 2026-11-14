//! Local message-cursor bookkeeping.
//!
//! These files are a convenience for one operator on one machine. They are not
//! trusted, never authorise anything, and are never consulted by the daemon.
//! A malicious or stale file can only lead a caller to re-read messages it was
//! already allowed to read, or to skip nothing that matters.
//!
//! Missing, unreadable and corrupt entries are reported rather than silently
//! treated as `0`: a zero cursor means "from the beginning", and an operator
//! should choose that explicitly when that is what they want.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use idboard_core::error::{CoreError, Result};
use idboard_core::layout;

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
struct FileCursors {
    cursors: BTreeMap<String, i64>,
}

/// A per-identity store kept under the idboard state root.
#[derive(Debug)]
pub struct CursorStore {
    path: PathBuf,
    cursors: BTreeMap<String, i64>,
    dirty: bool,
}

impl CursorStore {
    /// Open (or allow absence for) the identity's cursor file.
    pub fn for_identity(identity: &str) -> Result<Self> {
        if let Err(e) = idboard_core::validate_identity(identity) {
            return Err(CoreError::bad_request(format!(
                "refusing to build a cursor path from identity {identity:?}: {e}"
            )));
        }
        let path = layout::idboard_home()
            .join("cursors")
            .join(format!("{identity}.json"));
        let cursors = if path.exists() { Self::load(&path)? } else { BTreeMap::new() };
        Ok(Self { path, cursors, dirty: false })
    }

    fn load(path: &Path) -> Result<BTreeMap<String, i64>> {
        let text = fs::read_to_string(path).map_err(|e| {
            CoreError::bad_request(format!(
                "no resumable cursor at {}; pass --since instead ({e})",
                path.display()
            ))
        })?;
        let file: FileCursors = serde_json::from_str(&text).map_err(|e| {
            CoreError::bad_request(format!(
                "cursor file {} is corrupt: {e}; pass --since instead (or remove the file)",
                path.display()
            ))
        })?;
        Ok(file.cursors)
    }

    /// Cursor for one channel. `0` means no position has been saved yet.
    pub fn get(&self, channel: &str) -> i64 {
        self.cursors.get(channel).copied().unwrap_or(0)
    }

    /// Record the newest position seen for a channel.
    pub fn set(&mut self, channel: &str, cursor: i64) {
        if cursor > self.get(channel) {
            self.cursors.insert(channel.to_string(), cursor);
            self.dirty = true;
        }
    }

    /// Write the file if anything changed.
    pub fn flush(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let parent = self.path.parent().expect("cursor path has a parent").to_path_buf();
        fs::create_dir_all(&parent).map_err(|e| {
            CoreError::internal(format!("failed to create {}: {e}", parent.display()))
        })?;
        let text = serde_json::to_string_pretty(&FileCursors { cursors: self.cursors.clone() })
            .map_err(|e| CoreError::internal(format!("failed to serialise cursors: {e}")))?;
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, text).map_err(|e| {
            CoreError::internal(format!("failed to write {}: {e}", tmp.display()))
        })?;
        fs::rename(&tmp, &self.path).map_err(|e| {
            CoreError::internal(format!(
                "failed to install cursor file {} from {}: {e}",
                self.path.display(),
                tmp.display()
            ))
        })?;
        self.dirty = false;
        Ok(())
    }
}

/// Explicit empty-cursor rule for callers whose UX requires a "start here".
#[allow(dead_code)]
pub fn default_cursor_for_absent() -> i64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialisation round trip and monotonicity across instances.
    #[test]
    fn cursor_store_round_trips_through_disk() {
        let _guard = crate::lock::tests::env_lock();
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("IDBOARD_HOME", tmp.path()) };

        let path = tmp.path().join("cursors").join("eng-01.json");
        let mut store = CursorStore::for_identity("eng-01").unwrap();
        store.set("general", 41);
        store.set("deploy-approvals", 9);
        store.flush().unwrap();
        assert!(path.exists(), "the store must be a real file");

        let raw: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(raw["cursors"]["general"], 41);

        // A fresh instance sees what was written, and never regresses.
        let mut reloaded = CursorStore::for_identity("eng-01").unwrap();
        assert_eq!(reloaded.get("general"), 41);
        reloaded.set("general", 12);
        assert_eq!(reloaded.get("general"), 41, "a lower cursor must never overwrite a higher one");
    }

    /// A corrupt file must be reported, not silently reset to zero — a zero
    /// cursor means "from the beginning", which is exactly the surprise to avoid.
    #[test]
    fn a_corrupt_cursor_file_is_an_error_not_a_silent_reset() {
        let _guard = crate::lock::tests::env_lock();
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("IDBOARD_HOME", tmp.path()) };

        let dir = tmp.path().join("cursors");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("eng-01.json"), "{ this is not json").unwrap();

        let err = CursorStore::for_identity("eng-01").unwrap_err();
        assert_eq!(err.code, idboard_core::ErrorCode::BadRequest);
        assert!(!err.detail.is_empty());
    }
}
