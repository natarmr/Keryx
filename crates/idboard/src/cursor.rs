//! Local message-cursor bookkeeping.
//!
//! These files are a convenience for one operator on one machine. They are not
//! trusted, never authorise anything, and are never consulted by the daemon.
//! A malicious or stale file can only lead a caller to re-read messages it was
//! already allowed to read, or to skip nothing that matters.
//!
//! A *missing* file is not an error: it is the first use of `--since-last`, and
//! there is no position to resume from yet, so the caller starts at `0`. A file
//! that is present but unreadable, corrupt, not a regular file, or absurdly
//! large is reported instead: a zero cursor means "from the beginning", and an
//! operator should choose that explicitly when that is what they want.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use idboard_core::error::{CoreError, Result};
use idboard_core::layout;

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
struct FileCursors {
    cursors: BTreeMap<String, i64>,
}

/// Largest cursor file this will read.
///
/// One entry is a channel name plus an `i64`, and channels are declared in the
/// config, so a real file is a few hundred bytes. The bound exists because the
/// file is writable by the agent the wrapper spawned — `KERYX_CURSOR_HOME` is
/// passed through on purpose — and `read_to_string` would otherwise allocate
/// whatever size that agent chose. An unbounded read is a way to abort the next
/// `keryx read` in the same wrapper.
const CURSOR_FILE_MAX_BYTES: u64 = 1024 * 1024;

/// A per-identity store kept under the keryx state root.
#[derive(Debug)]
pub struct CursorStore {
    path: PathBuf,
    cursors: BTreeMap<String, i64>,
    dirty: bool,
}

/// Override for the cursor state root.
///
/// The normal implementation uses `$IDBOARD_HOME/cursors`. That directory is
/// deliberately not inherited by wrapper children (`IDBOARD_HOME` is stripped),
/// so agents that need cursor replay need an explicit root that is allowed in
/// their environment. `KERYX_CURSOR_HOME` names that root; when unset, the
/// default `<state root>/cursors` is used.
pub const ENV_CURSOR_HOME: &str = "KERYX_CURSOR_HOME";

pub fn cursor_root() -> PathBuf {
    if let Some(path) = std::env::var_os(ENV_CURSOR_HOME) {
        return PathBuf::from(path).join("cursors");
    }
    layout::idboard_home().join("cursors")
}

impl CursorStore {
    /// Open (or allow absence for) the identity's cursor file.
    pub fn for_identity(identity: &str) -> Result<Self> {
        if let Err(e) = idboard_core::validate_identity(identity) {
            return Err(CoreError::bad_request(format!(
                "refusing to build a cursor path from identity {identity:?}: {e}"
            )));
        }
        let path = cursor_root().join(format!("{identity}.json"));
        // Inspect before reading. `metadata` follows a symlink, so a link to a
        // FIFO or a device is caught here too: reading a FIFO blocks until a
        // writer appears, which is a hang, and a device has no meaningful
        // length. A missing file is the ordinary first-run case.
        let cursors = match fs::metadata(&path) {
            Ok(meta) => {
                if !meta.is_file() {
                    return Err(CoreError::bad_request(format!(
                        "cursor file {} is not a regular file; remove it and pass --since instead",
                        path.display()
                    )));
                }
                if meta.len() > CURSOR_FILE_MAX_BYTES {
                    return Err(CoreError::bad_request(format!(
                        "cursor file {} is {} bytes, limit is {CURSOR_FILE_MAX_BYTES}; \
                         remove it and pass --since instead",
                        path.display(),
                        meta.len()
                    )));
                }
                Self::load(&path)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => {
                return Err(CoreError::bad_request(format!(
                    "cannot inspect cursor file {}: {e}; pass --since instead",
                    path.display()
                )));
            }
        };
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

    /// Remove a channel's saved local position, if any.
    pub fn remove(&mut self, channel: &str) {
        self.cursors.remove(channel);
        self.dirty = true;
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
        // Remove any stale entry first, then create the file exclusively.
        // `fs::write` alone would follow a symlink left here (redirecting the
        // cursor write into another file) and would block forever on a FIFO.
        // Both are creatable by the agent the wrapper spawned, so the temp path
        // gets the same "regular file only" discipline as the cursor path.
        let _ = fs::remove_file(&tmp);
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(|e| {
            CoreError::internal(format!("failed to create {}: {e}", tmp.display()))
        })?;
        file.write_all(text.as_bytes()).map_err(|e| {
            CoreError::internal(format!("failed to write {}: {e}", tmp.display()))
        })?;
        drop(file);
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

    /// A missing file is the first `--since-last`, not an error: there is no
    /// position to resume from yet, so the caller starts at the beginning.
    #[test]
    fn a_missing_cursor_file_starts_at_the_beginning() {
        let _guard = crate::lock::tests::env_lock();
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("IDBOARD_HOME", tmp.path()) };

        let store = CursorStore::for_identity("eng-01").unwrap();
        assert_eq!(store.get("general"), 0);
        assert!(!tmp.path().join("cursors").join("eng-01.json").exists());
    }

    /// The file is writable by the agent the wrapper spawned, so its size is
    /// that agent's choice. It must be refused before it is read: the point of
    /// the bound is that the allocation never happens.
    #[test]
    fn an_oversized_cursor_file_is_refused_before_it_is_read() {
        let _guard = crate::lock::tests::env_lock();
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("IDBOARD_HOME", tmp.path()) };

        let dir = tmp.path().join("cursors");
        fs::create_dir_all(&dir).unwrap();
        // Valid JSON, so a successful parse would prove it had been read. The
        // padding alone pushes it over the limit.
        let mut text = String::from(r#"{"cursors":{"general":1}}"#);
        text.push_str(&" ".repeat(CURSOR_FILE_MAX_BYTES as usize));
        fs::write(dir.join("eng-01.json"), text).unwrap();

        let err = CursorStore::for_identity("eng-01").unwrap_err();
        assert_eq!(err.code, idboard_core::ErrorCode::BadRequest);
    }

    /// A directory at the path must be a refusal, not a read that fails
    /// obscurely. On Unix the same guard rejects a FIFO, which would otherwise
    /// block the CLI forever waiting for a writer.
    #[test]
    fn a_cursor_path_that_is_not_a_regular_file_is_refused() {
        let _guard = crate::lock::tests::env_lock();
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("IDBOARD_HOME", tmp.path()) };

        let path = tmp.path().join("cursors").join("eng-01.json");
        fs::create_dir_all(&path).unwrap();

        let err = CursorStore::for_identity("eng-01").unwrap_err();
        assert_eq!(err.code, idboard_core::ErrorCode::BadRequest);
    }

    /// A stale entry at the temp path is replaced, never merged into the file.
    ///
    /// A regular file is the portable stand-in for the shapes that matter — a
    /// symlink (which `fs::write` would follow) and a FIFO (which it would
    /// block on) — both creatable by the agent, and both rejected by the
    /// remove-then-`create_new` sequence in `flush`.
    #[test]
    fn flush_replaces_a_stale_entry_at_the_temp_path() {
        let _guard = crate::lock::tests::env_lock();
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("IDBOARD_HOME", tmp.path()) };

        let dir = tmp.path().join("cursors");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("eng-01.json.tmp"), "stale").unwrap();

        let mut store = CursorStore::for_identity("eng-01").unwrap();
        store.set("general", 7);
        store.flush().unwrap();

        let text = fs::read_to_string(dir.join("eng-01.json")).unwrap();
        assert!(text.contains("\"general\": 7"), "{text}");
        assert!(!text.contains("stale"), "the stale temp entry leaked into the file: {text}");
    }
}
