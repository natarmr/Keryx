//! One live wrapper per identity.
//!
//! # Why this exists
//!
//! Two concurrent `keryx run --identity X` processes would share one key and
//! interleave their sequence numbers. The board could not then tell which
//! process posted a given message, which destroys post-incident attribution —
//! the main thing a signed board is for.
//!
//! An exclusive lock turns that from a silent ambiguity into a loud failure: the
//! second launch exits non-zero and says which process holds the identity.
//!
//! # What the lock is not
//!
//! It is not access control. It is an advisory lock on a file, released by the
//! kernel when the holder dies, so a crashed wrapper does not leave an identity
//! permanently unusable. It confers no authority: skipping it gains an attacker
//! nothing they could not do by reading the key directly.

use std::fs::{File, OpenOptions};
use std::path::PathBuf;

use idboard_core::layout;

/// Held for as long as a wrapper owns an identity.
#[derive(Debug)]
pub struct IdentityLock {
    file: File,
    path: PathBuf,
    identity: String,
}

/// Why a lock could not be taken.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("identity {identity:?} is already in use by another `keryx run` (lock {path}, pid {pid})")]
    Held { identity: String, path: String, pid: u32 },

    #[error("cannot open lock file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

impl IdentityLock {
    /// Try to take exclusive ownership of an identity, at the default path.
    pub fn try_acquire(identity: &str) -> Result<Self, LockError> {
        Self::try_acquire_at(layout::lock_path(identity), identity)
    }

    /// Try to take exclusive ownership at an explicit path.
    ///
    /// The path is a parameter rather than derived internally so that every path a
    /// wrapper uses can come from one place. Deriving it from the ambient
    /// environment instead means a caller who relocates the config and the socket
    /// but not `IDBOARD_HOME` silently gets a lock somewhere they did not choose.
    pub fn try_acquire_at(path: PathBuf, identity: &str) -> Result<Self, LockError> {
        // Owner-only, like the keystore directory that sits in the same state
        // root. The lock is not access control, so this is hygiene rather than
        // enforcement: a run directory other accounts can list is an invitation
        // to interfere with a live identity's lockfile.
        layout::ensure_private_dir(path.parent().expect("lock path has a parent"))
            .map_err(|source| LockError::Io { path: path.display().to_string(), source })?;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| LockError::Io { path: path.display().to_string(), source })?;

        // `File::try_lock` is the exclusive, non-blocking form, stable in std
        // since 1.89. Distinguish "someone holds it" from a real error, so a
        // permissions problem is not misreported as a lock conflict.
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(LockError::Held {
                    identity: identity.to_string(),
                    path: path.display().to_string(),
                    pid: Self::read_pid(&path).unwrap_or(0),
                });
            }
            Err(e) => {
                return Err(LockError::Io { path: path.display().to_string(), source: std::io::Error::other(e) });
            }
        }

        // The pid lives in a *separate* file, not in the lock file.
        //
        // On Windows a file lock is a byte-range lock, and it blocks reads as well
        // as writes from any other handle. So the holder's pid cannot be read back
        // out of the file it has locked, and a lock file that also served as the
        // pid source could never report a useful pid. Separating them keeps the
        // error message actionable.
        let _ = std::fs::write(Self::pid_path(&path), format!("{}\n", std::process::id()));

        Ok(Self { file, path, identity: identity.to_string() })
    }

    /// Where the lockfile for an identity lives by default.
    pub fn lock_path(identity: &str) -> PathBuf {
        layout::lock_path(identity)
    }

    /// Where the holder's pid is recorded, for diagnostics.
    fn pid_path(path: &std::path::Path) -> PathBuf {
        path.with_extension("pid")
    }

    /// Best-effort read of the recorded pid, purely for the error message.
    fn read_pid(path: &std::path::Path) -> Option<u32> {
        std::fs::read_to_string(Self::pid_path(path)).ok()?.trim().parse().ok()
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for IdentityLock {
    fn drop(&mut self) {
        // Best effort: the OS releases the lock when the handle closes either
        // way, so a failure here cannot leave the identity locked.
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
use idboard_core::layout;

    /// Point the layout at a temp dir so these tests never touch a real
    /// `~/.idboard`. Env vars are process-global, so this is a mutex-guarded
    /// single test rather than several parallel ones.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The one process-global environment lock in this crate.
    ///
    /// Exposed to other test modules so a test that mutates `IDBOARD_*` takes
    /// the same lock rather than defining a second mutex that serialises
    /// nothing. `wrapper`'s env test does exactly that.
    pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn with_temp_home<T>(f: impl FnOnce() -> T) -> T {
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var(layout::ENV_HOME, dir.path());
        }
        let out = f();
        unsafe {
            std::env::remove_var(layout::ENV_HOME);
        }
        out
    }

    #[test]
    fn a_lock_is_exclusive() {
        with_temp_home(|| {
            let first = IdentityLock::try_acquire("eng-01").unwrap();
            let err = IdentityLock::try_acquire("eng-01").unwrap_err();
            match err {
                LockError::Held { identity, pid, .. } => {
                    assert_eq!(identity, "eng-01");
                    assert_eq!(pid, std::process::id(), "should name the current holder");
                }
                other => panic!("expected Held, got {other}"),
            }
            drop(first);
            // Released, so a second acquisition succeeds.
            IdentityLock::try_acquire("eng-01").expect("lock should be free after drop");
        });
    }

    #[test]
    fn different_identities_do_not_contend() {
        with_temp_home(|| {
            let _a = IdentityLock::try_acquire("eng-01").unwrap();
            let _b = IdentityLock::try_acquire("lead").unwrap();
        });
    }

    #[test]
    fn the_error_message_names_the_fix() {
        with_temp_home(|| {
            let _a = IdentityLock::try_acquire("eng-01").unwrap();
            let msg = IdentityLock::try_acquire("eng-01").unwrap_err().to_string();
            assert!(msg.contains("already in use"), "{msg}");
            assert!(msg.contains("eng-01"), "{msg}");
        });
    }

    #[test]
    fn lock_paths_are_per_identity() {
        assert_ne!(IdentityLock::lock_path("a"), IdentityLock::lock_path("b"));
        assert!(IdentityLock::lock_path("a").ends_with("a.lock"));
    }
}
