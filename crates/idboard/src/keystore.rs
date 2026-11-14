//! Private key storage: one raw ed25519 seed per identity.
//!
//! # What this is and is not
//!
//! This is a plain file. It is **not** a secret boundary against other processes
//! running as you: the child agent is spawned by the same user and could read
//! `~/.idboard/keys/eng-01.key` if it knew the path.
//!
//! What the wrapper arrangement does buy is narrower and real: the agent has no
//! documented interface to the key, is never told where it lives, and cannot
//! sign anything outside the wrapper's own lifetime. The key is absent from the
//! agent's *reach*, not merely from its instructions. If you need the stronger
//! property, run each identity under a separate OS user with an ACL on this
//! directory. That is deferred, not dismissed.
//!
//! # File format
//!
//! Exactly 32 raw bytes, the ed25519 seed. No header, no encoding, no
//! passphrase. Written owner-only on Unix, and read back with a length check so
//! a truncated or corrupted file is an error rather than a silently different
//! identity.

use std::io::Write;
use std::path::{Path, PathBuf};

use idboard_core::error::{CoreError, ErrorCode};
use idboard_core::keys::LocalSigner;
use idboard_core::layout;

/// Length of a raw ed25519 seed.
pub const SEED_LEN: usize = 32;

/// Keystore failures.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("no key for identity {0:?}; run `keryx keygen {0}` and add the result to your config")]
    Missing(String),

    #[error("key file {path} is {len} bytes, expected exactly {SEED_LEN}")]
    WrongLength { path: String, len: usize },

    #[error("io error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("a key for {identity:?} already exists at {path}; refusing to replace it. \
             Run `keryx keygen {identity}` to print the key that is actually on disk, \
             or `keryx keygen {identity} --force` to rotate (then update the config pubkey and restart the daemon)")]
    AlreadyExists { identity: String, path: String },
}

impl From<KeystoreError> for CoreError {
    fn from(e: KeystoreError) -> Self {
        let code = match e {
            KeystoreError::Missing(_) | KeystoreError::AlreadyExists { .. } => ErrorCode::UnknownIdentity,
            _ => ErrorCode::Internal,
        };
        CoreError::new(code, e.to_string())
    }
}

/// Filesystem-backed key storage.
#[derive(Debug, Clone)]
pub struct Keystore {
    root: PathBuf,
}

impl Keystore {
    /// Use the standard `~/.idboard/keys` directory.
    pub fn standard() -> Self {
        Self { root: layout::keys_dir() }
    }

    /// Use an explicit directory. For tests.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Path to an identity's key file.
    pub fn key_path(&self, identity: &str) -> PathBuf {
        self.root.join(format!("{identity}.key"))
    }

    /// Read an identity's seed, or `None` if it has none yet.
    pub fn load_seed(&self, identity: &str) -> std::result::Result<Option<[u8; SEED_LEN]>, KeystoreError> {
        let path = self.key_path(identity);
        let display = path.display().to_string();
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(KeystoreError::Io { path: display, source }),
        };
        if bytes.len() != SEED_LEN {
            return Err(KeystoreError::WrongLength { path: display, len: bytes.len() });
        }
        let mut seed = [0u8; SEED_LEN];
        seed.copy_from_slice(&bytes);
        Ok(Some(seed))
    }

    /// Write an identity's seed, creating the directory if needed.
    ///
    /// Writes to a temporary file and then *links* it into place, so a crash
    /// mid-write cannot leave a short file that would silently load as a
    /// *different* identity key. That failure mode is nasty precisely because it
    /// produces valid-looking output.
    ///
    /// The link also makes this refuse to replace an existing key, which a plain
    /// rename would not: `rename` replaces on Windows, so two `keryx keygen`
    /// runs racing for one identity both generate, the second wins the rename,
    /// and the first then prints a public key that is not the key on disk. The
    /// operator pastes that key into the config and every post fails with
    /// `bad_signature` against a key they can see is correct.
    pub fn save_seed(&self, identity: &str, seed: &[u8; SEED_LEN]) -> std::result::Result<(), KeystoreError> {
        let path = self.key_path(identity);
        let display = path.display().to_string();

        layout::ensure_private_dir(&self.root)
            .map_err(|source| KeystoreError::Io { path: self.root.display().to_string(), source })?;

        let tmp = self.root.join(format!(".{identity}.key.tmp{}", std::process::id()));
        let write_result = write_private(&tmp, seed)
            .map_err(|source| KeystoreError::Io { path: tmp.display().to_string(), source });

        if let Err(e) = write_result {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }

        // Hard link rather than rename: the content is already complete, and the
        // link fails with `AlreadyExists` instead of clobbering. Fails on a
        // filesystem without hard links, which is a fine thing to discover loudly.
        let link_result = std::fs::hard_link(&tmp, &path);
        let _ = std::fs::remove_file(&tmp);
        link_result.map_err(|source| {
            let kind = source.kind();
            if kind == std::io::ErrorKind::AlreadyExists {
                KeystoreError::AlreadyExists { identity: identity.to_string(), path: display }
            } else {
                KeystoreError::Io { path: display, source }
            }
        })?;
        Ok(())
    }

    /// Load the signer for an identity, generating a key on first use.
    ///
    /// Returns the signer and whether a new key was created, so the caller can
    /// print the public key for the operator to paste into the config. Creating
    /// a key silently is not enough: an unregistered identity cannot post, and
    /// the operator needs to be told exactly what to add.
    pub fn load_or_create(
        &self,
        identity: &str,
    ) -> std::result::Result<(LocalSigner, bool), KeystoreError> {
        match self.load_seed(identity)? {
            Some(seed) => {
                let signer = LocalSigner::from_seed(&seed, identity)
                    .map_err(|e| KeystoreError::Io { path: self.key_path(identity).display().to_string(), source: std::io::Error::other(e.detail) })?;
                Ok((signer, false))
            }
            None => {
                let (signer, seed) = LocalSigner::generate(identity).map_err(|e| {
                    KeystoreError::Io { path: self.key_path(identity).display().to_string(), source: std::io::Error::other(e.detail) }
                })?;
                self.save_seed(identity, &seed)?;
                Ok((signer, true))
            }
        }
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Keystore) {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::at(dir.path().join("keys"));
        (dir, ks)
    }

    #[test]
    fn missing_key_is_none_then_created() {
        let (_d, ks) = store();
        assert!(ks.load_seed("eng-01").unwrap().is_none());
        let (signer, created) = ks.load_or_create("eng-01").unwrap();
        assert!(created, "first use must report that it created a key");
        assert_eq!(signer.sender_id(), "eng-01");
        assert!(ks.load_seed("eng-01").unwrap().is_some());
    }

    #[test]
    fn second_use_reuses_the_same_key() {
        let (_d, ks) = store();
        let (first, created_first) = ks.load_or_create("eng-01").unwrap();
        let (second, created_second) = ks.load_or_create("eng-01").unwrap();
        assert!(created_first);
        assert!(!created_second, "an existing key must never be silently replaced");
        assert_eq!(first.public_hex(), second.public_hex());
        assert_eq!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn keys_are_isolated_per_identity() {
        let (_d, ks) = store();
        let (a, _) = ks.load_or_create("eng-01").unwrap();
        let (b, _) = ks.load_or_create("lead").unwrap();
        assert_ne!(a.public_hex(), b.public_hex());
        assert_ne!(a.fingerprint(), b.fingerprint());
        // And each file holds only its own key.
        assert_eq!(ks.load_seed("eng-01").unwrap().unwrap(), a.seed());
        assert_eq!(ks.load_seed("lead").unwrap().unwrap(), b.seed());
    }

    #[test]
    fn a_truncated_key_file_is_an_error_not_a_different_identity() {
        let (_d, ks) = store();
        let (signer, _) = ks.load_or_create("eng-01").unwrap();
        std::fs::write(ks.key_path("eng-01"), b"short").unwrap();
        let err = ks.load_seed("eng-01").unwrap_err();
        assert!(matches!(err, KeystoreError::WrongLength { len: 5, .. }), "{err}");
        // And the operator still has the original public key to compare against.
        assert_eq!(signer.public_hex().len(), 64);
    }

    #[test]
    fn an_oversized_key_file_is_also_rejected() {
        let (_d, ks) = store();
        ks.load_or_create("eng-01").unwrap();
        std::fs::write(ks.key_path("eng-01"), vec![0u8; 64]).unwrap();
        assert!(matches!(ks.load_seed("eng-01"), Err(KeystoreError::WrongLength { len: 64, .. })));
    }

    #[test]
    fn seed_round_trips_exactly() {
        let (_d, ks) = store();
        let (signer, _) = ks.load_or_create("eng-01").unwrap();
        assert_eq!(ks.load_seed("eng-01").unwrap().unwrap(), signer.seed());
    }

    #[test]
    fn saving_creates_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::at(dir.path().join("a").join("b").join("keys"));
        assert!(ks.load_or_create("eng-01").is_ok());
        assert!(ks.root().is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn key_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, ks) = store();
        ks.load_or_create("eng-01").unwrap();
        let mode = std::fs::metadata(ks.key_path("eng-01")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "got {:o}", mode & 0o777);
    }

    #[cfg(unix)]
    #[test]
    fn the_keys_directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, ks) = store();
        ks.load_or_create("eng-01").unwrap();
        let mode = std::fs::metadata(ks.root()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "got {:o}", mode & 0o777);
    }

    #[test]
    fn no_temporary_files_are_left_behind() {
        let (_d, ks) = store();
        ks.load_or_create("eng-01").unwrap();
        let leftovers: Vec<String> = std::fs::read_dir(ks.root())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left behind {leftovers:?}");
    }

    #[test]
    fn invalid_identity_names_cannot_escape_the_directory() {
        let (_d, ks) = store();
        // `validate_identity` runs inside `LocalSigner`, so a traversal attempt
        // fails before any path is built.
        assert!(ks.load_or_create("../escape").is_err());
        assert!(ks.load_or_create("a/b").is_err());
        assert!(ks.load_or_create("..").is_err());
    }

    #[test]
    fn missing_key_error_names_the_fix() {
        let err = KeystoreError::Missing("lead".into());
        assert!(err.to_string().contains("keryx keygen lead"), "{err}");
    }

    /// A key must never be silently replaced.
    ///
    /// `save_seed` used to end in `std::fs::rename`, which replaces the target on
    /// Windows. Two `keryx keygen` runs racing for one identity both saw no key,
    /// both generated one, the second won the rename, and the first then printed a
    /// public key that was not the key on disk — which an operator would paste into
    /// the config and watch every post fail with `bad_signature`.
    #[test]
    fn saving_never_replaces_an_existing_key() {
        let (_d, ks) = store();
        let (first, _) = ks.load_or_create("eng-01").unwrap();
        let original = ks.load_seed("eng-01").unwrap().unwrap();

        let (second, seed) = idboard_core::keys::LocalSigner::generate("eng-01").unwrap();
        assert_ne!(second.public_hex(), first.public_hex(), "the test needs two distinct keys");

        let err = ks
            .save_seed("eng-01", &seed)
            .expect_err("a second save must not replace the first");
        assert!(
            matches!(err, KeystoreError::AlreadyExists { ref identity, .. } if identity == "eng-01"),
            "{err}"
        );

        // The decisive part: the key on disk is still the first one, so the
        // public key the loser printed is still the truth.
        assert_eq!(ks.load_seed("eng-01").unwrap().unwrap(), original);
        assert_eq!(
            idboard_core::keys::LocalSigner::from_seed(&original, "eng-01").unwrap().public_hex(),
            first.public_hex(),
            "the on-disk key must be unchanged after a refused save"
        );
    }

    /// The refusal must name the fix, and must tell the operator to read the key
    /// that is actually on disk rather than to try again.
    #[test]
    fn a_refused_save_names_the_key_on_disk() {
        let (_d, ks) = store();
        ks.load_or_create("eng-01").unwrap();
        let (_, seed) = idboard_core::keys::LocalSigner::generate("eng-01").unwrap();
        let msg = ks.save_seed("eng-01", &seed).unwrap_err().to_string();
        assert!(msg.contains("keryx keygen eng-01"), "{msg}");
    }

    /// `load_or_create` is also check-then-act, and it must not be the thing that
    /// reintroduces the race the atomic link prevents.
    #[test]
    fn a_refused_create_does_not_leave_a_temporary_file_behind() {
        let (_d, ks) = store();
        ks.load_or_create("eng-01").unwrap();
        let (_, seed) = idboard_core::keys::LocalSigner::generate("eng-01").unwrap();
        let _ = ks.save_seed("eng-01", &seed);

        let leftovers: Vec<String> = std::fs::read_dir(ks.root())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "a refused save left behind {leftovers:?}");
    }
}
