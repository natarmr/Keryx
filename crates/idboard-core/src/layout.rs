//! On-disk layout and the environment contract between wrapper and child.
//!
//! Centralised here so the two binaries cannot drift, and so the trust-relevant
//! statements about the environment live in one readable place.

use std::path::{Path, PathBuf};

/// Relay socket name. Injected into the child by `keryx run`.
///
/// This is the only channel a child process has to the board. If it is absent,
/// the CLI refuses to act rather than falling back to the daemon.
pub const ENV_RELAY: &str = "IDBOARD_RELAY";

/// Bearer token for the relay socket. Injected into the child by `keryx run`.
///
/// A local socket name is not a secret on its own. On Unix, any process can
/// `stat` the path; on Windows, any process can enumerate `\\.\pipe\*`. The
/// token is what makes a connection meaningful, and it travels only through the
/// environment, which the child inherits along with its own descendants.
pub const ENV_TOKEN: &str = "IDBOARD_TOKEN";

/// Daemon socket override. Read by the wrapper, **stripped** from the child.
pub const ENV_DAEMON: &str = "IDBOARD_DAEMON";

/// Config path override. Read by the wrapper, **stripped** from the child.
///
/// Stripping is defence in depth, not the actual control. A child that knew
/// where the daemon and the config lived still could not post: it has no key,
/// and the daemon verifies every message against a registered key. The control
/// is the signature; these strips just remove the temptation.
pub const ENV_CONFIG: &str = "IDBOARD_CONFIG";

/// Overrides the whole `~/.idboard` directory. Primarily for tests.
pub const ENV_HOME: &str = "IDBOARD_HOME";

/// Current unix time in milliseconds.
pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        // Clock before 1970. Cannot happen in practice; a wrong-but-monotonic
        // value is better than panicking in a signing path.
        Err(e) => -(e.duration().as_millis() as i64),
    }
}

/// The user's home directory, platform-appropriate.
pub fn user_home() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(unix)]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

/// Root of idboard's state: `$IDBOARD_HOME`, else `<home>/.idboard`.
pub fn idboard_home() -> PathBuf {
    if let Some(p) = std::env::var_os(ENV_HOME) {
        return PathBuf::from(p);
    }
    match user_home() {
        Some(h) => h.join(".idboard"),
        None => PathBuf::from(".idboard"),
    }
}

/// Path to the daemon config file.
pub fn config_path() -> PathBuf {
    if let Some(p) = std::env::var_os(ENV_CONFIG) {
        return PathBuf::from(p);
    }
    idboard_home().join("config.toml")
}

/// Directory holding one file per identity's private seed.
pub fn keys_dir() -> PathBuf {
    idboard_home().join("keys")
}

/// Directory holding lockfiles and, on Unix, the daemon socket.
pub fn run_dir() -> PathBuf {
    idboard_home().join("run")
}

/// Path to the SQLite database.
pub fn db_path() -> PathBuf {
    idboard_home().join("idboard.db")
}

/// Path to an identity's private seed file.
pub fn key_path(identity: &str) -> PathBuf {
    keys_dir().join(format!("{identity}.key"))
}

/// Path to an identity's exclusive lockfile.
///
/// Advisory lock only. Its presence is not authority over anything; it exists
/// to stop two live wrappers from interleaving sequence numbers under one
/// identity, which would make post-incident attribution impossible.
pub fn lock_path(identity: &str) -> PathBuf {
    run_dir().join(format!("{identity}.lock"))
}

/// Default daemon socket name for this machine and user.
///
/// A named pipe on Windows, a filesystem socket on Unix. Both are
/// machine-local; neither is reachable over the network.
pub fn default_daemon_socket() -> PathBuf {
    #[cfg(windows)]
    {
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".into());
        PathBuf::from(format!(r"\\.\pipe\idboardd-{user}"))
    }
    #[cfg(unix)]
    {
        // XDG_RUNTIME_DIR is tmpfs and per-user, which is the right place for a
        // socket. Fall back to our own run dir, created 0700.
        if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
            return PathBuf::from(rt).join("idboard").join("idboardd.sock");
        }
        run_dir().join("idboardd.sock")
    }
}

/// Daemon socket, honouring `$IDBOARD_DAEMON`.
pub fn daemon_socket() -> PathBuf {
    if let Some(p) = std::env::var_os(ENV_DAEMON) {
        return PathBuf::from(p);
    }
    default_daemon_socket()
}

/// Per-invocation relay socket name: unpredictable, namespaced by identity.
///
/// The randomness is defence in depth rather than the primary control, since
/// the bearer token is what actually authorises a request. It does mean two
/// concurrent wrappers cannot collide, and it keeps the pipe namespace from
/// filling with guessable names.
pub fn relay_socket_name(identity: &str, suffix: &str) -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(format!(r"\\.\pipe\idboard-{identity}-{suffix}"))
    }
    #[cfg(unix)]
    {
        // Abstract sockets would avoid filesystem cleanup entirely, but they are
        // not portable through interprocess's path-based name type, so we use a
        // real file in a 0700 directory and unlink it on exit.
        run_dir().join(format!("relay-{identity}-{suffix}.sock"))
    }
}

/// Create `dir` and every missing parent.
pub fn ensure_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// Create `dir` with owner-only permissions where the platform supports it.
///
/// On Windows this is a no-op beyond creating the directory. NTFS inherits ACLs
/// from the parent, so a directory under `%USERPROFILE%` already inherits a DACL
/// granting the creating account and SYSTEM and denying Everyone. keryx does
/// **not** set or verify that DACL, and there is no Windows file-ACL code
/// anywhere in the tree. The reliance is stated rather than enforced: the daemon
/// prints `Config::custody_statement` at startup, and the operator can check the
/// real answer with `icacls`.
///
/// Note this chmods a directory that *already exists*, so calling it on every
/// start resets a mode an operator deliberately loosened. That is deliberate for
/// the keystore; be aware of it before adding another call site.
pub fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    ensure_dir(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_derived_from_idboard_home() {
        // Guard against these silently reading a developer's real ~/.idboard
        // during tests.
        unsafe {
            std::env::set_var(ENV_HOME, "/tmp/idboard-test-home");
        }
        assert!(config_path().starts_with("/tmp/idboard-test-home"));
        assert!(keys_dir().ends_with("keys"));
        assert!(key_path("eng-01").ends_with("eng-01.key"));
        assert!(lock_path("eng-01").ends_with("eng-01.lock"));
        unsafe {
            std::env::remove_var(ENV_HOME);
        }
    }

    #[test]
    fn relay_names_are_namespaced_by_identity() {
        let a = relay_socket_name("eng-01", "deadbeefdeadbeef");
        let b = relay_socket_name("eng-02", "deadbeefdeadbeef");
        assert_ne!(a, b);
        let s = a.to_string_lossy();
        assert!(s.contains("eng-01"), "{s}");
        assert!(s.contains("deadbeefdeadbeef"), "{s}");
    }

    #[test]
    fn now_ms_is_plausible() {
        // After 2020-01-01 and before 2100. Catches a units mix-up between
        // seconds and milliseconds, which would silently break the read skew
        // window either way.
        let t = now_ms();
        assert!(t > 1_577_836_800_000, "timestamp looks like seconds, not ms: {t}");
        assert!(t < 4_102_444_800_000, "timestamp looks wrong: {t}");
    }
}
