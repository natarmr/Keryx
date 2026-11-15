//! Structural limits and identifier validation.
//!
//! keryx talks to sockets that any local process can connect to, so every
//! inbound field is untrusted until proven otherwise. These limits bound what a
//! caller can make the daemon allocate before any signature check happens.

use crate::error::{CoreError, Result};

/// Longest permitted identity name, in bytes.
pub const MAX_IDENTITY_LEN: usize = 64;
/// Longest permitted channel name, in bytes.
pub const MAX_CHANNEL_LEN: usize = 128;
/// Longest permitted message body, in bytes (64 KiB).
pub const MAX_BODY_LEN: usize = 64 * 1024;
/// Nonce length in bytes before hex encoding.
pub const NONCE_BYTES: usize = 16;
/// Largest `read` page the daemon will serve in one response.
pub const MAX_READ_LIMIT: usize = 1000;
/// Default `read` page size.
pub const DEFAULT_READ_LIMIT: u32 = 100;

/// Accepted skew for signed timestamps on read-only operations, in
/// milliseconds. Read-only ops authenticate by time rather than by counter, so
/// this window is the whole of their freshness guarantee.
///
/// Generous on purpose: both processes sit on one machine and normally share a
/// clock. This exists to reject a stale captured request, not to police NTP.
pub const READ_SKEW_MS: i64 = 5 * 60 * 1000;

/// A `read`'s `since` value that means "the current end of the board", not a
/// cursor.
///
/// Lives here, in the shared contract, because both ends need it and the CLI
/// must not have to depend on the daemon to name a value the daemon interprets.
///
/// The daemon answers such a read with the newest cursor in the board. Echoing
/// the sentinel back instead is the obvious implementation and is wrong: a
/// poller that took it at face value would pass `i64::MAX` as its cursor on
/// every subsequent read, match no row ever, and poll silently forever.
pub const SINCE_CURRENT_END: i64 = i64::MAX;

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

fn is_channel_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/')
}

/// Windows device names, which are still devices when they carry an extension.
///
/// `keys/CON.key` opens the console rather than a file, so a key written there
/// can never be read back. The list is the documented set; `CONIN$`/`CONOUT$`
/// and the superscript-digit aliases need characters the identity charset
/// already refuses.
const WINDOWS_DEVICE_NAMES: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Whether `name` is a Windows device name once the first `.` is stripped.
///
/// Windows resolves `CON`, `CON.key` and `con.anything` to the same device, and
/// does so case-insensitively. `deploy.bot` is an ordinary file: only the part
/// before the first dot is a device candidate.
fn is_windows_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name);
    WINDOWS_DEVICE_NAMES.contains(&stem.to_ascii_lowercase().as_str())
}

/// Validate an identity name: non-empty, bounded, restricted charset.
///
/// Deliberately narrow. Identity names end up in lockfile paths, socket names,
/// and TOML table headers, so we refuse separators, spaces, and control
/// characters rather than sanitising them. A caller that wants "deploy bot"
/// should name it `deploy-bot`.
///
/// Windows device names are refused on every platform, not just on Windows. The
/// name is a portable config value: accepting it on Unix and rejecting it on
/// Windows would give one config two meanings, and the Windows failure is silent
/// (the key file is created, then unreadable).
pub fn validate_identity(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(CoreError::bad_request("identity name is empty"));
    }
    // `.` and `..` pass the character check below, but they are directory
    // entries in their own right. An identity called `..` would resolve to the
    // parent of the keys directory.
    if name == "." || name == ".." {
        return Err(CoreError::bad_request(format!("identity name {name:?} is reserved")));
    }
    // The key file is `<name>.key`, and on Windows a device name wins over the
    // directory: the file would be created and then be unreadable.
    if is_windows_device_name(name) {
        return Err(CoreError::bad_request(format!(
            "identity name {name:?} is a reserved Windows device name (CON, PRN, AUX, NUL, \
             COM1-9, LPT1-9) and cannot be used as a key file name"
        )));
    }
    if name.len() > MAX_IDENTITY_LEN {
        return Err(CoreError::bad_request(format!(
            "identity name is {} bytes, limit is {MAX_IDENTITY_LEN}",
            name.len()
        )));
    }
    if let Some(bad) = name.chars().find(|c| !is_ident_char(*c)) {
        return Err(CoreError::bad_request(format!(
            "identity name contains disallowed character {bad:?}; allowed are [A-Za-z0-9._-]"
        )));
    }
    Ok(())
}

/// Validate a channel name: non-empty, bounded, restricted charset.
///
/// `/` is allowed so channels can be namespaced (`deploy/prod`). It is the one
/// path-ish character we permit, and it is safe here because channel names are
/// never joined to a filesystem path.
pub fn validate_channel(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(CoreError::bad_request("channel name is empty"));
    }
    if name.len() > MAX_CHANNEL_LEN {
        return Err(CoreError::bad_request(format!(
            "channel name is {} bytes, limit is {MAX_CHANNEL_LEN}",
            name.len()
        )));
    }
    if let Some(bad) = name.chars().find(|c| !is_channel_char(*c)) {
        return Err(CoreError::bad_request(format!(
            "channel name contains disallowed character {bad:?}; allowed are [A-Za-z0-9._-/]"
        )));
    }
    Ok(())
}

/// Enforce the body size cap.
pub fn validate_body(body: &str) -> Result<()> {
    if body.len() > MAX_BODY_LEN {
        return Err(CoreError::bad_request(format!(
            "body is {} bytes, limit is {MAX_BODY_LEN}",
            body.len()
        )));
    }
    Ok(())
}

/// Clamp a caller-supplied read limit into `1..=MAX_READ_LIMIT`.
pub fn clamp_read_limit(limit: u32) -> usize {
    if limit == 0 {
        return 1;
    }
    (limit as usize).min(MAX_READ_LIMIT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    #[test]
    fn accepts_ordinary_names() {
        for n in ["eng-01", "lead", "a", "deploy.bot", "x_y", &"n".repeat(64)] {
            assert!(validate_identity(n).is_ok(), "identity {n:?} rejected");
        }
        for c in ["general", "deploy/prod", "a", &"c".repeat(128)] {
            assert!(validate_channel(c).is_ok(), "channel {c:?} rejected");
        }
    }

    #[test]
    fn rejects_traversal_and_separators_in_identity() {
        // These are the names that would let an identity escape the keys
        // directory or collide with a sibling path.
        for n in ["../evil", "a/b", "a\\b", "a b", "a;b", "", "a\0b", ".."] {
            let err = validate_identity(n).unwrap_err();
            assert_eq!(err.code, ErrorCode::BadRequest, "identity {n:?}");
        }
    }

    #[test]
    fn rejects_over_length() {
        let long = "n".repeat(MAX_IDENTITY_LEN + 1);
        assert_eq!(validate_identity(&long).unwrap_err().code, ErrorCode::BadRequest);
        let long = "c".repeat(MAX_CHANNEL_LEN + 1);
        assert_eq!(validate_channel(&long).unwrap_err().code, ErrorCode::BadRequest);
    }

    #[test]
    fn channel_allows_slash_but_not_backslash() {
        assert!(validate_channel("deploy/prod").is_ok());
        assert!(validate_channel("a\\b").is_err());
    }

    #[test]
    fn rejects_non_ascii() {
        // Guards against homoglyph identities that look alike in a terminal.
        assert!(validate_identity("eng\u{0430}1").is_err());
        assert!(validate_channel("gener\u{0430}l").is_err());
    }

    #[test]
    fn rejects_windows_reserved_device_names() {
        // An identity name becomes `keys/<name>.key`. On Windows the device
        // names win over the directory: `keys/CON.key` is the console, not a
        // file, so a key written there can never be read back. Measured:
        // `keryx keygen CON` prints a pubkey, then every later run fails with
        // `already exists`, because the entry exists but resolves to the device.
        for n in [
            "CON", "con", "Con", "PRN", "AUX", "NUL", "nul", "COM1", "COM9", "LPT1", "LPT9", "lpt9",
            "CON.key", "nul.txt",
        ] {
            let err = validate_identity(n).unwrap_err();
            assert_eq!(err.code, ErrorCode::BadRequest, "identity {n:?} must be refused");
        }
    }

    #[test]
    fn accepts_names_that_merely_resemble_a_device() {
        // The check is on the whole name before the first dot, not a substring:
        // these are ordinary files and must stay usable.
        for n in ["console", "con-artist", "null", "com0", "com10", "lpt", "lpt10", "auxiliary", "deploy.bot", "prn1"] {
            assert!(validate_identity(n).is_ok(), "identity {n:?} was wrongly refused");
        }
    }

    #[test]
    fn clamps_limits() {
        assert_eq!(clamp_read_limit(0), 1);
        assert_eq!(clamp_read_limit(50), 50);
        assert_eq!(clamp_read_limit(10_000), MAX_READ_LIMIT);
        assert_eq!(clamp_read_limit(u32::MAX), MAX_READ_LIMIT);
    }
}
