//! SQLite storage: the board itself, and the replay guard.
//!
//! # Replay protection
//!
//! The counter check and the insert happen in one `IMMEDIATE` transaction, so
//! there is no window between "sequence number accepted" and "row written" for a
//! second post to slip through.
//!
//! Three independent mechanisms guard against a replayed post, in order:
//!
//! 1. `UPDATE identities SET last_seq = :seq WHERE name = :id AND last_seq < :seq`.
//!    If this affects zero rows, either the identity is unknown or the sequence
//!    number was not strictly greater. Both are rejections.
//! 2. A `UNIQUE` index on `(sender_id, seq)`, so even a logic error above cannot
//!    produce two rows with the same identity and sequence number.
//! 3. `AUTOINCREMENT` cursors, which are never reused, so a client cursor
//!    cannot silently skip or repeat a message.
//!
//! # Why the daemon is the only writer
//!
//! Nothing else opens this database. The CLI and the wrapper both talk to the
//! daemon over a socket, so there is exactly one writer process and no lock
//! contention to reason about beyond SQLite's own.

use std::path::Path;

use idboard_core::envelope::{Envelope, Op, Provenance};
use idboard_core::error::{CoreError, ErrorCode};
use idboard_core::wire::{PeerStatus, StoredMessage};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use idboard_acl::Identity;

/// Storage failures, each mapping to a specific protocol error code.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("cannot prepare {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "replay: identity {sender_id:?} sent sequence {seq}, but the highest accepted is {last_seq}"
    )]
    Replay { sender_id: String, seq: i64, last_seq: i64 },

    #[error("identity {0:?} is not in the registry")]
    UnknownIdentity(String),

    #[error("failed to decode stored message at cursor {cursor}: {detail}")]
    Corrupt { cursor: i64, detail: String },
}

impl StoreError {
    /// The protocol code this failure should surface as.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Replay { .. } => ErrorCode::Replay,
            Self::UnknownIdentity(_) => ErrorCode::UnknownIdentity,
            // A daemon-side or operator-side problem, not the caller's fault.
            Self::Sqlite(_) | Self::Io { .. } | Self::Corrupt { .. } => ErrorCode::Internal,
        }
    }
}

impl From<StoreError> for CoreError {
    fn from(e: StoreError) -> Self {
        CoreError::new(e.code(), e.to_string())
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS messages (
    cursor     INTEGER PRIMARY KEY AUTOINCREMENT,
    channel    TEXT    NOT NULL,
    sender_id  TEXT    NOT NULL,
    sender_fp  TEXT    NOT NULL,
    seq        INTEGER NOT NULL,
    provenance TEXT    NOT NULL,
    body       TEXT    NOT NULL,
    ts_ms      INTEGER NOT NULL,
    signature  BLOB    NOT NULL
);

-- Replay backstop. The transaction check is the real guard; this makes a
-- logic error in that check a hard failure rather than silent duplication.
CREATE UNIQUE INDEX IF NOT EXISTS messages_sender_seq ON messages(sender_id, seq);

CREATE INDEX IF NOT EXISTS messages_channel_cursor ON messages(channel, cursor);

CREATE TABLE IF NOT EXISTS identities (
    name         TEXT PRIMARY KEY,
    role         TEXT    NOT NULL,
    pubkey       BLOB    NOT NULL,
    fingerprint  TEXT    NOT NULL,
    last_seq     INTEGER NOT NULL DEFAULT 0,
    last_seen_ms INTEGER NOT NULL DEFAULT 0
);
"#;

/// Rough per-row cost of everything in a `StoredMessage` that is not the body:
/// cursor, sender, fingerprint, sequence, provenance, timestamp, signature, and
/// the JSON keys and quoting around them. Only used to keep a page of tiny
/// messages bounded, so an over-estimate is harmless.
const ENVELOPE_OVERHEAD_BYTES: usize = 512;

/// How many bytes of message body one read response will carry.
///
/// A read page is a single frame on a single connection, so it has to fit inside
/// `idboard_ipc::MAX_FRAME_BYTES`. Without this budget the daemon would happily
/// build a response too large to write — up to `MAX_READ_LIMIT` bodies of 64 KiB,
/// about 64 MiB in its heap — and then fail closed at the write, which makes
/// reading a backlog larger than the frame cap impossible rather than merely
/// paged.
///
/// Deliberately a local constant rather than an import from `idboard-ipc`: the
/// budget is what the *store* promises, and storage taking a dependency on the
/// transport crate to read one number is the wrong direction for the tree. The
/// coupling to the frame cap is pinned by
/// `a_backlog_larger_than_one_frame_is_still_readable` in the e2e suite.
const READ_BUDGET_BYTES: usize = 256 * 1024;

/// Handle to the board.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if needed) the database at `path` and apply the schema.
    ///
    /// The state root is created owner-only, and so is the database file itself.
    /// The directory alone is not enough: a file that already exists keeps
    /// whatever mode it had, and SQLite would create a new one with the process
    /// umask rather than a mode we chose.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            idboard_core::layout::ensure_private_dir(parent)
                .map_err(|source| StoreError::Io { path: parent.display().to_string(), source })?;
        }
        create_owner_only(path)
            .map_err(|source| StoreError::Io { path: path.display().to_string(), source })?;
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Open a throwaway in-memory board. Used by tests.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, StoreError> {
        // WAL keeps a reader from blocking the writer. With a single writer
        // process this is belt and braces, but it is free and it means a slow
        // `subscribe` poll cannot stall a post.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Seed the identity registry from the loaded config.
    ///
    /// Called once at daemon startup. `last_seq` is preserved across restarts
    /// by design: a restarted wrapper resumes above the last accepted number,
    /// and a daemon restart must not reset that.
    ///
    /// Returns the identities whose registered public key changed since the last
    /// run, which is worth a loud warning: it means either a deliberate key
    /// rotation or a config mistake, and in the second case nobody can post.
    pub fn register_identities(&mut self, identities: &[&Identity]) -> Result<Vec<String>, StoreError> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut rotated = Vec::new();
        for id in identities {
            let existing: Option<Vec<u8>> = tx
                .query_row("SELECT pubkey FROM identities WHERE name = ?1", params![id.name], |r| r.get(0))
                .optional()?;
            match existing {
                Some(prev) if prev != id.public_key.to_bytes() => {
                    rotated.push(id.name.clone());
                }
                Some(_) => {
                    // Key unchanged. Refresh role and fingerprint in case the
                    // config moved them, but never touch last_seq.
                    tx.execute(
                        "UPDATE identities SET role = ?2, fingerprint = ?3 WHERE name = ?1",
                        params![id.name, id.role, id.fingerprint],
                    )?;
                }
                None => {
                    tx.execute(
                        "INSERT INTO identities (name, role, pubkey, fingerprint, last_seq, last_seen_ms)
                         VALUES (?1, ?2, ?3, ?4, 0, 0)",
                        params![id.name, id.role, id.public_key.to_bytes().to_vec(), id.fingerprint],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(rotated)
    }

    /// Highest sequence number accepted for an identity.
    ///
    /// Zero means "nothing accepted yet", which is the correct answer for a
    /// fresh identity and makes a fresh counter start at 1.
    ///
    /// An identity that is not in the registry is an error, not a zero. Failing
    /// open here would hand a caller a reusable counter, which is the one
    /// direction a replay guard must never fail in. Unreachable today because
    /// [`register_identities`](Self::register_identities) seeds every configured
    /// identity at startup, but "unreachable" is not a reason to be wrong.
    pub fn last_seq(&self, identity: &str) -> Result<i64, StoreError> {
        let v: Option<i64> = self
            .conn
            .query_row("SELECT last_seq FROM identities WHERE name = ?1", params![identity], |r| r.get(0))
            .optional()?;
        v.ok_or_else(|| StoreError::UnknownIdentity(identity.to_string()))
    }

    /// Append a verified message, rejecting a non-increasing sequence number.
    ///
    /// The caller must have verified the signature and checked the ACL before
    /// getting here. This function's contract is that `envelope.sender_id`
    /// matches `verified`, and it does not re-derive that: the check belongs at
    /// the trust boundary, not here, and duplicating it invites the two copies
    /// to disagree.
    pub fn append(
        &mut self,
        verified: &str,
        envelope: &Envelope,
        now_ms: i64,
    ) -> Result<StoredMessage, StoreError> {
        debug_assert_eq!(verified, envelope.sender_id, "caller must pass the verified identity");

        let signature = hex::decode(&envelope.signature).map_err(|e| StoreError::Corrupt {
            cursor: -1,
            detail: format!("signature is not valid hex: {e}"),
        })?;

        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        // Mechanism 1: guarded advance. Zero rows affected means either the
        // identity is absent or the number did not strictly increase.
        let advanced = tx.execute(
            "UPDATE identities SET last_seq = ?2, last_seen_ms = ?3
             WHERE name = ?1 AND last_seq < ?2",
            params![verified, envelope.seq, now_ms],
        )?;
        if advanced == 0 {
            let last_seq: Option<i64> = tx
                .query_row("SELECT last_seq FROM identities WHERE name = ?1", params![verified], |r| r.get(0))
                .optional()?;
            return match last_seq {
                Some(last_seq) => Err(StoreError::Replay {
                    sender_id: verified.to_string(),
                    seq: envelope.seq,
                    last_seq,
                }),
                None => Err(StoreError::UnknownIdentity(verified.to_string())),
            };
        }

        tx.execute(
            "INSERT INTO messages (channel, sender_id, sender_fp, seq, provenance, body, ts_ms, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                envelope.channel,
                verified,
                envelope.sender_pubkey_fp,
                envelope.seq,
                provenance_str(envelope.provenance),
                envelope.body,
                envelope.timestamp,
                signature,
            ],
        )?;

        let cursor = tx.last_insert_rowid();
        tx.commit()?;

        Ok(StoredMessage { cursor, envelope: envelope.clone() })
    }

    /// Note that an identity was seen, without touching its counter.
    ///
    /// For read-only ops, which are authenticated by timestamp and must not
    /// consume a sequence number.
    pub fn touch(&self, identity: &str, now_ms: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE identities SET last_seen_ms = ?2 WHERE name = ?1",
            params![identity, now_ms],
        )?;
        Ok(())
    }

    /// Fetch up to `limit` messages in `channel` with a cursor above `since`.
    ///
    /// The response is also bounded by [`READ_BUDGET_BYTES`], so a page of
    /// large bodies cannot produce a frame the daemon is then unable to write.
    /// The budget only ever truncates the page early; the cursor contract is
    /// unchanged, because [`handle_read`](crate::handle_read) already reports the
    /// last cursor actually returned and a short page is a normal outcome.
    pub fn read(&self, channel: &str, since: i64, limit: usize) -> Result<Vec<StoredMessage>, StoreError> {
        let mut stmt = self.conn.prepare_cached(
            // `channel` is selected as well as filtered on, so the read-back
            // envelope is the envelope that was authenticated rather than a copy
            // with a hole in it.
            //
            // `lower()` because SQLite's hex() emits uppercase, and an
            // envelope's signature is lowercase hex. Without this a read-back
            // signature would not compare equal to the one that was signed,
            // which would silently break any re-verification against stored data.
            "SELECT cursor, channel, sender_id, sender_fp, seq, provenance, body, ts_ms, lower(hex(signature))
             FROM messages
             WHERE channel = ?1 AND cursor > ?2
             ORDER BY cursor ASC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![channel, since, limit as i64], row_to_message)?;
        let mut out = Vec::new();
        let mut budget = READ_BUDGET_BYTES;
        for r in rows {
            let message = r?;
            // The body dominates the row, and the rest of the envelope is a few
            // hundred bytes. Charge a floor per row so a page of empty bodies
            // still cannot run to `limit` unbounded overhead.
            let charge = message.envelope.body.len() + ENVELOPE_OVERHEAD_BYTES;
            if !out.is_empty() && budget < charge {
                break;
            }
            budget = budget.saturating_sub(charge);
            out.push(message);
        }
        Ok(out)
    }

    /// The newest `limit` messages in `channel`, oldest first.
    ///
    /// `read` walks forward from a cursor, which is what a poller wants; an
    /// inbox wants the opposite end, and subtracting from a cursor does not work
    /// because cursors are global row ids shared across channels. So this is a
    /// separate query, ordered DESC and reversed, and it applies the same byte
    /// budget as `read` so a digest of many large bodies cannot build a frame the
    /// daemon then fails to write.
    pub fn read_tail(&self, channel: &str, limit: usize) -> Result<Vec<StoredMessage>, StoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut stmt = self.conn.prepare_cached(
            "SELECT cursor, channel, sender_id, sender_fp, seq, provenance, body, ts_ms, lower(hex(signature))
             FROM messages
             WHERE channel = ?1
             ORDER BY cursor DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![channel, limit as i64], row_to_message)?;
        let mut out = Vec::new();
        let mut budget = READ_BUDGET_BYTES;
        for r in rows {
            let message = r?;
            let charge = message.envelope.body.len() + ENVELOPE_OVERHEAD_BYTES;
            if !out.is_empty() && budget < charge {
                break;
            }
            budget = budget.saturating_sub(charge);
            out.push(message);
        }
        out.reverse();
        Ok(out)
    }

    /// Newest cursor in one channel, or zero if it has no messages.
    pub fn channel_high_water(&self, channel: &str) -> Result<i64, StoreError> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(MAX(cursor), 0) FROM messages WHERE channel = ?1",
            params![channel],
            |r| r.get(0),
        )?)
    }

    /// The roster, with the last time each identity was seen, newest first.
    ///
    /// `last_seen_ms` is 0 for an identity that has never sent anything, which
    /// is a fact worth showing rather than hiding: a configured identity that has
    /// never acted is different from one that acted yesterday.
    ///
    /// This is diagnostic data. Nothing in the authorisation path consults it.
    pub fn peers(&self) -> Result<Vec<PeerStatus>, StoreError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT name, role, last_seen_ms FROM identities
             ORDER BY last_seen_ms DESC, name ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(PeerStatus { identity: r.get(0)?, role: r.get(1)?, last_seen_ms: r.get(2)? })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Total messages stored, for diagnostics and tests.
    pub fn message_count(&self) -> Result<i64, StoreError> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?)
    }

    /// Newest cursor in use, or zero for an empty board. This is the value a
    /// fresh reader should pass as `since` to see everything.
    pub fn high_water_cursor(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT COALESCE(MAX(cursor), 0) FROM messages", [], |r| r.get(0))?)
    }

    /// Raw signature bytes, for a test that needs to prove they were stored
    /// faithfully rather than trusting a round-trip through hex.
    pub fn signature_bytes(&self, cursor: i64) -> Result<Vec<u8>, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT signature FROM messages WHERE cursor = ?1", params![cursor], |r| r.get(0))?)
    }

    /// Direct access for tests that need to assert on schema state.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

/// Create the database file with owner-only permissions if it is not there yet.
///
/// No-op on Windows, which has no file mode: NTFS inherits the ACL from the
/// state root, which `ensure_private_dir` has already created. On Unix the mode
/// is set at creation rather than afterwards, so the file is never briefly
/// readable by anyone else.
fn create_owner_only(path: &Path) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    drop(opts.open(path)?);
    Ok(())
}

fn provenance_str(p: Provenance) -> &'static str {    match p {
        Provenance::SelfOriginated => "self",
        Provenance::External => "external",
        Provenance::NotApplicable => "n/a",
    }
}

fn provenance_from_str(s: &str) -> Result<Provenance, StoreError> {
    match s {
        "self" => Ok(Provenance::SelfOriginated),
        "external" => Ok(Provenance::External),
        "n/a" => Ok(Provenance::NotApplicable),
        other => Err(StoreError::Corrupt { cursor: -1, detail: format!("unknown provenance {other:?}") }),
    }
}

fn row_to_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMessage> {
    let cursor: i64 = row.get(0)?;
    let channel: String = row.get(1)?;
    let sender_id: String = row.get(2)?;
    let sender_fp: String = row.get(3)?;
    let seq: i64 = row.get(4)?;
    let provenance: String = row.get(5)?;
    let body: String = row.get(6)?;
    let ts_ms: i64 = row.get(7)?;
    let signature: String = row.get(8)?;

    let provenance = provenance_from_str(&provenance).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            5, // column index of `provenance` in the SELECT above
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(e.to_string())),
        )
    })?;

    Ok(StoredMessage {
        cursor,
        envelope: Envelope {
            op: Op::Post,
            sender_id,
            sender_pubkey_fp: sender_fp,
            // The channel the message was *authenticated into*, not a
            // placeholder. Every field above this line is inside the signature,
            // so substituting an empty one here produced a message that could no
            // longer be re-verified: `validate_channel` rejected it before the
            // signature was ever reached.
            channel,
            body,
            provenance,
            seq,
            timestamp: ts_ms,
            nonce: String::new(),
            signature,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use idboard_core::keys::LocalSigner;

    fn signer(id: &str) -> LocalSigner {
        LocalSigner::generate(id).unwrap().0
    }

    fn register(store: &mut Store, s: &LocalSigner) {
        let id = Identity {
            name: s.sender_id().to_string(),
            role: s.sender_id().to_string(),
            public_key: s.verifying_key(),
            pubkey_hex: s.public_hex(),
            fingerprint: s.fingerprint().to_string(),
            description: None,
            force_external: false,
        };
        assert!(store.register_identities(&[&id]).unwrap().is_empty());
    }

    fn post(s: &LocalSigner, channel: &str, body: &str, seq: i64) -> Envelope {
        s.sign_post(channel, body, Provenance::SelfOriginated, seq, 1_758_900_000_000).unwrap()
    }

    #[test]
    fn schema_applies_to_a_fresh_database() {
        let store = Store::open_in_memory().unwrap();
        let n: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('messages','identities')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn append_and_read_round_trip() {
        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);

        let env = post(&s, "general", "hello", 1);
        let stored = store.append("eng-01", &env, 1_758_900_000_000).unwrap();
        assert!(stored.cursor > 0);

        let got = store.read("general", 0, 100).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].envelope.body, "hello");
        assert_eq!(got[0].envelope.sender_id, "eng-01");
        assert_eq!(got[0].envelope.seq, 1);
        assert_eq!(got[0].envelope.provenance, Provenance::SelfOriginated);
        assert_eq!(got[0].envelope.signature, env.signature);
    }

    /// A message read back must be the envelope that was authenticated, not a
    /// copy with a hole in it. `channel` is inside the signature, so dropping it
    /// meant a reader could not check a delivered message against the signature
    /// that produced it — the whole point of the board.
    #[test]
    fn a_read_back_message_carries_the_channel_it_was_signed_for() {
        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);

        let env = post(&s, "deploy/prod", "ship it", 1);
        store.append("eng-01", &env, 1_758_900_000_000).unwrap();

        let got = store.read("deploy/prod", 0, 100).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].envelope.channel, "deploy/prod");
    }

    /// The consequence of the above, and the reason it mattered: a read-back
    /// message must still verify against the key that signed it.
    ///
    /// Before the projection was fixed this failed *early and closed* — not at the
    /// signature, but inside `verify_with_key`, which calls `env.validate()`
    /// before building canonical bytes, and the post invariants call
    /// `validate_channel`, which rejects the empty string with `bad_request`.
    #[test]
    fn a_read_back_message_still_verifies_against_its_signer() {
        use idboard_core::keys::verify_with_key;

        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);

        let env = post(&s, "general", "hello", 1);
        store.append("eng-01", &env, 1_758_900_000_000).unwrap();

        let got = store.read("general", 0, 100).unwrap();
        let back = &got[0].envelope;
        let verified = verify_with_key(&s.verifying_key(), back).expect("read-back must verify");
        assert_eq!(verified.sender_id, "eng-01");
    }

    /// An unknown identity must be an error, not a fresh counter.
    ///
    /// `last_seq` used to return `Ok(unwrap_or(0))`, which fails open: a caller
    /// for an identity the registry has never heard of was told "nothing
    /// accepted yet" and would start again at 1.
    #[test]
    fn last_seq_fails_closed_for_an_identity_the_registry_does_not_hold() {
        let store = Store::open_in_memory().unwrap();
        let err = store.last_seq("never-registered").unwrap_err();
        assert!(
            matches!(err, StoreError::UnknownIdentity(ref n) if n == "never-registered"),
            "{err}"
        );
        // And the direction of failure is the point: this must not be `Ok(0)`.
        assert!(store.last_seq("never-registered").is_err());
    }

    /// A read page has to fit in one frame on one connection. Without a byte
    /// budget the store would build a response the transport then refuses to
    /// write, so a backlog larger than the frame cap became unreadable rather
    /// than paged.
    #[test]
    fn a_read_page_is_bounded_by_bytes_and_still_advances() {
        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);

        // 20 bodies of 32 KiB is 640 KiB: over the budget, so a page must stop
        // early rather than return all twenty.
        let big = "b".repeat(32 * 1024);
        for seq in 1..=20 {
            store
                .append("eng-01", &post(&s, "general", &big, seq), 1_758_900_000_000)
                .unwrap();
        }

        let first = store.read("general", 0, 100).unwrap();
        assert!(!first.is_empty(), "the budget must not return nothing");
        assert!(first.len() < 20, "the budget did not bound the page: {} rows", first.len());
        let bytes: usize = first.iter().map(|m| m.envelope.body.len()).sum();
        assert!(bytes <= READ_BUDGET_BYTES, "page carried {bytes} bytes");

        // The cursor contract is unchanged: a short page is normal, and the
        // caller resumes from the last row it actually received.
        let last = first.last().unwrap().cursor;
        let second = store.read("general", last, 100).unwrap();
        assert!(!second.is_empty());
        assert!(second[0].cursor > last, "the second page must move forward");
        assert_ne!(second[0].envelope.seq, first[0].envelope.seq, "pages must not overlap");
    }

    #[test]
    fn signature_bytes_are_stored_faithfully() {
        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);
        let env = post(&s, "general", "hello", 1);
        let stored = store.append("eng-01", &env, 1).unwrap();
        assert_eq!(
            store.signature_bytes(stored.cursor).unwrap(),
            hex::decode(&env.signature).unwrap()
        );
    }

    /// The core replay property, for sequence numbers that are structurally
    /// valid but not strictly increasing.
    ///
    /// Zero and negative sequence numbers are absent on purpose: they never
    /// reach the store, because `Envelope::check_op_invariants` rejects them at
    /// the signing and verification boundary. The store's job is narrower, and
    /// this is the guard for exactly that job.
    #[test]
    fn replayed_sequence_number_is_rejected() {
        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);
        store.append("eng-01", &post(&s, "general", "first", 1), 1).unwrap();
        store.append("eng-01", &post(&s, "general", "second", 2), 1).unwrap();

        for bad_seq in [1, 2] {
            let err = store.append("eng-01", &post(&s, "general", "replay", bad_seq), 2).unwrap_err();
            assert_eq!(err.code(), ErrorCode::Replay, "seq {bad_seq} should be a replay");
        }
        assert_eq!(store.message_count().unwrap(), 2, "no replayed message may be stored");
        assert_eq!(store.last_seq("eng-01").unwrap(), 2, "a rejected post must not advance the counter");
    }

    /// A gap followed by a lower number: legal signature, stale sequence.
    #[test]
    fn a_number_below_the_high_water_mark_is_a_replay() {
        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);
        store.append("eng-01", &post(&s, "general", "one", 1), 1).unwrap();
        store.append("eng-01", &post(&s, "general", "ten", 10), 1).unwrap();
        let err = store.append("eng-01", &post(&s, "general", "five", 5), 1).unwrap_err();
        assert!(matches!(err, StoreError::Replay { seq: 5, last_seq: 10, .. }), "{err}");
    }

    /// A captured envelope resubmitted verbatim is a replay. The signature is
    /// still perfectly valid; only the counter stops it.
    #[test]
    fn verbatim_replay_of_a_valid_envelope_is_rejected() {
        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);
        let captured = post(&s, "general", "transfer 100", 1);
        store.append("eng-01", &captured, 1).unwrap();

        let err = store.append("eng-01", &captured, 2).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Replay);
        assert!(matches!(err, StoreError::Replay { seq: 1, last_seq: 1, .. }));
    }

    /// Gaps are tolerated: a send that failed in flight must not permanently
    /// lock an identity out.
    #[test]
    fn sequence_gaps_are_tolerated() {
        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);
        store.append("eng-01", &post(&s, "general", "one", 1), 1).unwrap();
        store.append("eng-01", &post(&s, "general", "five", 5), 2).unwrap();
        store.append("eng-01", &post(&s, "general", "six", 6), 3).unwrap();
        assert_eq!(store.message_count().unwrap(), 3);
        assert_eq!(store.last_seq("eng-01").unwrap(), 6);
    }

    #[test]
    fn counters_are_independent_per_identity() {
        let mut store = Store::open_in_memory().unwrap();
        let a = signer("eng-01");
        let b = signer("eng-02");
        register(&mut store, &a);
        register(&mut store, &b);

        for i in 1..=3 {
            store.append("eng-01", &post(&a, "general", "a", i), 1).unwrap();
            store.append("eng-02", &post(&b, "general", "b", i), 1).unwrap();
        }
        assert_eq!(store.last_seq("eng-01").unwrap(), 3);
        assert_eq!(store.last_seq("eng-02").unwrap(), 3);
        assert_eq!(store.message_count().unwrap(), 6);
    }

    #[test]
    fn last_seq_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("board.db");
        let s = signer("eng-01");
        {
            let mut store = Store::open(&path).unwrap();
            let id = Identity {
                name: "eng-01".into(),
                role: "eng-01".into(),
                public_key: s.verifying_key(),
                pubkey_hex: s.public_hex(),
                fingerprint: s.fingerprint().into(),
                description: None,
                force_external: false,
            };
            store.register_identities(&[&id]).unwrap();
            store.append("eng-01", &post(&s, "general", "persisted", 1), 1).unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.last_seq("eng-01").unwrap(), 1, "a daemon restart must not reset the counter");
        assert_eq!(store.read("general", 0, 10).unwrap().len(), 1);
    }

    #[test]
    fn unknown_identity_is_distinguished_from_replay() {
        let mut store = Store::open_in_memory().unwrap();
        let ghost = signer("ghost");
        let err = store.append("ghost", &post(&ghost, "general", "x", 1), 1).unwrap_err();
        assert_eq!(err.code(), ErrorCode::UnknownIdentity);
        assert!(matches!(err, StoreError::UnknownIdentity(_)));
    }

    #[test]
    fn key_rotation_is_reported_and_resets_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("board.db");
        let old = signer("eng-01");
        let new = signer("eng-01");

        let mut store = Store::open(&path).unwrap();
        let id_old = Identity {
            name: "eng-01".into(),
            role: "eng-01".into(),
            public_key: old.verifying_key(),
            pubkey_hex: old.public_hex(),
            fingerprint: old.fingerprint().into(),
            description: None,
            force_external: false,
        };
        store.register_identities(&[&id_old]).unwrap();
        store.append("eng-01", &post(&old, "general", "before", 1), 1).unwrap();

        let id_new = Identity {
            name: "eng-01".into(),
            role: "eng-01".into(),
            public_key: new.verifying_key(),
            pubkey_hex: new.public_hex(),
            fingerprint: new.fingerprint().into(),
            description: None,
            force_external: false,
        };
        let rotated = store.register_identities(&[&id_new]).unwrap();
        assert_eq!(rotated, vec!["eng-01".to_string()], "a changed key must be reported");

        // The new key cannot rewind the counter, but must be able to continue it.
        assert!(matches!(
            store.append("eng-01", &post(&new, "general", "rewind", 1), 2),
            Err(StoreError::Replay { .. })
        ));
        store.append("eng-01", &post(&new, "general", "after", 2), 3).unwrap();
        assert_eq!(store.read("general", 0, 10).unwrap().len(), 2);
    }

    #[test]
    fn unchanged_key_is_not_reported_as_rotated() {
        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);
        let id = Identity {
            name: "eng-01".into(),
            role: "lead".into(), // role changed, key did not
            public_key: s.verifying_key(),
            pubkey_hex: s.public_hex(),
            fingerprint: s.fingerprint().into(),
            description: None,
            force_external: false,
        };
        assert!(store.register_identities(&[&id]).unwrap().is_empty());
    }

    #[test]
    fn read_is_scoped_by_channel_and_cursor() {
        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);
        for i in 1..=5 {
            store.append("eng-01", &post(&s, "general", &format!("g{i}"), i), 1).unwrap();
        }
        for i in 1..=2 {
            store.append("eng-01", &post(&s, "other", &format!("o{i}"), 5 + i), 1).unwrap();
        }

        assert_eq!(store.read("general", 0, 100).unwrap().len(), 5);
        assert_eq!(store.read("other", 0, 100).unwrap().len(), 2);
        assert_eq!(store.read("nope", 0, 100).unwrap().len(), 0);

        let all = store.read("general", 0, 100).unwrap();
        assert_eq!(store.read("general", all.last().unwrap().cursor, 100).unwrap().len(), 0);
        assert_eq!(store.read("general", all[1].cursor, 100).unwrap().len(), 3);
    }

    #[test]
    fn read_respects_the_limit_and_keeps_cursor_order() {
        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);
        for i in 1..=10 {
            store.append("eng-01", &post(&s, "general", &format!("m{i}"), i), 1).unwrap();
        }
        let page = store.read("general", 0, 4).unwrap();
        assert_eq!(page.len(), 4);
        assert_eq!(page[0].envelope.body, "m1");
        assert_eq!(page[3].envelope.body, "m4");
        for w in page.windows(2) {
            assert!(w[0].cursor < w[1].cursor, "cursors must strictly increase");
        }
    }

    /// Cursors are monotonic and never reused, which is what makes `since` a
    /// safe resumption token across daemon restarts.
    #[test]
    fn cursors_are_unique_and_never_reused_after_deletion() {
        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);
        let mut seen = std::collections::HashSet::new();
        for i in 1..=20 {
            let m = store.append("eng-01", &post(&s, "general", "x", i), 1).unwrap();
            assert!(seen.insert(m.cursor), "cursor {} reused", m.cursor);
        }
        store.connection().execute("DELETE FROM messages", []).unwrap();
        let m = store.append("eng-01", &post(&s, "general", "after delete", 21), 1).unwrap();
        assert!(!seen.contains(&m.cursor), "AUTOINCREMENT must not reuse a deleted cursor");
    }

    #[test]
    fn touch_does_not_advance_the_counter() {
        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);
        store.append("eng-01", &post(&s, "general", "x", 1), 1).unwrap();
        store.touch("eng-01", 999).unwrap();
        assert_eq!(store.last_seq("eng-01").unwrap(), 1, "reads must not consume sequence numbers");
    }

    #[test]
    fn high_water_cursor_on_empty_and_populated_boards() {
        let mut store = Store::open_in_memory().unwrap();
        assert_eq!(store.high_water_cursor().unwrap(), 0);
        let s = signer("eng-01");
        register(&mut store, &s);
        let m = store.append("eng-01", &post(&s, "general", "x", 1), 1).unwrap();
        assert_eq!(store.high_water_cursor().unwrap(), m.cursor);
    }

    /// Cursors are global row ids, so "the newest five in this channel" is not
    /// `high_water - 5`. This is the query that answers it correctly.
    #[test]
    fn read_tail_returns_the_newest_messages_oldest_first() {
        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);
        for i in 1..=5 {
            store.append("eng-01", &post(&s, "general", &format!("m{i}"), i), 1).unwrap();
        }
        // Interleave another channel so the cursors are not contiguous here.
        store.append("eng-01", &post(&s, "other", "elsewhere", 6), 1).unwrap();

        let tail = store.read_tail("general", 2).unwrap();
        let bodies: Vec<&str> = tail.iter().map(|m| m.envelope.body.as_str()).collect();
        assert_eq!(bodies, ["m4", "m5"], "newest page, oldest first");

        assert!(store.read_tail("general", 0).unwrap().is_empty(), "zero means no rows");
        assert_eq!(store.read_tail("nothing-here", 5).unwrap().len(), 0);
    }

    #[test]
    fn channel_high_water_is_per_channel() {
        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);
        assert_eq!(store.channel_high_water("general").unwrap(), 0);
        store.append("eng-01", &post(&s, "general", "a", 1), 1).unwrap();
        let second = store.append("eng-01", &post(&s, "other", "b", 2), 1).unwrap();
        assert_eq!(store.high_water_cursor().unwrap(), second.cursor);
        assert!(
            store.channel_high_water("general").unwrap() < second.cursor,
            "a channel cursor must not inherit another channel's position"
        );
    }

    #[test]
    fn peers_are_ordered_by_last_seen_and_include_the_never_seen() {
        let mut store = Store::open_in_memory().unwrap();
        let a = signer("eng-01");
        let b = signer("lead");
        register(&mut store, &a);
        register(&mut store, &b);
        store.append("eng-01", &post(&a, "general", "x", 1), 500).unwrap();

        let peers = store.peers().unwrap();
        assert_eq!(peers[0].identity, "eng-01");
        assert_eq!(peers[0].last_seen_ms, 500);
        assert_eq!(peers[1].identity, "lead");
        assert_eq!(peers[1].last_seen_ms, 0, "never-seen identities sort last and say so");
    }

    #[test]
    fn external_provenance_round_trips() {
        let mut store = Store::open_in_memory().unwrap();
        let s = signer("eng-01");
        register(&mut store, &s);
        let env = s
            .sign_post("general", "copied from a web page", Provenance::External, 1, 1)
            .unwrap();
        store.append("eng-01", &env, 1).unwrap();
        assert_eq!(store.read("general", 0, 10).unwrap()[0].envelope.provenance, Provenance::External);
    }
}
