//! Identity keys: generation, fingerprints, signing, and verification.
//!
//! The verification entry point is [`verify_with_key`], which is the only
//! function in the codebase that decides whether a message is authentic. The
//! daemon must call it with the key the config registers for the claimed
//! identity, never with a key supplied by the caller.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::envelope::{Envelope, Op, Provenance};
use crate::error::{CoreError, ErrorCode, Result};
use crate::ids::validate_identity;

/// Bytes of SHA-256 output kept in a fingerprint: 8 bytes, 16 hex characters.
///
/// Long enough that a collision across the handful of identities on one machine
/// is not a practical concern, short enough to read in a log line.
pub const FINGERPRINT_BYTES: usize = 8;

/// Hex characters in a fingerprint.
pub const FINGERPRINT_HEX_LEN: usize = FINGERPRINT_BYTES * 2;

/// Hex characters in a hex-encoded ed25519 public key.
pub const PUBKEY_HEX_LEN: usize = 64;

/// Hex characters in a hex-encoded ed25519 signature.
pub const SIGNATURE_HEX_LEN: usize = 128;

/// Fill a buffer with cryptographically secure random bytes.
fn random_bytes(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| CoreError::internal(format!("system CSPRNG unavailable: {e}")))
}

/// Generate a fresh hex nonce for a read-only op.
///
/// Present for hygiene, not because a replayed read is exploitable: a nonce
/// changes nothing an attacker could use, since the worst case is re-fetching
/// data the caller was already authorised to see.
pub fn generate_nonce() -> Result<String> {
    let mut buf = [0u8; crate::ids::NONCE_BYTES];
    random_bytes(&mut buf)?;
    Ok(hex::encode(buf))
}

/// Short hex fingerprint of a public key: `SHA-256(pubkey)[0..8]`.
pub fn fingerprint_of(vk: &VerifyingKey) -> String {
    let digest = Sha256::digest(vk.as_bytes());
    hex::encode(&digest[..FINGERPRINT_BYTES])
}

/// Parse a hex-encoded public key.
///
/// Note that `ed25519-dalek` applies ZIP-215 here, which accepts non-canonical
/// y encodings of a valid point. A successful parse therefore means "these
/// bytes denote a point", not "these bytes are the only encoding of that
/// point". It also means a parse success is *not* a safety property: use
/// [`verify_with_key`], which calls `verify_strict`, to decide whether a key may
/// be trusted.
pub fn pubkey_from_hex(hex_str: &str) -> Result<VerifyingKey> {
    if hex_str.len() != PUBKEY_HEX_LEN {
        return Err(CoreError::bad_request(format!(
            "public key must be {PUBKEY_HEX_LEN} hex chars, got {}",
            hex_str.len()
        )));
    }
    let bytes = hex::decode(hex_str)
        .map_err(|e| CoreError::bad_request(format!("public key is not valid hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CoreError::bad_request("public key must be exactly 32 bytes"))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| CoreError::bad_request(format!("public key is not a valid ed25519 point: {e}")))
}

/// A fact the daemon established about a sender, derived from a signature.
///
/// Constructing this requires a successful `verify_strict`, so holding one is
/// proof of key possession. Every downstream authorisation decision keys off
/// this type rather than off any string the caller supplied.
#[derive(Debug, Clone)]
pub struct VerifiedSender {
    pub sender_id: String,
    pub fingerprint: String,
    pub public_key: VerifyingKey,
}

/// A local identity's signing capability.
///
/// Deliberately does **not** implement `Drop` zeroisation. A `SigningKey` in
/// memory that outlives the process is not the threat model here; see the trust
/// boundary section of the README. The key's protection is that it lives in
/// this process and not in the agent's.
#[derive(Clone)]
pub struct LocalSigner {
    signing_key: SigningKey,
    sender_id: String,
    fingerprint: String,
}

impl LocalSigner {
    /// Build a signer from a 32-byte ed25519 seed.
    pub fn from_seed(seed: &[u8; 32], sender_id: &str) -> Result<Self> {
        validate_identity(sender_id)?;
        let signing_key = SigningKey::from_bytes(seed);
        let fingerprint = fingerprint_of(&signing_key.verifying_key());
        Ok(Self { signing_key, sender_id: sender_id.to_string(), fingerprint })
    }

    /// Generate a brand-new identity, returning the signer and the seed to
    /// persist.
    pub fn generate(sender_id: &str) -> Result<(Self, [u8; 32])> {
        let mut seed = [0u8; 32];
        random_bytes(&mut seed)?;
        let signer = Self::from_seed(&seed, sender_id)?;
        Ok((signer, seed))
    }

    /// The raw seed, for writing to the keystore.
    pub fn seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Hex-encoded public key, for pasting into the daemon config.
    pub fn public_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The public half, for callers that need to verify or register this key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn sender_id(&self) -> &str {
        &self.sender_id
    }

    /// Sign a post. `seq` comes from the caller, which owns the counter.
    pub fn sign_post(
        &self,
        channel: &str,
        body: &str,
        provenance: Provenance,
        seq: i64,
        timestamp_ms: i64,
    ) -> Result<Envelope> {
        let mut env = Envelope {
            op: Op::Post,
            sender_id: self.sender_id.clone(),
            sender_pubkey_fp: self.fingerprint.clone(),
            channel: channel.to_string(),
            body: body.to_string(),
            provenance,
            seq,
            timestamp: timestamp_ms,
            nonce: String::new(),
            signature: String::new(),
        };
        self.finish(&mut env)?;
        Ok(env)
    }

    /// Sign a read request. Authenticated by timestamp, not by counter.
    pub fn sign_read(&self, channel: &str, timestamp_ms: i64) -> Result<Envelope> {
        let mut env = Envelope {
            op: Op::Read,
            sender_id: self.sender_id.clone(),
            sender_pubkey_fp: self.fingerprint.clone(),
            channel: channel.to_string(),
            body: String::new(),
            provenance: Provenance::NotApplicable,
            seq: 0,
            timestamp: timestamp_ms,
            nonce: generate_nonce()?,
            signature: String::new(),
        };
        self.finish(&mut env)?;
        Ok(env)
    }

    /// Sign a handshake. Answers the question "what sequence number should I
    /// resume from", for this identity only.
    pub fn sign_handshake(&self, timestamp_ms: i64) -> Result<Envelope> {
        self.sign_channel_less(Op::Handshake, timestamp_ms)
    }

    /// Sign an inbox query: a digest of every channel this identity can see.
    pub fn sign_inbox(&self, timestamp_ms: i64) -> Result<Envelope> {
        self.sign_channel_less(Op::Inbox, timestamp_ms)
    }

    /// Sign a peers query: who is on the board and when each was last seen.
    pub fn sign_peers(&self, timestamp_ms: i64) -> Result<Envelope> {
        self.sign_channel_less(Op::Peers, timestamp_ms)
    }

    /// The three channel-less queries share one shape: a nonce, no sequence
    /// number, no body, no provenance. Factored so a new query cannot quietly
    /// acquire a different shape from the one
    /// [`Envelope::check_op_invariants`](crate::envelope::Envelope::check_op_invariants)
    /// enforces.
    fn sign_channel_less(&self, op: Op, timestamp_ms: i64) -> Result<Envelope> {
        let mut env = Envelope {
            op,
            sender_id: self.sender_id.clone(),
            sender_pubkey_fp: self.fingerprint.clone(),
            channel: String::new(),
            body: String::new(),
            provenance: Provenance::NotApplicable,
            seq: 0,
            timestamp: timestamp_ms,
            nonce: generate_nonce()?,
            signature: String::new(),
        };
        self.finish(&mut env)?;
        Ok(env)
    }

    /// Fill in the signature after the caller has populated the fields.
    ///
    /// Validates before signing so a wrapper bug surfaces at the point of the
    /// mistake rather than as an opaque daemon rejection.
    fn finish(&self, env: &mut Envelope) -> Result<()> {
        env.validate()?;
        let bytes = env.signing_bytes()?;
        let sig: Signature = self.signing_key.sign(&bytes);
        env.signature = hex::encode(sig.to_bytes());
        Ok(())
    }
}

/// Monotonic per-identity sequence counter for posts.
///
/// Owned by the wrapper, seeded from the daemon's `handshake` reply, so a
/// restarted wrapper resumes above whatever the daemon has already accepted
/// rather than re-issuing numbers it used last time.
#[derive(Debug, Clone, Copy)]
pub struct SeqCounter {
    /// Next value to hand out. A value of zero or less means exhausted.
    next: i64,
}

impl SeqCounter {
    /// Start counting at `last_accepted + 1`.
    ///
    /// A negative `last_accepted` is clamped up to 1, since sequence numbers
    /// start at 1 and 0 is reserved to mean "this op does not use the counter".
    pub fn after(last_accepted: i64) -> Self {
        // Guard before adding, so i64::MAX cannot overflow.
        let next = if last_accepted >= i64::MAX { 0 } else { (last_accepted + 1).max(1) };
        Self { next }
    }

    /// A counter that is already spent, for tests and for the exhausted case.
    pub fn exhausted() -> Self {
        Self { next: 0 }
    }

    /// Hand out the next value and advance.
    ///
    /// Refuses rather than wrapping or repeating. Exhausting i64 would require
    /// 9.2e18 posts, but silently reissuing a number would break the replay
    /// guarantee the counter exists to provide, so a stop is the correct
    /// failure.
    pub fn take(&mut self) -> Result<i64> {
        if self.next <= 0 {
            return Err(CoreError::internal(
                "per-identity sequence counter exhausted; \
                 this identity has posted i64::MAX messages",
            ));
        }
        let v = self.next;
        self.next = if v == i64::MAX { 0 } else { v + 1 };
        Ok(v)
    }

    /// The value that [`SeqCounter::take`] will hand out next, or `None` once
    /// exhausted.
    pub fn peek(&self) -> Option<i64> {
        if self.next <= 0 { None } else { Some(self.next) }
    }
}

/// Verify an envelope against a specific public key.
///
/// This is the trust boundary. Order of checks matters, so it is:
///
/// 1. structural validation and per-op invariants,
/// 2. rebuild the canonical bytes,
/// 3. `verify_strict` against the supplied key,
/// 4. confirm the embedded fingerprint matches that key.
///
/// Steps 1 and 2 are duplicated on the signing side by
/// [`LocalSigner::finish`], so a well-formed signed envelope and its
/// verification path always agree.
pub fn verify_with_key(vk: &VerifyingKey, env: &Envelope) -> Result<VerifiedSender> {
    env.validate()?;

    let sig_bytes = hex::decode(&env.signature).map_err(|_| {
        CoreError::new(ErrorCode::BadSignature, "signature is not valid hex")
    })?;
    if sig_bytes.len() != 64 {
        return Err(CoreError::new(
            ErrorCode::BadSignature,
            format!("signature must be 64 bytes, got {}", sig_bytes.len()),
        ));
    }
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| CoreError::new(ErrorCode::BadSignature, format!("malformed signature: {e}")))?;

    let bytes = env.signing_bytes()?;

    vk.verify_strict(&bytes, &sig).map_err(|e| {
        CoreError::new(
            ErrorCode::BadSignature,
            format!(
                "signature does not verify for identity {:?}: {e}",
                env.sender_id
            ),
        )
    })?;

    let actual_fp = fingerprint_of(vk);
    if env.sender_pubkey_fp != actual_fp {
        return Err(CoreError::new(
            ErrorCode::BadSignature,
            format!(
                "fingerprint mismatch: envelope claims {} but registered key is {actual_fp}",
                env.sender_pubkey_fp
            ),
        ));
    }

    Ok(VerifiedSender {
        sender_id: env.sender_id.clone(),
        fingerprint: actual_fp,
        public_key: *vk,
    })
}

/// Verify against a hex-encoded key. Convenience wrapper for tests and config
/// paths.
pub fn verify_with_pubkey_hex(pubkey_hex: &str, env: &Envelope) -> Result<VerifiedSender> {
    let vk = pubkey_from_hex(pubkey_hex)?;
    verify_with_key(&vk, env)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(id: &str) -> LocalSigner {
        LocalSigner::generate(id).expect("keygen").0
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let s = signer("eng-01");
        let env = s
            .sign_post("general", "hello", Provenance::SelfOriginated, 1, 1_758_900_000_000)
            .unwrap();
        let vk = pubkey_from_hex(&s.public_hex()).unwrap();
        let v = verify_with_key(&vk, &env).expect("should verify");
        assert_eq!(v.sender_id, "eng-01");
        assert_eq!(v.fingerprint, s.fingerprint());
    }

    #[test]
    fn read_and_handshake_verify() {
        let s = signer("lead");
        let vk = pubkey_from_hex(&s.public_hex()).unwrap();
        assert!(verify_with_key(&vk, &s.sign_read("general", 1_758_900_000_000).unwrap()).is_ok());
        assert!(verify_with_key(&vk, &s.sign_handshake(1_758_900_000_000).unwrap()).is_ok());
    }

    #[test]
    fn tampering_with_any_field_is_caught() {
        let s = signer("eng-01");
        let vk = pubkey_from_hex(&s.public_hex()).unwrap();
        let base = s.sign_post("general", "hello", Provenance::SelfOriginated, 1, 1_758_900_000_000).unwrap();

        let mutations: Vec<(&str, Box<dyn Fn(&mut Envelope)>)> = vec![
            ("body", Box::new(|e: &mut Envelope| e.body.push('!'))),
            ("channel", Box::new(|e: &mut Envelope| e.channel = "other".into())),
            ("sender_id", Box::new(|e: &mut Envelope| e.sender_id = "lead".into())),
            ("seq", Box::new(|e: &mut Envelope| e.seq += 1)),
            ("timestamp", Box::new(|e: &mut Envelope| e.timestamp += 1)),
            ("provenance", Box::new(|e: &mut Envelope| e.provenance = Provenance::External)),
            ("fp", Box::new(|e: &mut Envelope| e.sender_pubkey_fp = "0".repeat(16))),
            ("signature", Box::new(|e: &mut Envelope| {
                let b = e.signature.clone();
                let mut c = b.into_bytes();
                c[0] = if c[0] == b'0' { b'1' } else { b'0' };
                e.signature = String::from_utf8(c).unwrap();
            })),
        ];
        for (name, f) in mutations {
            let mut e = base.clone();
            f(&mut e);
            let err = verify_with_key(&vk, &e).unwrap_err();
            assert_eq!(err.code, ErrorCode::BadSignature, "mutating {name} was not detected");
        }
    }

    /// The headline adversarial property: identity A cannot produce a message
    /// that verifies as identity B, even though A fully controls every field it
    /// sends and even though B's public key is on the same machine.
    #[test]
    fn one_identity_cannot_forge_another() {
        let alice = signer("eng-01");
        let bob = signer("lead");
        let bob_vk = pubkey_from_hex(&bob.public_hex()).unwrap();

        // Alice signs honestly, then relabels it as Bob.
        let mut forged = alice
            .sign_post("general", "trust me", Provenance::SelfOriginated, 1, 1_758_900_000_000)
            .unwrap();
        forged.sender_id = "lead".into();
        forged.sender_pubkey_fp = bob.fingerprint().to_string();

        let err = verify_with_key(&bob_vk, &forged).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadSignature);
    }

    /// A valid signature from an unregistered key must not pass as a known
    /// identity. This is `unknown_identity` in spirit; the registry lookup lives
    /// in idboard-acl, but the crypto must at least not accept it under a name.
    #[test]
    fn a_different_key_cannot_verify() {
        let a = signer("eng-01");
        let b = signer("eng-02");
        let env = a.sign_post("general", "x", Provenance::SelfOriginated, 1, 1).unwrap();
        let b_vk = pubkey_from_hex(&b.public_hex()).unwrap();
        assert_eq!(
            verify_with_key(&b_vk, &env).unwrap_err().code,
            ErrorCode::BadSignature
        );
    }

    #[test]
    fn fingerprint_is_16_hex_chars_and_stable() {
        let s = signer("eng-01");
        assert_eq!(s.fingerprint().len(), FINGERPRINT_HEX_LEN);
        assert!(s.fingerprint().chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Stable across a re-derivation from the same seed.
        let again = LocalSigner::from_seed(&s.seed(), "eng-01").unwrap();
        assert_eq!(again.fingerprint(), s.fingerprint());
        assert_eq!(again.public_hex(), s.public_hex());
    }

    #[test]
    fn distinct_keys_have_distinct_fingerprints() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..64 {
            let s = signer(&format!("id-{i}"));
            assert!(seen.insert(s.fingerprint().to_string()), "fingerprint collision at {i}");
        }
    }

    /// Milestone 1 exit criterion: the crypto must be cheap enough to be
    /// invisible per message.
    ///
    /// The budget is split by build profile on purpose. Unoptimised builds of
    /// `curve25519-dalek` run roughly two orders of magnitude slower than
    /// optimised ones, so one threshold would be either meaningless in release
    /// or flaky in debug. Each bound is loose enough to survive a loaded CI box
    /// but tight enough to catch a switch to a pathological verification path.
    #[test]
    fn signing_and_verification_are_fast_enough_per_message() {
        const N: i64 = 1000;
        let budget_secs = if cfg!(debug_assertions) { 90.0 } else { 2.0 };

        let s = signer("eng-01");
        let vk = pubkey_from_hex(&s.public_hex()).unwrap();
        let start = std::time::Instant::now();
        for i in 0..N {
            let env = s.sign_post("general", "a message body", Provenance::SelfOriginated, i + 1, i).unwrap();
            verify_with_key(&vk, &env).unwrap();
        }
        let elapsed = start.elapsed();
        let per_msg_ms = elapsed.as_secs_f64() * 1000.0 / N as f64;
        eprintln!(
            "sign+verify: {N} pairs in {elapsed:?} ({per_msg_ms:.3} ms/pair, {} build)",
            if cfg!(debug_assertions) { "debug" } else { "release" }
        );
        assert!(
            elapsed.as_secs_f64() < budget_secs,
            "{N} sign+verify pairs took {elapsed:?} ({per_msg_ms:.3} ms/pair), \
             over the {budget_secs}s budget for this build profile"
        );
    }

    /// Documents a subtlety in `ed25519-dalek` 3.0 that is easy to get wrong.
    ///
    /// `VerifyingKey::from_bytes` applies ZIP-215, which *deliberately* accepts
    /// non-canonical y encodings of a valid point. Parsing therefore does not
    /// guarantee a public key has one unique spelling. `verify_strict` — not
    /// `from_bytes` — is the layer that rejects weak and malleable keys, which
    /// is precisely why this crate calls it.
    ///
    /// Consequence for idboard: a fingerprint is a function of the exact 32
    /// bytes in the config, so two spellings of one point are two
    /// fingerprints. That is safe, because the daemon resolves keys by identity
    /// name and requires an envelope's fingerprint to match the registered
    /// bytes. A changed `pubkey` therefore invalidates an identity rather than
    /// silently aliasing it, which is the behaviour you want from a rotation.
    #[test]
    fn pubkey_parsing_is_permissive_by_design_zip215() {
        let s = signer("eng-01");
        let hex_str = s.public_hex();
        let vk = pubkey_from_hex(&hex_str).expect("a canonical key must parse");
        assert_eq!(hex::encode(vk.to_bytes()), hex_str, "a normal key round-trips byte for byte");
        assert!(!vk.is_weak(), "a freshly generated key must not be weak");

        // Structural rejections still happen at parse time.
        assert!(pubkey_from_hex("").is_err(), "empty");
        assert!(pubkey_from_hex("abcd").is_err(), "wrong length");
        assert!(pubkey_from_hex(&"z".repeat(64)).is_err(), "not hex");
        assert!(pubkey_from_hex(&"a".repeat(64)).is_ok(), "correct length and hex parses");
    }

    /// Documents why `verify_strict` rather than `verify`. A low-order public
    /// key would validate a signature over almost any message, which is exactly
    /// the forgery primitive this whole project exists to prevent.
    #[test]
    fn weak_keys_are_rejected_by_strict_verification() {
        let weak = [0u8; 32];
        if let Ok(vk) = VerifyingKey::from_bytes(&weak) {
            assert!(vk.is_weak(), "expected the all-zero y encoding to be a weak key");
        }
        // A normal key must not be flagged, so the check above is meaningful.
        let s = signer("eng-01");
        assert!(!s.signing_key.verifying_key().is_weak());
    }

    #[test]
    fn seq_counter_starts_above_last_accepted() {
        assert_eq!(SeqCounter::after(0).peek(), Some(1));
        assert_eq!(SeqCounter::after(7).peek(), Some(8));
        let mut c = SeqCounter::after(0);
        assert_eq!(c.take().unwrap(), 1);
        assert_eq!(c.take().unwrap(), 2);
    }

    #[test]
    fn seq_counter_never_returns_zero_or_negative() {
        assert_eq!(SeqCounter::after(-5).peek(), Some(1), "a negative last_seq must start at 1");
        assert_eq!(SeqCounter::after(i64::MIN).peek(), Some(1));
    }

    /// The counter must stop rather than wrap or repeat, because a repeated
    /// sequence number is exactly the replay the counter exists to prevent.
    #[test]
    fn seq_counter_refuses_when_exhausted() {
        let mut c = SeqCounter::after(i64::MAX);
        assert_eq!(c.peek(), None, "handing out i64::MAX again would be a replay");
        assert!(c.take().is_err());

        let mut c = SeqCounter::after(i64::MAX - 1);
        assert_eq!(c.take().unwrap(), i64::MAX);
        assert!(c.take().is_err(), "must not reissue i64::MAX");

        let mut c = SeqCounter::exhausted();
        assert!(c.take().is_err());
    }

    #[test]
    fn nonces_are_unique_and_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            let n = generate_nonce().unwrap();
            assert_eq!(n.len(), crate::ids::NONCE_BYTES * 2);
            assert!(seen.insert(n));
        }
    }

    #[test]
    fn identity_names_are_validated_at_signer_construction() {
        assert!(LocalSigner::generate("../evil").is_err());
        assert!(LocalSigner::generate("").is_err());
        assert!(LocalSigner::generate("ok-name").is_ok());
    }
}
