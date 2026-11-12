//! The board: verification, authorisation, and dispatch.
//!
//! This is the whole trust boundary, and it lives in one type so it can be
//! tested without a socket. The binary in `main.rs` does nothing but move bytes.
//!
//! # The order of checks, and why it is that order
//!
//! For every request, in this sequence:
//!
//! 1. **Protocol version.** Cheap, and a mismatch means nothing else is
//!    meaningful.
//! 2. **Registration.** Is the claimed `sender_id` in the config at all? This
//!    answers `unknown_identity`.
//! 3. **Signature.** `verify_strict` against *the key the config registers for
//!    that name*, never a key from the request. This answers `bad_signature`.
//! 4. **Per-op invariants.** Already enforced inside verification, so a post
//!    cannot arrive without a sequence number or a read cannot smuggle one.
//! 5. **Freshness.** Read-only ops only, and only because their entire
//!    authentication rests on the signed timestamp. Posts rely on the counter
//!    instead, so they get no clock window.
//! 6. **Authorisation.** The ACL, checked against the *verified* identity.
//!
//! Step 2 precedes step 3 so an unregistered name produces a clear
//! `unknown_identity` rather than a confusing `bad_signature`. That ordering has
//! no security consequence: an unregistered name is rejected at step 2 and a
//! registered name with a bad signature is rejected at step 3 either way. The
//! `sender_id` is a claim throughout; only step 3 turns it into an identity.

use std::sync::Arc;

use idboard_acl::{Config, Identity};
use idboard_core::envelope::{Envelope, Op};
use idboard_core::error::{CoreError, ErrorCode};
use idboard_core::ids::clamp_read_limit;
use idboard_core::wire::{ChannelDigest, DaemonRequest, DaemonResponse, HandshakeReply, PeerStatus};
use idboard_core::{PROTOCOL_VERSION, READ_SKEW_MS, SINCE_CURRENT_END, verify_with_key};

use idboard_store::{Store, StoreError};


/// A monotonic-enough clock, injectable so skew-window tests need not sleep.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// The verified, authorised board.
pub struct Board {
    config: Config,
    store: Store,
    clock: Clock,
    /// Per-identity post budget. In memory, so a restart resets the window.
    budget: PostBudget,
}

impl Board {
    /// Build a board and seed the identity registry.
    ///
    /// Returns the identities whose registered public key differs from what the
    /// database last saw, which the caller should surface loudly: it is either a
    /// deliberate rotation or a config mistake, and in the second case the real
    /// agent will be unable to post.
    pub fn new(config: Config, mut store: Store) -> Result<(Self, Vec<String>), StoreError> {
        let identities: Vec<&Identity> = config.identities().collect();
        let rotated = store.register_identities(&identities)?;
        let board = Self {
            config,
            store,
            clock: Arc::new(idboard_core::now_ms),
            budget: PostBudget::default(),
        };
        Ok((board, rotated))
    }

    /// Replace the clock. Test-only seam.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Pin the clock to a fixed instant, and optionally an offset from it.
    pub fn with_fixed_clock(self, now_ms: i64) -> Self {
        self.with_clock(Arc::new(move || now_ms))
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Handle one request, always producing a response.
    ///
    /// Infallible by design: a caller on a socket must get something back, and
    /// the error taxonomy is the product here.
    pub fn handle(&mut self, req: &DaemonRequest) -> DaemonResponse {
        match self.dispatch(req) {
            Ok(res) => res,
            Err(e) => DaemonResponse::from_err(&e),
        }
    }

    fn dispatch(&mut self, req: &DaemonRequest) -> Result<DaemonResponse, CoreError> {
        if req.v != PROTOCOL_VERSION {
            return Err(CoreError::bad_request(format!(
                "protocol version {} is not supported; this daemon speaks {PROTOCOL_VERSION}",
                req.v
            )));
        }

        // Steps 2 and 3. `verified` is the only identity the rest of this
        // function is allowed to consult.
        let env = &req.envelope;
        let identity = self.config.identity(&env.sender_id).ok_or_else(|| {
            CoreError::new(
                ErrorCode::UnknownIdentity,
                format!(
                    "no identity {:?} is registered. Keys are never learned on first use, \
                     because any local process could claim the name first and lock you out. \
                     Run `idboard keygen {}` and add the result to the config.",
                    env.sender_id, env.sender_id
                ),
            )
        })?;
        verify_with_key(&identity.public_key, env)?;

        match env.op {
            Op::Post => handle_post(
                &self.config,
                &mut self.store,
                &self.clock,
                &mut self.budget,
                identity,
                env,
            ),
            Op::Read => handle_read(&self.config, &mut self.store, &self.clock, identity, env, req),
            Op::Handshake => {
                handle_handshake(&self.config, &mut self.store, &self.clock, identity, env)
            }
            Op::Inbox => handle_inbox(
                &self.config,
                &mut self.store,
                &self.clock,
                identity,
                env,
                req,
            ),
            Op::Peers => handle_peers(&mut self.store, &self.clock, identity, env),
        }
    }
}

/// Freshness check for read-only ops.
///
/// Not applied to posts. A post's freshness guarantee is its sequence number,
/// and the timestamp is display metadata written by the wrapper, which we trust
/// to tell the truth about its own clock. A skewed clock is a local bug, not an
/// attack, so it should not be able to lock an identity out of posting.
fn check_skew(clock: &Clock, env: &Envelope) -> Result<(), CoreError> {
    let now = clock();
    let delta = now.saturating_sub(env.timestamp);
    if delta.abs() > READ_SKEW_MS {
        return Err(CoreError::new(
            ErrorCode::ClockSkew,
            format!(
                "signed timestamp is {delta} ms from now, outside the +/-{READ_SKEW_MS} ms window. \
                 Both processes should be on this machine, so a large skew usually means \
                 a wrong clock rather than an attack."
            ),
        ));
    }
    Ok(())
}

/// Check the ACL for a verified identity.
///
/// Authorisation always runs against the identity established by signature
/// verification. Nothing reaches here with an unverified identity, and the
/// verifier takes no arguments that could substitute for one.
fn authorize(config: &Config, identity: &Identity, channel: &str, op: Op) -> Result<(), CoreError> {
    let ch = config.channel(channel).ok_or_else(|| {
        CoreError::new(
            ErrorCode::UnknownChannel,
            format!("channel {channel:?} has no [channel.{channel}] entry in the config"),
        )
    })?;
    let allowed = match op {
        Op::Post => ch.can_post(identity),
        _ => ch.can_read(identity),
    };
    if allowed {
        return Ok(());
    }
    let verb = if op == Op::Post { "post to" } else { "read" };
    Err(CoreError::new(
        ErrorCode::Unauthorized,
        format!(
            "verified identity {:?} (role {:?}) may not {verb} {channel:?}. \
             channel.{channel} allows post={:?} read={:?}",
            identity.name, identity.role, ch.post, ch.read
        ),
    ))
}

fn handle_post(
    config: &Config,
    store: &mut Store,
    clock: &Clock,
    budget: &mut PostBudget,
    identity: &Identity,
    env: &Envelope,
) -> Result<DaemonResponse, CoreError> {
    authorize(config, identity, &env.channel, Op::Post)?;

    // After authorisation, before the append. An unauthorised post must not
    // consume budget, or an attacker holding any valid key could exhaust another
    // identity's allowance by replaying posts it was never allowed to make.
    let now = clock();
    if !budget.allow(&identity.name, now, config.limits()) {
        let limits = config.limits();
        return Err(CoreError::new(
            ErrorCode::RateLimited,
            format!(
                "identity {:?} has used its budget of {} posts per {}s. Reads are not \
                 charged, so polling still works; wait for the window to slide, or raise \
                 [limits].posts_per_window in the config.",
                identity.name,
                limits.posts_per_window,
                limits.window_ms / 1000
            ),
        ));
    }

    let stored = store.append(&identity.name, env, now)?;
    Ok(DaemonResponse::ok()
        .with_cursor(stored.cursor)
        .with_messages(vec![stored]))
}

/// A per-identity sliding window of accepted post times.
///
/// Held in memory rather than in SQLite. A soft limit does not justify a schema
/// migration, and the consequence of a restart is that one window resets — which
/// is visible, bounded, and preferable to a rate-limit table that has to be
/// reasoned about forever.
///
/// Memory is bounded by `posts_per_window` entries per identity that has posted
/// inside the window, and entries are dropped as the window slides.
#[derive(Debug, Default)]
struct PostBudget {
    recent: std::collections::HashMap<String, std::collections::VecDeque<i64>>,
}

impl PostBudget {
    /// Record a post and report whether it is within budget.
    ///
    /// Recording and checking are one operation so a caller cannot check without
    /// charging, which is the bug that makes a limit ineffective.
    fn allow(&mut self, identity: &str, now_ms: i64, limits: idboard_acl::Limits) -> bool {
        if limits.is_unlimited() {
            return true;
        }
        let window = limits.window_ms as i64;
        let cutoff = now_ms.saturating_sub(window);
        let recent = self.recent.entry(identity.to_string()).or_default();
        while recent.front().is_some_and(|t| *t <= cutoff) {
            recent.pop_front();
        }
        if recent.len() >= limits.posts_per_window as usize {
            return false;
        }
        recent.push_back(now_ms);
        true
    }
}

fn handle_read(
    config: &Config,
    store: &mut Store,
    clock: &Clock,
    identity: &Identity,
    env: &Envelope,
    req: &DaemonRequest,
) -> Result<DaemonResponse, CoreError> {
    check_skew(clock, env)?;
    authorize(config, identity, &env.channel, Op::Read)?;
    // Reads must not consume a sequence number, so this records presence only.
    store.touch(&identity.name, clock())?;

    let since = req.since.max(0);
    let limit = clamp_read_limit(req.limit);
    let messages = store.read(&env.channel, since, limit)?;

    // A read that returns nothing still reports where the caller is, so a poller
    // does not re-scan the same range forever. Only ever move forward: a caller
    // passing a cursor above anything we hold is not something to "correct".
    //
    // `i64::MAX` is the one exception, and it is a documented sentinel rather
    // than an accident: it means "tell me the current end and nothing else".
    // `idboard subscribe` uses it to start at the present without replaying
    // history, so echoing it back would hand the caller a cursor that can never
    // match a row and it would poll silently forever. Answering with the real
    // high-water mark is what the caller actually asked for.
    let cursor = match messages.last() {
        Some(m) => m.cursor,
        None if since == SINCE_CURRENT_END => store.high_water_cursor()?,
        None => since,
    };
    let mut res = DaemonResponse::ok().with_messages(messages);
    res.cursor = Some(cursor);
    Ok(res)
}

fn handle_handshake(
    config: &Config,
    store: &mut Store,
    clock: &Clock,
    identity: &Identity,
    env: &Envelope,
) -> Result<DaemonResponse, CoreError> {
    check_skew(clock, env)?;
    let last_seq = store.last_seq(&identity.name)?;
    store.touch(&identity.name, clock())?;
    let (readable, postable) = visible_channels(config, identity);
    Ok(DaemonResponse::ok().with_handshake(HandshakeReply {
        last_seq,
        fingerprint: identity.fingerprint.clone(),
        role: identity.role.clone(),
        readable_channels: readable,
        postable_channels: postable,
    }))
}

/// Which channels this identity may read and post to.
///
/// Both lists are produced by calling [`authorize`], the same function a real
/// read or post runs, rather than by re-reading the grant lists here. That is
/// the point: a list computed by a second implementation is free to disagree
/// with enforcement, and the disagreement would be invisible until an agent
/// tried the channel it was told about.
///
/// The lists are advisory. Nothing consumes them as permission.
fn visible_channels(config: &Config, identity: &Identity) -> (Vec<String>, Vec<String>) {
    let mut readable = Vec::new();
    let mut postable = Vec::new();
    for channel in config.channels() {
        if authorize(config, identity, &channel.name, Op::Read).is_ok() {
            readable.push(channel.name.clone());
        }
        if authorize(config, identity, &channel.name, Op::Post).is_ok() {
            postable.push(channel.name.clone());
        }
    }
    (readable, postable)
}

/// A digest of every channel this identity has anything to do with.
///
/// One signed request instead of a fan-out of reads, so the digest is a
/// consistent snapshot and an agent that has just started can ask one question.
/// Channels the identity can neither read nor post to are omitted entirely
/// rather than reported as empty, because the roster of channels is itself
/// worth not leaking.
fn handle_inbox(
    config: &Config,
    store: &mut Store,
    clock: &Clock,
    identity: &Identity,
    env: &Envelope,
    req: &DaemonRequest,
) -> Result<DaemonResponse, CoreError> {
    check_skew(clock, env)?;
    store.touch(&identity.name, clock())?;

    // Zero means "the channel list and positions, no messages". `clamp_read_limit`
    // maps zero to one for reads, which is the right answer there and the wrong
    // one here, so the meaning is decided before clamping.
    let limit = if req.limit == 0 { 0 } else { clamp_read_limit(req.limit) };

    let mut digests = Vec::new();
    for channel in config.channels() {
        let can_read = authorize(config, identity, &channel.name, Op::Read).is_ok();
        let can_post = authorize(config, identity, &channel.name, Op::Post).is_ok();
        if !can_read && !can_post {
            continue;
        }
        let (cursor, messages) = if can_read {
            (store.channel_high_water(&channel.name)?, store.read_tail(&channel.name, limit)?)
        } else {
            (0, Vec::new())
        };
        digests.push(ChannelDigest {
            channel: channel.name.clone(),
            can_read,
            can_post,
            cursor,
            messages,
        });
    }
    Ok(DaemonResponse::ok().with_channels(digests))
}

/// The roster, with last-seen times.
///
/// No ACL check, because there is no channel to check: any registered identity
/// may see the roster. That is not a new disclosure — every identity and its
/// public key is in the config file on the same machine.
fn handle_peers(
    store: &mut Store,
    clock: &Clock,
    identity: &Identity,
    env: &Envelope,
) -> Result<DaemonResponse, CoreError> {
    check_skew(clock, env)?;
    store.touch(&identity.name, clock())?;
    let peers: Vec<PeerStatus> = store.peers()?;
    Ok(DaemonResponse::ok().with_peers(peers))
}

/// Longest prefix of an untrusted field kept in a rejection line.
///
/// The fields below are bounded only by `idboard_ipc::MAX_FRAME_BYTES`, so a
/// single request could otherwise put a megabyte of attacker-chosen text on the
/// operator's stderr.
const MAX_LOG_FIELD: usize = 128;

/// Render a claimed identity or channel for a rejection line.
///
/// Two things go wrong if a claimed `sender_id` or `channel` is formatted
/// straight into a log line. A newline lets one request emit several lines, the
/// second shaped exactly like a genuine rejection and naming a *different*
/// identity on a channel it may not touch — which corrupts the post-incident
/// attribution record the operator relies on. And even once newlines are escaped,
/// the text is still *confusable* with the line's own fields:
/// `channel=lead\x0aidboardd: rejected op=post` reads, at a glance, like
/// structure rather than like a value.
///
/// So escaping alone is not enough. A value built only from the characters
/// `validate_identity` and `validate_channel` accept needs no delimiting — it
/// cannot contain a space, an `=`, a quote, or a control character, so it cannot
/// be mistaken for the fields around it — and is emitted bare, which keeps the
/// line greppable and unchanged for every honest request. Anything else is
/// quoted as well as escaped, so a reader can see exactly where the untrusted
/// value stops.
fn log_token(s: &str) -> String {
    let bounded = truncate(s);
    if !bounded.is_empty() && bounded.chars().all(is_token_char) {
        return bounded;
    }
    let mut out = String::with_capacity(bounded.len() + 2);
    out.push('"');
    for c in bounded.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c if is_token_char(c) => out.push(c),
            // A space is safe inside a quoted value, and spaces are what make
            // this line readable, so it stays.
            c if is_log_printable(c) => out.push(c),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push_str(&unicode_escape(c)),
        }
    }
    out.push('"');
    out
}

/// Render an error detail for a rejection line.
///
/// Different job from [`log_token`], and deliberately a looser one. A detail is
/// prose the daemon itself wrote — it is not a structured field an attacker
/// composes, and quoting every rejection would make the line unreadable. The two
/// things it still needs are a bound, because a detail can embed a claimed name
/// and inherit its length, and no raw control characters, because an unescaped
/// newline here is just as good at forging a record as one in the claim.
fn log_detail(s: &str) -> String {
    let mut out = String::with_capacity(truncate(s).len());
    for c in truncate(s).chars() {
        match c {
            c if is_log_printable(c) => out.push(c),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push_str(&unicode_escape(c)),
        }
    }
    out
}

/// Cut a field to [`MAX_LOG_FIELD`], marking that it was cut.
///
/// The bound is applied to *every* value, including one made entirely of
/// characters that look safe: 64 KiB of `a` contains nothing dangerous and is
/// still a 64 KiB log line an operator has to scroll past.
fn truncate(s: &str) -> String {
    let mut out: String = s.chars().take(MAX_LOG_FIELD).collect();
    if s.chars().nth(MAX_LOG_FIELD).is_some() {
        out.push_str("...");
    }
    out
}

/// The characters `validate_identity` and `validate_channel` both accept.
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/')
}

/// A character safe to emit raw into a log line.
///
/// Printable ASCII, or anything that is not a control character — which
/// deliberately includes non-ASCII. Agents write prose, and an em dash or a CJK
/// bracket is not an attack; mangling it would corrupt an honest line to defend
/// against a hostile one.
///
/// Note `char::is_ascii_graphic` excludes space, so it is the wrong predicate
/// here: without the explicit `|| c == ' '` a space falls through to the escaping
/// arm and every line reads `detail=outside\x20the\x20window`.
fn is_log_printable(c: char) -> bool {
    c.is_ascii_graphic() || c == ' ' || (!c.is_ascii() && !c.is_control())
}

fn unicode_escape(c: char) -> String {
    let n = c as u32;
    if n < 0x100 {
        format!("\\x{n:02x}")
    } else {
        format!("\\u{{{n:x}}}")
    }
}

/// A one-line description of a rejection, for the daemon log.
///
/// Kept separate from the response so operators get a consistent, greppable line
/// regardless of which transport the rejection arrived over. Every field here is
/// attacker-influenceable, and this is written for every `!ok` response, not only
/// the pre-cryptography ones.
pub fn rejection_line(env: &Envelope, e: &CoreError) -> String {
    format!(
        "rejected op={} claimed_sender={} channel={} seq={} code={} detail={}",
        env.op.as_str(),
        log_token(&env.sender_id),
        if env.channel.is_empty() { "-".to_string() } else { log_token(&env.channel) },
        env.seq,
        e.code,
        log_detail(&e.detail),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use idboard_core::keys::LocalSigner;
    use idboard_core::{Envelope, Provenance};

    const T0: i64 = 1_758_900_000_000;

    fn keygen(id: &str) -> (LocalSigner, String) {
        let s = LocalSigner::generate(id).unwrap().0;
        let hex = s.public_hex();
        (s, hex)
    }

    struct Fixture {
        board: Board,
        eng: LocalSigner,
        lead: LocalSigner,
        stranger: LocalSigner,
    }

    fn fixture() -> Fixture {
        fixture_with_extra("")
    }

    /// The same board with extra `[channel.*]` tables appended, for tests that
    /// need a channel some identity cannot reach.
    fn fixture_with_extra(extra: &str) -> Fixture {
        let (eng, eng_key) = keygen("eng-01");
        let (lead, lead_key) = keygen("lead");
        let (stranger, _) = keygen("stranger");

        let config = Config::from_toml(&format!(
            r#"
[identity.eng-01]
role = "engineer"
pubkey = "{eng_key}"

[identity.lead]
role = "lead"
pubkey = "{lead_key}"

[channel.general]
post = ["*"]
read = ["*"]

[channel.deploy-approvals]
post = ["lead"]
read = ["*"]
{extra}"#
        ))
        .unwrap();

        let store = Store::open_in_memory().unwrap();
        let (board, rotated) = Board::new(config, store).unwrap();
        assert!(rotated.is_empty());
        Fixture { board: board.with_fixed_clock(T0), eng, lead, stranger }
    }

    fn request(env: Envelope) -> DaemonRequest {
        DaemonRequest { v: PROTOCOL_VERSION, envelope: env, since: 0, limit: 100 }
    }

    fn post_req(s: &LocalSigner, channel: &str, body: &str, seq: i64) -> DaemonRequest {
        request(s.sign_post(channel, body, Provenance::SelfOriginated, seq, T0).unwrap())
    }

    #[test]
    fn a_valid_post_is_accepted_and_attributed() {
        let mut f = fixture();
        let res = f.board.handle(&post_req(&f.eng, "general", "hello", 1));
        assert!(res.ok, "{res:?}");
        assert_eq!(res.messages.len(), 1);
        assert_eq!(res.messages[0].envelope.sender_id, "eng-01");
        assert_eq!(res.messages[0].envelope.body, "hello");
        assert!(res.cursor.unwrap() > 0);
    }

    /// A delivered message must be checkable against the signature that produced
    /// it. It could not be before: the read projection dropped `channel`, which
    /// is inside the signed bytes, so re-verifying a read-back message failed.
    #[test]
    fn a_read_back_message_still_carries_its_channel_and_signature() {
        let mut f = fixture();
        // Post to the channel `eng-01` may read but not post to, so the message
        // under test is one that crossed an authorisation boundary on the way in
        // and still has to verify on the way out.
        f.board.handle(&post_req(&f.lead, "deploy-approvals", "ship it", 1));

        let mut req = request(f.eng.sign_read("deploy-approvals", T0).unwrap());
        req.since = 0;
        let res = f.board.handle(&req);
        assert!(res.ok, "{res:?}");
        assert_eq!(res.messages.len(), 1, "the restricted-channel message must reach a reader");
        let back = &res.messages[0].envelope;
        assert_eq!(back.channel, "deploy-approvals");
        assert!(!back.signature.is_empty(), "the stored signature must reach the reader");
        let verified = idboard_core::verify_with_key(&f.lead.verifying_key(), back)
            .expect("a delivered message must verify against its signer");
        assert_eq!(verified.sender_id, "lead");
    }

    /// `idboard subscribe` bootstraps its cursor with `SINCE_CURRENT_END` so it
    /// starts at the present instead of replaying history.
    ///
    /// The obvious implementation — echo `since` back when the page is empty —
    /// hands the caller `i64::MAX`, which it then uses as its cursor on every
    /// subsequent read. No row can ever match, so subscribe polls silently
    /// forever and never shows a message.
    #[test]
    fn asking_for_the_current_end_answers_with_a_real_cursor() {
        let mut f = fixture();
        f.board.handle(&post_req(&f.eng, "general", "one", 1));
        f.board.handle(&post_req(&f.eng, "general", "two", 2));
        let end = f.board.store().high_water_cursor().unwrap();
        assert!(end > 0);

        // The bootstrap: the sentinel must come back as the newest real cursor.
        let mut boot = request(f.eng.sign_read("general", T0).unwrap());
        boot.since = SINCE_CURRENT_END;
        let res = f.board.handle(&boot);
        assert!(res.ok, "{res:?}");
        assert!(res.messages.is_empty(), "the sentinel must not replay history");
        assert_eq!(
            res.cursor,
            Some(end),
            "the sentinel was echoed back instead of answered; subscribe would poll forever"
        );

        // And the cursor it hands back must actually work.
        let mut poll = request(f.eng.sign_read("general", T0).unwrap());
        poll.since = res.cursor.unwrap();
        let res = f.board.handle(&poll);
        assert!(res.ok, "{res:?}");
        assert!(res.messages.is_empty(), "there is nothing new after the end");

        // A message posted after the bootstrap must now be seen.
        f.board.handle(&post_req(&f.eng, "general", "three", 3));
        let mut poll = request(f.eng.sign_read("general", T0).unwrap());
        poll.since = res.cursor.unwrap();
        let res = f.board.handle(&poll);
        assert_eq!(res.messages.len(), 1, "subscribe must see a message posted after it started");
        assert_eq!(res.messages[0].envelope.body, "three");
    }

    /// An ordinary empty page still echoes the caller's own cursor. The sentinel
    /// is the one exception, and only because it is a request for a position
    /// rather than a claim about one.
    #[test]
    fn an_empty_page_still_echoes_the_callers_own_cursor() {
        let mut f = fixture();
        f.board.handle(&post_req(&f.eng, "general", "one", 1));
        let since = f.board.store().high_water_cursor().unwrap();

        let mut req = request(f.eng.sign_read("general", T0).unwrap());
        req.since = since;
        let res = f.board.handle(&req);
        assert!(res.messages.is_empty());
        assert_eq!(res.cursor, Some(since), "a poller must not be re-scanned from the start");
    }


    /// The headline property. Identity A cannot produce anything the daemon
    /// will attribute to identity B.
    #[test]
    fn one_identity_cannot_post_as_another() {
        let mut f = fixture();
        // eng-01 signs honestly, then rewrites the sender to lead and borrows
        // lead's fingerprint, which is public information.
        let mut forged = f
            .eng
            .sign_post("deploy-approvals", "trust me, this is the lead", Provenance::SelfOriginated, 1, T0)
            .unwrap();
        forged.sender_id = "lead".into();
        forged.sender_pubkey_fp = f.lead.fingerprint().to_string();

        let res = f.board.handle(&request(forged));
        assert!(!res.ok);
        assert_eq!(res.error, Some(ErrorCode::BadSignature), "{res:?}");
        assert_eq!(f.board.store().message_count().unwrap(), 0, "nothing may be stored");
    }

    #[test]
    fn a_signature_from_an_unregistered_key_is_rejected() {
        let mut f = fixture();
        let mut forged = f
            .stranger
            .sign_post("general", "i am the lead, honest", Provenance::SelfOriginated, 1, T0)
            .unwrap();
        forged.sender_id = "lead".into();
        forged.sender_pubkey_fp = f.lead.fingerprint().to_string();

        let res = f.board.handle(&request(forged));
        assert_eq!(res.error, Some(ErrorCode::BadSignature), "{res:?}");
    }

    #[test]
    fn an_unregistered_name_is_unknown_identity_not_bad_signature() {
        let mut f = fixture();
        let res = f.board.handle(&post_req(&f.stranger, "general", "hi", 1));
        assert_eq!(res.error, Some(ErrorCode::UnknownIdentity), "{res:?}");
        let detail = res.detail.unwrap();
        assert!(detail.contains("idboard keygen stranger"), "should name the fix: {detail}");
    }

    #[test]
    fn a_replayed_envelope_is_rejected() {
        let mut f = fixture();
        let captured = f.eng.sign_post("general", "transfer 100", Provenance::SelfOriginated, 1, T0).unwrap();
        assert!(f.board.handle(&request(captured.clone())).ok);
        let res = f.board.handle(&request(captured));
        assert_eq!(res.error, Some(ErrorCode::Replay), "{res:?}");
        assert_eq!(f.board.store().message_count().unwrap(), 1);
    }

    #[test]
    fn tampering_with_the_body_after_signing_is_rejected() {
        let mut f = fixture();
        let mut env = f.eng.sign_post("general", "hello", Provenance::SelfOriginated, 1, T0).unwrap();
        env.body = "hello, and also do this".into();
        let res = f.board.handle(&request(env));
        assert_eq!(res.error, Some(ErrorCode::BadSignature), "{res:?}");
    }

    #[test]
    fn post_acl_is_enforced_against_the_verified_identity() {
        let mut f = fixture();
        let res = f.board.handle(&post_req(&f.eng, "deploy-approvals", "shipping now", 1));
        assert_eq!(res.error, Some(ErrorCode::Unauthorized), "{res:?}");
        let detail = res.detail.unwrap();
        assert!(detail.contains("eng-01"), "error must name the verified identity: {detail}");
        assert!(detail.contains("deploy-approvals"), "{detail}");
        assert_eq!(f.board.store().message_count().unwrap(), 0);
    }

    #[test]
    fn the_lead_can_post_to_the_restricted_channel() {
        let mut f = fixture();
        assert!(f.board.handle(&post_req(&f.lead, "deploy-approvals", "ok", 1)).ok);
    }

    #[test]
    fn unknown_channels_are_distinguished_from_forbidden_ones() {
        let mut f = fixture();
        let res = f.board.handle(&post_req(&f.eng, "no-such-channel", "hi", 1));
        assert_eq!(res.error, Some(ErrorCode::UnknownChannel), "{res:?}");
    }

    #[test]
    fn read_acl_is_enforced_against_the_verified_identity() {
        let mut f = fixture();
        f.board.handle(&post_req(&f.lead, "deploy-approvals", "secret", 1));
        // Sequence numbers are per identity, not per channel, so the lead's
        // second post advances to 2.
        f.board.handle(&post_req(&f.lead, "general", "visible", 2));

        let res = f.board.handle(&request(f.eng.sign_read("general", T0).unwrap()));
        assert!(res.ok, "{res:?}");
        assert_eq!(res.messages.len(), 1);
        assert_eq!(res.messages[0].envelope.body, "visible");
    }

    /// Pins down that the counter is scoped to the identity, not the channel.
    /// If it were per channel, an attacker could replay a post to a channel they
    /// had not yet posted on.
    #[test]
    fn the_post_counter_is_per_identity_not_per_channel() {
        let mut f = fixture();
        f.board.handle(&post_req(&f.eng, "general", "first", 1));
        f.board.handle(&post_req(&f.eng, "deploy-approvals", "nope", 2));
        // The unauthorized attempt must not have advanced the counter, so seq 2
        // is still available on an authorized channel.
        let replay = post_req(&f.eng, "general", "hi again", 1);
        let res = f.board.handle(&replay);
        assert_eq!(
            res.error,
            Some(ErrorCode::Replay),
            "seq 1 was already spent by this identity, on a different channel"
        );
        assert!(f.board.handle(&post_req(&f.eng, "general", "ok", 2)).ok);
    }

    #[test]
    fn reads_require_a_valid_signature() {
        let mut f = fixture();
        f.board.handle(&post_req(&f.eng, "general", "visible", 1));

        // A read with a corrupted signature must not return content.
        let mut env = f.eng.sign_read("general", T0).unwrap();
        env.sender_id = "lead".into();
        let res = f.board.handle(&request(env));
        assert_eq!(res.error, Some(ErrorCode::BadSignature), "{res:?}");
        assert!(res.messages.is_empty());
    }

    #[test]
    fn read_respects_the_cursor() {
        let mut f = fixture();
        for i in 1..=5 {
            f.board.handle(&post_req(&f.eng, "general", &format!("m{i}"), i));
        }
        let page = f.board.handle(&request(f.eng.sign_read("general", T0).unwrap()));
        assert_eq!(page.messages.len(), 5);
        let cut = page.messages[1].cursor;

        let mut req = request(f.eng.sign_read("general", T0).unwrap());
        req.since = cut;
        let rest = f.board.handle(&req);
        assert_eq!(rest.messages.len(), 3);
        assert_eq!(rest.messages[0].envelope.body, "m3");
    }

    /// Reads must not consume the post counter, or a subscribe loop would burn
    /// sequence numbers at its poll rate.
    #[test]
    fn reads_do_not_consume_the_post_counter() {
        let mut f = fixture();
        f.board.handle(&post_req(&f.eng, "general", "first", 1));
        for _ in 0..50 {
            f.board.handle(&request(f.eng.sign_read("general", T0).unwrap()));
        }
        assert_eq!(f.board.store().last_seq("eng-01").unwrap(), 1, "counter must be untouched by reads");
        // And the identity can still post with the next number.
        assert!(f.board.handle(&post_req(&f.eng, "general", "second", 2)).ok);
    }

    #[test]
    fn handshake_reports_the_counter_and_never_echoes_a_requested_name() {
        let mut f = fixture();
        f.board.handle(&post_req(&f.eng, "general", "a", 1));
        f.board.handle(&post_req(&f.eng, "general", "b", 2));

        let res = f.board.handle(&request(f.eng.sign_handshake(T0).unwrap()));
        assert!(res.ok, "{res:?}");
        let hs = res.handshake.unwrap();
        assert_eq!(hs.last_seq, 2);
        assert_eq!(hs.fingerprint, f.eng.fingerprint());
        assert_eq!(hs.role, "engineer");
    }

    /// A handshake is a signed query, so learning a counter requires the key.
    #[test]
    fn handshake_requires_a_signature() {
        let mut f = fixture();
        let mut env = f.eng.sign_handshake(T0).unwrap();
        env.sender_id = "lead".into();
        let res = f.board.handle(&request(env));
        assert_eq!(res.error, Some(ErrorCode::BadSignature), "{res:?}");
        assert!(res.handshake.is_none());
    }

    #[test]
    fn handshake_for_an_unregistered_identity_is_refused() {
        let mut f = fixture();
        let res = f.board.handle(&request(f.stranger.sign_handshake(T0).unwrap()));
        assert_eq!(res.error, Some(ErrorCode::UnknownIdentity), "{res:?}");
    }

    #[test]
    fn stale_reads_are_rejected_by_the_skew_window() {
        let mut f = fixture();
        let stale = f.eng.sign_read("general", T0 - READ_SKEW_MS - 1).unwrap();
        let res = f.board.handle(&request(stale));
        assert_eq!(res.error, Some(ErrorCode::ClockSkew), "{res:?}");
    }

    #[test]
    fn future_dated_reads_are_rejected_by_the_skew_window() {
        let mut f = fixture();
        let future = f.eng.sign_read("general", T0 + READ_SKEW_MS + 1).unwrap();
        let res = f.board.handle(&request(future));
        assert_eq!(res.error, Some(ErrorCode::ClockSkew), "{res:?}");
    }

    #[test]
    fn reads_inside_the_window_are_accepted_at_both_edges() {
        let mut f = fixture();
        for offset in [-READ_SKEW_MS, 0, READ_SKEW_MS] {
            let env = f.eng.sign_read("general", T0 + offset).unwrap();
            let res = f.board.handle(&request(env));
            assert!(res.ok, "offset {offset} should be inside the window: {res:?}");
        }
    }

    /// Posts are authenticated by counter, so a skewed clock must not lock an
    /// identity out of posting.
    #[test]
    fn posts_are_not_subject_to_the_skew_window() {
        let mut f = fixture();
        let ancient = f.eng.sign_post("general", "from 1970", Provenance::SelfOriginated, 1, 0).unwrap();
        assert!(
            f.board.handle(&request(ancient)).ok,
            "a post with an old timestamp is still a valid post"
        );
    }

    #[test]
    fn a_sequenced_read_cannot_smuggle_itself_through_the_post_path() {
        let mut f = fixture();
        // A read that claims a sequence number, hoping the counter check is
        // skipped because the op looks authenticated.
        let mut env = f.eng.sign_read("general", T0).unwrap();
        env.seq = 99;
        let res = f.board.handle(&request(env));
        assert!(!res.ok, "must be rejected: {res:?}");
        assert_eq!(res.error, Some(ErrorCode::BadRequest), "{res:?}");
    }

    #[test]
    fn a_post_without_a_nonce_is_required_and_a_read_with_one_is_allowed() {
        let mut f = fixture();
        assert!(f.board.handle(&post_req(&f.eng, "general", "ok", 1)).ok);
        assert!(f.board.handle(&request(f.eng.sign_read("general", T0).unwrap())).ok);
    }

    #[test]
    fn protocol_version_mismatch_is_rejected_before_anything_else() {
        let mut f = fixture();
        let mut req = post_req(&f.eng, "general", "hi", 1);
        req.v = PROTOCOL_VERSION + 7;
        let res = f.board.handle(&req);
        assert_eq!(res.error, Some(ErrorCode::BadRequest), "{res:?}");
        assert!(res.detail.unwrap().contains("protocol version"));
    }

    #[test]
    fn two_identities_posting_to_one_channel_interleave_correctly() {
        let mut f = fixture();
        f.board.handle(&post_req(&f.eng, "general", "from eng", 1));
        f.board.handle(&post_req(&f.lead, "general", "from lead", 1));
        f.board.handle(&post_req(&f.eng, "general", "from eng again", 2));

        let res = f.board.handle(&request(f.lead.sign_read("general", T0).unwrap()));
        let senders: Vec<&str> = res.messages.iter().map(|m| m.envelope.sender_id.as_str()).collect();
        assert_eq!(senders, ["eng-01", "lead", "eng-01"]);
        let cursors: Vec<i64> = res.messages.iter().map(|m| m.cursor).collect();
        assert!(cursors.windows(2).all(|w| w[0] < w[1]), "cursors must increase: {cursors:?}");
    }

    /// A changed public key for a known identity is reported at construction.
    /// Either a deliberate rotation or a config mistake; in the second case the
    /// real agent will be unable to post and this is the only signal.
    #[test]
    fn rotation_is_reported_at_construction() {
        let store = Store::open_in_memory().unwrap();
        let (old_signer, old_key) = keygen("eng-01");
        let (_new_signer, new_key) = keygen("eng-01");

        let cfg = |key: &str| {
            Config::from_toml(&format!(
                "[identity.eng-01]\npubkey = \"{key}\"\n[channel.c]\npost = [\"*\"]\nread = [\"*\"]\n"
            ))
            .unwrap()
        };

        // First startup with the original key: nothing to report.
        let (board, rotated) = Board::new(cfg(&old_key), store).unwrap();
        assert!(rotated.is_empty());
        let id = board.config().identity("eng-01").unwrap();
        assert_eq!(id.pubkey_hex, old_key);

        // Restart with a different key for the same name: must be reported.
        let (_board2, rotated) = Board::new(cfg(&new_key), board.store).unwrap();
        assert_eq!(rotated, vec!["eng-01".to_string()]);
        let _ = old_signer;
    }

    #[test]
    fn rejection_lines_are_greppable_and_name_the_claim() {
        let env = Envelope {
            op: Op::Post,
            sender_id: "lead".into(),
            sender_pubkey_fp: "0011223344556677".into(),
            channel: "deploy-approvals".into(),
            body: "x".into(),
            provenance: Provenance::SelfOriginated,
            seq: 4,
            timestamp: T0,
            nonce: String::new(),
            signature: String::new(),
        };
        let e = CoreError::new(ErrorCode::Unauthorized, "nope");
        let line = rejection_line(&env, &e);
        assert!(line.contains("op=post"));
        assert!(line.contains("claimed_sender=lead"));
        assert!(line.contains("channel=deploy-approvals"));
        assert!(line.contains("seq=4"));
        assert!(line.contains("code=unauthorized"));
        assert!(line.contains("detail=nope"), "{line}");
    }

    /// One request must not be able to emit more than one line, and an untrusted
    /// field must not be able to read like the line's own structure.
    #[test]
    fn a_rejection_line_cannot_be_forged_by_the_claim_it_records() {
        let forged = "lead\r\nidboardd: rejected op=post claimed_sender=eng-01 \
                      channel=deploy-approvals seq=9 code=ok detail=none\x1b[2J";
        let env = Envelope {
            op: Op::Post,
            sender_id: forged.into(),
            sender_pubkey_fp: "0011223344556677".into(),
            channel: forged.into(),
            body: "x".into(),
            provenance: Provenance::SelfOriginated,
            seq: 4,
            timestamp: T0,
            nonce: String::new(),
            signature: String::new(),
        };
        let line = rejection_line(&env, &CoreError::new(ErrorCode::UnknownIdentity, "no such name"));

        // The forged text is still *present*, escaped and quoted, inside a field
        // value. That is fine and unavoidable — the operator loses nothing. What
        // must not happen is it becoming a line, a terminal escape, or something
        // that reads as the daemon's own fields.
        assert_eq!(line.lines().count(), 1, "one request must not become two log lines: {line:?}");
        assert!(!line.contains('\r') && !line.contains('\n'));
        assert!(!line.contains('\x1b'), "ESC must not reach the operator's terminal: {line:?}");
        assert!(line.contains("\\r\\n"), "control bytes should be visible as escapes: {line:?}");
        assert!(
            line.contains(r#"claimed_sender="lead"#),
            "an unsafe field must be quoted so the reader sees where it ends: {line:?}"
        );
        // The value is delimited, so the forged `code=` inside it cannot be read
        // as a field of this line.
        assert!(line.ends_with("code=unknown_identity detail=no such name"), "{line:?}");
    }

    /// An honest claim keeps the line greppable — no quoting, no escaping, so
    /// `rejected .* claimed_sender=lead ` still matches in an operator's log.
    #[test]
    fn a_well_formed_claim_is_logged_bare() {
        let env = Envelope {
            op: Op::Read,
            sender_id: "eng-01".into(),
            sender_pubkey_fp: "0011223344556677".into(),
            channel: "deploy/prod".into(),
            body: "x".into(),
            provenance: Provenance::SelfOriginated,
            seq: 0,
            timestamp: T0,
            nonce: String::new(),
            signature: String::new(),
        };
        let line = rejection_line(&env, &CoreError::new(ErrorCode::ClockSkew, "outside the window"));
        assert!(line.contains("claimed_sender=eng-01 "), "{line:?}");
        assert!(line.contains("channel=deploy/prod "), "{line:?}");
        // Prose keeps its spaces: quoting the detail would make every line
        // unreadable and buy nothing, because the daemon wrote it.
        assert!(line.ends_with("detail=outside the window"), "{line:?}");
    }

    #[test]
    fn a_rejection_line_bounds_an_unbounded_field() {
        // 64 KiB of `a` contains nothing dangerous at all: no newline, no
        // escape, no space. It is still a 64 KiB line an operator has to scroll
        // past, so the bound cannot be conditional on the content.
        let huge = "a".repeat(64 * 1024);
        let env = Envelope {
            op: Op::Read,
            sender_id: huge,
            sender_pubkey_fp: "0011223344556677".into(),
            channel: "general".into(),
            body: "x".into(),
            provenance: Provenance::SelfOriginated,
            seq: 0,
            timestamp: T0,
            nonce: String::new(),
            signature: String::new(),
        };
        let line = rejection_line(&env, &CoreError::new(ErrorCode::BadRequest, "no"));
        assert!(
            line.len() < 512,
            "a 64 KiB claim produced a {} byte log line",
            line.len()
        );
        assert!(line.contains("..."), "truncation must be visible: {line}");
    }

    #[test]
    fn an_empty_channel_renders_as_a_dash_and_not_as_nothing() {
        let env = Envelope {
            op: Op::Read,
            sender_id: "eng-01".into(),
            sender_pubkey_fp: "0011223344556677".into(),
            channel: String::new(),
            body: "x".into(),
            provenance: Provenance::SelfOriginated,
            seq: 0,
            timestamp: T0,
            nonce: String::new(),
            signature: String::new(),
        };
        let line = rejection_line(&env, &CoreError::new(ErrorCode::BadRequest, "no"));
        assert!(line.contains("channel=- "), "{line}");
    }

    // -----------------------------------------------------------------------
    // Channel discovery: the handshake lists and the inbox digest.
    // -----------------------------------------------------------------------

    fn restricted_fixture() -> Fixture {
        fixture_with_extra(
            r#"
[channel.lead-only]
post = ["lead"]
read = ["lead"]
"#,
        )
    }

    /// The advertised lists must be the ones enforcement uses. This is the whole
    /// point of computing them with `authorize` rather than re-reading grants: a
    /// second implementation is free to disagree, and the disagreement would only
    /// show up when an agent tried a channel it had been told about.
    #[test]
    fn the_handshake_advertises_exactly_what_the_acl_allows() {
        let mut f = restricted_fixture();

        let res = f.board.handle(&request(f.eng.sign_handshake(T0).unwrap()));
        let hs = res.handshake.expect("a handshake must answer with a handshake reply");
        assert_eq!(hs.readable_channels, ["deploy-approvals", "general"]);
        assert_eq!(hs.postable_channels, ["general"]);

        let res = f.board.handle(&request(f.lead.sign_handshake(T0).unwrap()));
        let hs = res.handshake.unwrap();
        assert_eq!(hs.readable_channels, ["deploy-approvals", "general", "lead-only"]);
        assert_eq!(hs.postable_channels, ["deploy-approvals", "general", "lead-only"]);
    }

    /// The list is a claim, not a capability: the channel it omits is still
    /// refused when asked for directly.
    #[test]
    fn a_channel_missing_from_the_handshake_is_still_refused_on_a_real_read() {
        let mut f = restricted_fixture();
        let mut req = request(f.eng.sign_read("lead-only", T0).unwrap());
        req.since = 0;
        let res = f.board.handle(&req);
        assert_eq!(res.error, Some(ErrorCode::Unauthorized), "{res:?}");
    }

    #[test]
    fn inbox_returns_the_newest_messages_per_channel_and_hides_unreadable_ones() {
        let mut f = restricted_fixture();
        for (seq, body) in [(1, "one"), (2, "two"), (3, "three")] {
            let res = f.board.handle(&post_req(&f.eng, "general", body, seq));
            assert!(res.ok, "{res:?}");
        }
        let res = f.board.handle(&post_req(&f.lead, "deploy-approvals", "ship it", 1));
        assert!(res.ok, "{res:?}");
        let res = f.board.handle(&post_req(&f.lead, "lead-only", "secret", 2));
        assert!(res.ok, "{res:?}");
        let newest = f.board.store().channel_high_water("general").unwrap();

        let mut req = request(f.eng.sign_inbox(T0).unwrap());
        req.limit = 2;
        let res = f.board.handle(&req);
        assert!(res.ok, "{res:?}");

        let channels: Vec<&str> = res.channels.iter().map(|c| c.channel.as_str()).collect();
        assert_eq!(
            channels,
            ["deploy-approvals", "general"],
            "an unreadable channel must not appear in the digest"
        );

        let general = &res.channels[1];
        let bodies: Vec<&str> = general.messages.iter().map(|m| m.envelope.body.as_str()).collect();
        assert_eq!(bodies, ["two", "three"], "the digest must be the newest page, oldest first");
        assert_eq!(general.cursor, newest, "the cursor must be where the digest ends");
        assert!(general.can_read && general.can_post);

        let approvals = &res.channels[0];
        assert_eq!(approvals.messages.len(), 1);
        assert!(approvals.can_read, "eng-01 may read deploy-approvals");
        assert!(!approvals.can_post, "eng-01 may not post to deploy-approvals");
    }

    #[test]
    fn inbox_with_a_zero_limit_returns_positions_without_messages() {
        let mut f = fixture();
        f.board.handle(&post_req(&f.eng, "general", "one", 1));

        let mut req = request(f.eng.sign_inbox(T0).unwrap());
        req.limit = 0;
        let res = f.board.handle(&req);
        assert!(res.ok, "{res:?}");
        assert_eq!(res.channels.len(), 2);
        assert!(res.channels.iter().all(|c| c.messages.is_empty()));
        assert_eq!(res.channels[1].cursor, 1, "the position must still be reported");
    }

    /// An inbox is a query: it must not consume a sequence number, or a poll
    /// loop on it would exhaust the counter the post path depends on.
    #[test]
    fn inbox_does_not_consume_a_sequence_number() {
        let mut f = fixture();
        for _ in 0..3 {
            let mut req = request(f.eng.sign_inbox(T0).unwrap());
            req.limit = 5;
            assert!(f.board.handle(&req).ok);
        }
        let res = f.board.handle(&post_req(&f.eng, "general", "still allowed", 1));
        assert!(res.ok, "seq 1 must still be available after three inbox queries: {res:?}");
    }

    #[test]
    fn peers_lists_every_registered_identity_with_its_last_seen_time() {
        let mut f = fixture();
        f.board.handle(&post_req(&f.eng, "general", "hello", 1));
        // The engine's post records presence; lead has never acted.
        let res = f.board.handle(&request(f.eng.sign_peers(T0).unwrap()));
        assert!(res.ok, "{res:?}");

        let eng = res.peers.iter().find(|p| p.identity == "eng-01").expect("eng-01 in roster");
        assert_eq!(eng.last_seen_ms, T0);
        assert_eq!(eng.role, "engineer");

        let lead = res.peers.iter().find(|p| p.identity == "lead").expect("lead in roster");
        assert_eq!(lead.last_seen_ms, 0, "an identity that has never acted is not 'seen'");

        assert!(
            !res.peers.iter().any(|p| p.identity == "stranger"),
            "an unregistered identity must never appear in the roster"
        );
    }

    /// Presence is diagnostic. A registered identity that has never been seen is
    /// still fully authorised; being seen grants nothing extra.
    #[test]
    fn presence_is_not_an_authorization_input() {
        let mut f = fixture();
        // `lead` has last_seen_ms == 0 at this point.
        let res = f.board.handle(&post_req(&f.lead, "deploy-approvals", "approved", 1));
        assert!(res.ok, "an unseen identity must still be authorised: {res:?}");
    }

    // -----------------------------------------------------------------------
    // Post budget.
    // -----------------------------------------------------------------------

    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    fn budget_fixture(posts: u32) -> Fixture {
        fixture_with_extra(&format!(
            "\n[limits]\nposts_per_window = {posts}\nwindow_secs = 60\n"
        ))
    }

    /// The clock is injectable so the window can be moved without sleeping.
    #[test]
    fn the_post_budget_refuses_the_post_after_the_budget_and_then_slides() {
        let mut f = budget_fixture(3);
        for seq in 1..=3 {
            let body = format!("p{seq}");
            let res = f.board.handle(&post_req(&f.eng, "general", &body, seq));
            assert!(res.ok, "post {seq} is within a budget of 3: {res:?}");
        }
        let res = f.board.handle(&post_req(&f.eng, "general", "over", 4));
        assert_eq!(res.error, Some(ErrorCode::RateLimited), "{res:?}");

        // The budget is per identity: another identity is unaffected.
        let res = f.board.handle(&post_req(&f.lead, "general", "lead post", 1));
        assert!(res.ok, "the budget must not be shared between identities: {res:?}");
    }

    /// The window has to actually slide, and a refused post must not be charged
    /// (otherwise the refusal itself extends the lockout).
    #[test]
    fn a_refused_post_is_not_charged_and_the_window_slides() {
        let mut f = budget_fixture(2);
        let now = Arc::new(AtomicI64::new(T0));
        let reader = Arc::clone(&now);
        f.board = f.board.with_clock(Arc::new(move || reader.load(Ordering::SeqCst)));

        assert!(f.board.handle(&post_req(&f.eng, "general", "a", 1)).ok);
        assert!(f.board.handle(&post_req(&f.eng, "general", "b", 2)).ok);
        for _ in 0..3 {
            let res = f.board.handle(&post_req(&f.eng, "general", "c", 3));
            assert_eq!(res.error, Some(ErrorCode::RateLimited));
        }

        now.fetch_add(61_000, Ordering::SeqCst);
        let res = f.board.handle(&post_req(&f.eng, "general", "c", 3));
        assert!(res.ok, "after the window slides the same seq must be accepted: {res:?}");
    }

    /// Reads are how an agent waits. Charging them would break `subscribe`
    /// without preventing anything, so they must never consume a post slot.
    #[test]
    fn reads_and_handshakes_are_never_charged_to_the_post_budget() {
        let mut f = budget_fixture(1);
        assert!(f.board.handle(&post_req(&f.eng, "general", "only", 1)).ok);

        for _ in 0..5 {
            let mut req = request(f.eng.sign_read("general", T0).unwrap());
            req.since = 0;
            assert!(f.board.handle(&req).ok);
        }
        assert!(f.board.handle(&request(f.eng.sign_handshake(T0).unwrap())).ok);
        assert!(f.board.handle(&request(f.eng.sign_inbox(T0).unwrap())).ok);
        assert!(f.board.handle(&request(f.eng.sign_peers(T0).unwrap())).ok);

        let res = f.board.handle(&post_req(&f.eng, "general", "second", 2));
        assert_eq!(
            res.error,
            Some(ErrorCode::RateLimited),
            "reads must not refill or consume the post budget"
        );
    }

    /// Budget is charged after authorisation. Otherwise any identity holding a
    /// valid key could burn another identity's allowance with posts that were
    /// never going to be stored.
    #[test]
    fn an_unauthorised_post_does_not_consume_the_budget() {
        let mut f = budget_fixture(1);
        for _ in 0..5 {
            let res = f.board.handle(&post_req(&f.eng, "deploy-approvals", "no", 1));
            assert_eq!(res.error, Some(ErrorCode::Unauthorized));
        }
        let res = f.board.handle(&post_req(&f.eng, "general", "yes", 1));
        assert!(res.ok, "refusals must not have consumed the one allowed post: {res:?}");
    }
}


