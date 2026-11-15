//! Daemon configuration: the identity registry, roles, and channel ACLs.
//!
//! # Why public keys must be explicit
//!
//! The config requires a `pubkey` for every identity, and the daemon refuses to
//! start without one. This closes a hole that a trust-on-first-use design would
//! leave wide open.
//!
//! With TOFU, a key is recorded the first time a name is seen. On a machine
//! where any process can reach the daemon socket, an attacker simply posts as
//! `lead` first, with an attacker-chosen key. The daemon records it. Later,
//! the real `lead` launches, signs with the genuine key, and is rejected as a
//! forgery. The attacker has permanently locked out the identity they are
//! impersonating, with no operator-visible error until someone tries to use it.
//!
//! Explicit keys move that decision to the one place it belongs: the config
//! file, written by whoever owns the machine.
//!
//! # Grant matching
//!
//! A grant matches an identity if it is `"*"`, the identity's name, or the
//! identity's role. Role matching is convenient and a footgun: adding a second
//! identity with `role = "engineer"` silently grants it every channel engineers
//! can reach. The daemon prints the resolved matrix at startup so that is
//! visible rather than inferred.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::VerifyingKey;
use idboard_core::error::{CoreError, ErrorCode};
use idboard_core::ids::{validate_channel, validate_identity};
use idboard_core::keys::{fingerprint_of, pubkey_from_hex};
use serde::{Deserialize, Serialize};

/// Raw config as it appears in TOML.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FileConfig {
    #[serde(default)]
    pub identity: BTreeMap<String, IdentityConfig>,
    #[serde(default)]
    pub channel: BTreeMap<String, ChannelConfig>,
    #[serde(default)]
    pub limits: LimitsConfig,
}

/// The optional `[limits]` table.
///
/// Absent means no limit at all, which is the default on purpose: a limit that
/// nobody asked for would break an existing agent the first time it ran a burst.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct LimitsConfig {
    /// Posts accepted per identity per window. `0`, or an absent table, means
    /// unlimited.
    #[serde(default)]
    pub posts_per_window: u32,
    /// Window length in seconds. Defaults to 60 when a budget is set; zero is a
    /// config error rather than a silently-empty window.
    #[serde(default)]
    pub window_secs: Option<u64>,
}

/// Resolved limits, with the default window already applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub posts_per_window: u32,
    pub window_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self { posts_per_window: 0, window_ms: 60_000 }
    }
}

impl Limits {
    /// Whether any limit is configured at all.
    pub fn is_unlimited(&self) -> bool {
        self.posts_per_window == 0
    }
}

/// One `[identity.NAME]` table.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct IdentityConfig {
    /// Role used for role-based grants. Defaults to the identity's own name if
    /// omitted, which makes a bare `[identity.x]` grant equivalent to naming it.
    #[serde(default)]
    pub role: Option<String>,
    /// Hex ed25519 public key. Mandatory.
    #[serde(default)]
    pub pubkey: Option<String>,
    /// Free-form note for operators. Never interpreted.
    #[serde(default)]
    pub description: Option<String>,
}

/// One `[channel.NAME]` table.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ChannelConfig {
    /// Identities or roles permitted to post. Empty means nobody.
    #[serde(default)]
    pub post: Vec<String>,
    /// Identities or roles permitted to read. Empty means nobody.
    #[serde(default)]
    pub read: Vec<String>,
    /// Whether external-provenance posts are accepted on this channel.
    ///
    /// Defaults to true, which is the historical behaviour. Set this to `false`
    /// for channels where content fetched from elsewhere must never enter the
    /// conversation as an actionable message.
    #[serde(default = "default_allow_external")]
    pub allow_external: bool,
}

fn default_allow_external() -> bool {
    true
}

/// What the daemon learned about one identity at load time.
#[derive(Debug, Clone)]
pub struct Identity {
    pub name: String,
    pub role: String,
    pub public_key: VerifyingKey,
    pub pubkey_hex: String,
    pub fingerprint: String,
    pub description: Option<String>,
}

impl Identity {
    /// Whether a grant entry matches this identity.
    ///
    /// `"*"` matches everyone; otherwise the entry must equal the identity's
    /// name or its role.
    pub fn matches_grant(&self, grant: &str) -> bool {
        grant == "*" || grant == self.name || grant == self.role
    }
}

/// What the daemon learned about one channel at load time.
#[derive(Debug, Clone)]
pub struct Channel {
    pub name: String,
    pub post: Vec<String>,
    pub read: Vec<String>,
    /// Accepted external-provenance posts. `false` means they are refused before
    /// authorisation is allowed to mutate anything.
    pub allow_external: bool,
}

impl Channel {
    fn permits(&self, grants: &[String], identity: &Identity) -> bool {
        grants.iter().any(|g| identity.matches_grant(g))
    }

    pub fn can_post(&self, identity: &Identity) -> bool {
        self.permits(&self.post, identity)
    }

    pub fn can_read(&self, identity: &Identity) -> bool {
        self.permits(&self.read, identity)
    }
}

/// A loaded, validated configuration.
#[derive(Debug, Clone)]
pub struct Config {
    identities: BTreeMap<String, Identity>,
    channels: BTreeMap<String, Channel>,
    limits: Limits,
}

/// A load failure, with enough context to point at the offending line.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("config is invalid: {0}")]
    Invalid(String),
}

impl From<ConfigError> for CoreError {
    fn from(e: ConfigError) -> Self {
        match e {
            // A config problem is the operator's to fix, so it surfaces as an
            // internal error rather than blaming the caller.
            _ => CoreError::new(ErrorCode::Internal, e.to_string()),
        }
    }
}

impl Config {
    /// Parse and validate from a TOML string.
    ///
    /// Every problem is reported, not just the first, so an operator fixing a
    /// fresh config does not have to run the daemon repeatedly to discover each
    /// mistake.
    pub fn from_toml(text: &str) -> std::result::Result<Self, ConfigError> {
        let raw: FileConfig = toml::from_str(text)
            .map_err(|source| ConfigError::Parse { path: "<config>".into(), source })?;

        let mut problems: Vec<String> = Vec::new();
        let mut identities = BTreeMap::new();
        let mut channels = BTreeMap::new();

        for (name, ic) in &raw.identity {
            if let Err(e) = validate_identity(name) {
                problems.push(format!("[identity.{name}]: {}", e.detail));
                continue;
            }

            // Lowercased, not just trimmed. `LocalSigner::public_hex` is
            // lowercase, and the wrapper compares the config's value against it
            // for equality to decide key drift. An operator who pasted a
            // correctly-cased-but-uppercase key therefore got exit 4
            // `KeyMismatch` naming two different keys that were the same key.
            let pubkey_hex = match &ic.pubkey {
                Some(p) if !p.trim().is_empty() => p.trim().to_ascii_lowercase(),
                Some(_) => {
                    problems.push(format!("[identity.{name}]: pubkey is present but empty"));
                    continue;
                }
                None => {
                    problems.push(format!(
                        "[identity.{name}]: pubkey is required. \
                         Run `keryx keygen {name}` and paste the result. \
                         Keys are never learned on first use, because any local \
                         process could claim the name first and lock you out."
                    ));
                    continue;
                }
            };

            let public_key = match pubkey_from_hex(&pubkey_hex) {
                Ok(k) => k,
                Err(e) => {
                    problems.push(format!("[identity.{name}]: {}", e.detail));
                    continue;
                }
            };

            let role = ic
                .role
                .as_deref()
                .map(str::trim)
                .filter(|r| !r.is_empty())
                .unwrap_or(name)
                .to_string();

            identities.insert(
                name.clone(),
                Identity {
                    name: name.clone(),
                    role,
                    fingerprint: fingerprint_of(&public_key),
                    public_key,
                    pubkey_hex,
                    description: ic.description.clone(),
                },
            );
        }

        for (name, cc) in &raw.channel {
            if let Err(e) = validate_channel(name) {
                problems.push(format!("[channel.{name}]: {}", e.detail));
                continue;
            }
            for grant in cc.post.iter().chain(cc.read.iter()) {
                if grant != "*" && !identities.contains_key(grant) {
                    // Not fatal: a grant may name a role, which is not an
                    // identity key. Only flag when it matches neither an
                    // identity nor any declared role.
                    let is_role = identities.values().any(|i| i.role == *grant);
                    if !is_role {
                        problems.push(format!(
                            "[channel.{name}]: grant {grant:?} matches no identity and no role. \
                             Identities: [{}]. If this is a typo it will silently deny access.",
                            identities.keys().cloned().collect::<Vec<_>>().join(", ")
                        ));
                    }
                }
            }
            channels.insert(name.clone(), Channel {
                name: name.clone(),
                post: cc.post.clone(),
                read: cc.read.clone(),
                allow_external: cc.allow_external,
            });
        }

        if identities.is_empty() {
            problems.push("no usable [identity.*] entries; the board would reject every message".into());
        }

        let window_secs = raw.limits.window_secs.unwrap_or(60);
        if raw.limits.posts_per_window > 0 && window_secs == 0 {
            problems.push(
                "[limits].window_secs must be at least 1; a zero-length window would either \
                 refuse every post or never reset"
                    .into(),
            );
        }
        let limits = Limits {
            posts_per_window: raw.limits.posts_per_window,
            window_ms: window_secs.saturating_mul(1000).max(1),
        };

        if !problems.is_empty() {
            return Err(ConfigError::Invalid(problems.join("\n  - ")));
        }

        Ok(Self { identities, channels, limits })
    }

    /// Read and validate a config file.
    ///
    /// The config is the sole trust root: it is the only thing that says which
    /// key belongs to which name, and a key substituted here is *self-consistent*
    /// — the fingerprint is derived from the parsed key rather than read from the
    /// file, so nothing downstream can notice. The fingerprint cross-check
    /// between the wrapper and the daemon compares two readings of the same
    /// substituted key and agrees with it.
    ///
    /// So the read is checked for custody first, with no third-party crates:
    /// the path must be a regular file and must not be a symlink, and on Unix
    /// it must be owned by the current user and not writable by group or other.
    ///
    /// On Windows there is no file ACL check here and none is claimed. NTFS
    /// inherits the DACL from `%USERPROFILE%`, which grants the creating account
    /// and SYSTEM; the only principal left in scope is a second non-administrative
    /// local account, and whether the inherited DACL permits that account to
    /// write is a property of the machine, not of this code. The daemon reports
    /// the custody it observed so an operator can check it with `icacls`.
    pub fn load(path: &std::path::Path) -> std::result::Result<Self, ConfigError> {
        let display = path.display().to_string();
        check_custody(path).map_err(|detail| ConfigError::Io { path: display.clone(), source: std::io::Error::other(detail) })?;
        let text = std::fs::read_to_string(path)
            .map_err(|source| ConfigError::Io { path: display.clone(), source })?;
        Self::from_toml(&text).map_err(|e| match e {
            ConfigError::Parse { source, .. } => ConfigError::Parse { path: display, source },
            other => other,
        })
    }

    /// A one-line statement of what is enforcing custody of the config.
    ///
    /// Printed at daemon startup so the answer is visible on the machine rather
    /// than asserted in a comment. The socket's own custody is a separate
    /// assumption and is reported by `idboard-ipc::listener_custody_statement` —
    /// the two are printed together because a config only matters if someone can
    /// reach the door in front of it.
    pub fn custody_statement() -> &'static str {
        #[cfg(unix)]
        {
            "config custody: regular file, not a symlink, owned by you, mode forbids \
             group/other writes (enforced). Verify with: scripts/check-custody.ps1"
        }
        #[cfg(not(unix))]
        {
            "config custody: regular file and not a symlink (enforced); owner and DACL are NOT \
             checked by idboard. This relies on the DACL inherited from your user profile, which \
             on a standard profile grants you, SYSTEM, and Administrators and denies Users and \
             Everyone. Verify with: scripts\\check-custody.ps1"
        }
    }

    pub fn identity(&self, name: &str) -> Option<&Identity> {
        self.identities.get(name)
    }

    pub fn channel(&self, name: &str) -> Option<&Channel> {
        self.channels.get(name)
    }

    pub fn identities(&self) -> impl Iterator<Item = &Identity> {
        self.identities.values()
    }

    pub fn channels(&self) -> impl Iterator<Item = &Channel> {
        self.channels.values()
    }

    /// The configured post budget. `is_unlimited()` is true on a default config.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub fn identity_count(&self) -> usize {
        self.identities.len()
    }

    /// Roles declared across all identities, for validating grants.
    pub fn roles(&self) -> BTreeSet<&str> {
        self.identities.values().map(|i| i.role.as_str()).collect()
    }

    /// The startup summary: who can do what, and which public keys are trusted.
    ///
    /// Printed at daemon start. The point is that an operator can see a
    /// misconfigured ACL without having to reason about role inheritance.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        out.push_str("identities:\n");
        for id in self.identities.values() {
            let postable: Vec<&str> = self
                .channels()
                .filter(|c| c.can_post(id))
                .map(|c| c.name.as_str())
                .collect();
            let readable: Vec<&str> = self
                .channels()
                .filter(|c| c.can_read(id))
                .map(|c| c.name.as_str())
                .collect();
            out.push_str(&format!(
                "  {:<16} role={:<12} fp={}  pubkey={}\n",
                id.name, id.role, id.fingerprint, id.pubkey_hex
            ));
            out.push_str(&format!("      post -> {}\n", if postable.is_empty() { "(none)".into() } else { postable.join(", ") }));
            out.push_str(&format!("      read -> {}\n", if readable.is_empty() { "(none)".into() } else { readable.join(", ") }));
        }
        out.push_str("channels:\n");
        for c in self.channels.values() {
            out.push_str(&format!(
                "  {:<20} post=[{}] read=[{}] allow_external={}\n",
                c.name,
                c.post.join(" "),
                c.read.join(" "),
                if c.allow_external { "yes" } else { "no" }
            ));
        }
        // Printed unconditionally: "no limit" is a configuration fact an
        // operator should see rather than infer from an absent table.
        if self.limits.is_unlimited() {
            out.push_str("limits: none (no post budget configured)\n");
        } else {
            out.push_str(&format!(
                "limits: {} posts per identity per {}s\n",
                self.limits.posts_per_window,
                self.limits.window_ms / 1000
            ));
        }
        out
    }

    /// Warn about the role-inheritance footgun: a role shared by more than one
    /// identity, where any grant names that role rather than the identity.
    pub fn role_inheritance_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        let mut by_role: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for id in self.identities.values() {
            by_role.entry(id.role.as_str()).or_default().push(id.name.as_str());
        }
        for (role, members) in by_role {
            if members.len() < 2 {
                continue;
            }
            let role_referenced: Vec<&str> = self
                .channels()
                .filter(|c| {
                    c.post.iter().chain(c.read.iter()).any(|g| g == role)
                })
                .map(|c| c.name.as_str())
                .collect();
            if role_referenced.is_empty() {
                continue;
            }
            warnings.push(format!(
                "role {role:?} is shared by {} and is referenced by channel(s) [{}]. \
                 Every one of them inherits those grants: {}",
                members.join(", "),
                role_referenced.join(", "),
                members.join(", ")
            ));
        }
        warnings
    }
}

/// Reject a config whose custody we cannot vouch for.
///
/// `symlink_metadata` rather than `metadata`, so the check sees the link itself
/// and not whatever it points at. A symlinked config is refused outright rather
/// than followed: the point of a trust root is that you know which bytes you
/// read, and a link makes that a property of something not being checked.
fn check_custody(path: &std::path::Path) -> std::result::Result<(), String> {
    let link = std::fs::symlink_metadata(path).map_err(|e| format!("cannot stat the config: {e}"))?;
    if link.file_type().is_symlink() {
        return Err("the config is a symlink; keryx will not follow a symlinked trust root".into());
    }
    if !link.is_file() {
        return Err("the config is not a regular file".into());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = current_uid();
        if link.uid() != uid {
            return Err(format!(
                "the config is owned by uid {} but this process runs as uid {}; a config you do \
                 not own decides which key signs as you",
                link.uid(),
                uid
            ));
        }
        if link.mode() & 0o022 != 0 {
            return Err(format!(
                "the config is mode {:o}; group and other must not be able to write it",
                link.mode() & 0o7777
            ));
        }
    }

    Ok(())
}

/// Current user id, without taking a dependency for one call.
///
/// `std` has no `getuid`. The `unsafe` is the FFI call itself: no state to
/// initialise, no allocation, nothing to uphold beyond the signature.
#[cfg(unix)]
fn current_uid() -> u32 {
    extern "C" {
        fn getuid() -> u32;
    }
    // SAFETY: `getuid` takes no arguments, cannot fail, and touches no memory we
    // own. It is async-signal-safe, which is the only property that matters here.
    unsafe { getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_for(id: &str) -> String {
        idboard_core::keys::LocalSigner::generate(id).unwrap().0.public_hex()
    }

    fn cfg_with(body: &str) -> std::result::Result<Config, ConfigError> {
        Config::from_toml(body)
    }

    fn standard() -> String {
        format!(
            r#"
[identity.eng-01]
role = "engineer"
pubkey = "{k1}"

[identity.eng-02]
role = "engineer"
pubkey = "{k2}"

[identity.lead]
role = "lead"
pubkey = "{k3}"

[channel.general]
post = ["*"]
read = ["*"]

[channel.deploy-approvals]
post = ["lead"]
read = ["*"]
"#,
            k1 = key_for("eng-01"),
            k2 = key_for("eng-02"),
            k3 = key_for("lead"),
        )
    }

    #[test]
    fn loads_the_plans_example_shape() {
        let c = cfg_with(&standard()).unwrap();
        assert_eq!(c.identity_count(), 3);
        assert!(c.channel("general").is_some());
        assert!(c.channel("deploy-approvals").is_some());
    }

    /// A limit nobody configured must not exist. The default is the product
    /// behaving exactly as it did before `[limits]` existed.
    #[test]
    fn channel_external_posts_are_allowed_by_default_and_can_be_forbidden() {
        let c = cfg_with(&standard()).unwrap();
        assert!(c.channel("general").unwrap().allow_external);
        assert!(c.summary().contains("allow_external=yes"), "{}", c.summary());

        let strict = format!(
            "{}\n[channel.strict]\npost = [\"*\"]\nread = [\"*\"]\nallow_external = false\n",
            standard()
        );
        let c = cfg_with(&strict).unwrap();
        let ch = c.channel("strict").unwrap();
        assert!(!ch.allow_external);
        assert!(c.summary().contains("allow_external=no"), "{}", c.summary());
    }

    #[test]
    fn limits_are_unlimited_by_default_and_say_so_in_the_summary() {
        let c = cfg_with(&standard()).unwrap();
        assert!(c.limits().is_unlimited(), "a config with no [limits] table must not throttle");
        assert!(c.summary().contains("limits: none"), "{}", c.summary());
    }

    #[test]
    fn a_post_budget_defaults_its_window_to_sixty_seconds() {
        let body = format!("{}\n[limits]\nposts_per_window = 10\n", standard());
        let c = cfg_with(&body).unwrap();
        assert_eq!(c.limits().posts_per_window, 10);
        assert_eq!(c.limits().window_ms, 60_000);
        assert!(c.summary().contains("10 posts per identity per 60s"), "{}", c.summary());
    }

    #[test]
    fn a_zero_length_window_with_a_budget_is_a_config_error() {
        let body = format!("{}\n[limits]\nposts_per_window = 5\nwindow_secs = 0\n", standard());
        let err = cfg_with(&body).unwrap_err().to_string();
        assert!(err.contains("window_secs"), "the error must name the key: {err}");
    }

    #[test]
    fn star_grant_matches_everyone() {
        let c = cfg_with(&standard()).unwrap();
        let ch = c.channel("general").unwrap();
        for id in c.identities() {
            assert!(ch.can_post(id), "{} should be able to post to general", id.name);
            assert!(ch.can_read(id));
        }
    }

    #[test]
    fn name_grant_matches_only_that_identity() {
        let c = cfg_with(&standard()).unwrap();
        let ch = c.channel("deploy-approvals").unwrap();
        let lead = c.identity("lead").unwrap();
        let eng1 = c.identity("eng-01").unwrap();
        let eng2 = c.identity("eng-02").unwrap();
        assert!(ch.can_post(lead));
        assert!(!ch.can_post(eng1), "eng-01 must not be able to post to deploy-approvals");
        assert!(!ch.can_post(eng2));
        // Reading is open to all.
        assert!(ch.can_read(eng1) && ch.can_read(eng2) && ch.can_read(lead));
    }

    /// The footgun, made explicit: two engineers, one role, so a role-named
    /// grant reaches both.
    #[test]
    fn role_grant_reaches_every_identity_with_that_role() {
        let text = format!(
            r#"
[identity.a]
role = "engineer"
pubkey = "{k1}"
[identity.b]
role = "engineer"
pubkey = "{k2}"
[channel.releases]
post = ["engineer"]
read = ["*"]
"#,
            k1 = key_for("a"),
            k2 = key_for("b"),
        );
        let c = cfg_with(&text).unwrap();
        let ch = c.channel("releases").unwrap();
        assert!(ch.can_post(c.identity("a").unwrap()));
        assert!(ch.can_post(c.identity("b").unwrap()), "role grant intentionally covers both");
    }

    #[test]
    fn role_inheritance_is_reported_as_a_warning() {
        let text = format!(
            r#"
[identity.a]
role = "engineer"
pubkey = "{k1}"
[identity.b]
role = "engineer"
pubkey = "{k2}"
[channel.releases]
post = ["engineer"]
read = ["*"]
"#,
            k1 = key_for("a"),
            k2 = key_for("b"),
        );
        let c = cfg_with(&text).unwrap();
        let w = c.role_inheritance_warnings();
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("engineer"));
        assert!(w[0].contains("releases"));
    }

    #[test]
    fn distinct_roles_produce_no_warning() {
        let c = cfg_with(&standard()).unwrap();
        // standard() has two engineers but no grant names the role.
        assert!(c.role_inheritance_warnings().is_empty());
    }

    #[test]
    fn missing_pubkey_is_a_load_failure_naming_the_fix() {
        let err = cfg_with(
            r#"
[identity.eng-01]
role = "engineer"
[channel.general]
post = ["*"]
"#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("pubkey is required"), "{msg}");
        assert!(msg.contains("keryx keygen eng-01"), "error should name the command: {msg}");
    }

    /// The TOFU hazard, stated as a test: no path assigns a key to a name that
    /// the config did not already declare.
    #[test]
    fn no_key_is_ever_learned_from_a_sender() {
        let c = cfg_with(&standard()).unwrap();
        assert!(c.identity("attacker").is_none());
        // A well-formed key from an undeclared identity has no registry entry,
        // so the daemon has nothing to verify it against.
        let rogue = idboard_core::keys::LocalSigner::generate("attacker").unwrap().0;
        let env = rogue.sign_post("general", "hi", idboard_core::Provenance::SelfOriginated, 1, 1).unwrap();
        let e = idboard_core::verify_with_key(&rogue.verifying_key(), &env);
        assert!(e.is_ok(), "the signature itself is valid...");
        // ...but there is no config entry binding that key to the name, which is
        // what the daemon checks before accepting anything.
        assert!(c.identity("attacker").is_none(), "...and no config entry binds it to a name");
    }

    #[test]
    fn empty_grants_deny_everyone() {
        let text = format!(
            r#"
[identity.a]
pubkey = "{k}"
[channel.locked]
post = []
read = []
"#,
            k = key_for("a")
        );
        let c = cfg_with(&text).unwrap();
        let ch = c.channel("locked").unwrap();
        let a = c.identity("a").unwrap();
        assert!(!ch.can_post(a), "empty post list must deny");
        assert!(!ch.can_read(a), "empty read list must deny");
    }

    #[test]
    fn role_defaults_to_the_identity_name() {
        let text = format!(
            r#"
[identity.solo]
pubkey = "{k}"
[channel.c]
post = ["solo"]
read = ["*"]
"#,
            k = key_for("solo")
        );
        let c = cfg_with(&text).unwrap();
        assert_eq!(c.identity("solo").unwrap().role, "solo");
        assert!(c.channel("c").unwrap().can_post(c.identity("solo").unwrap()));
    }

    #[test]
    fn all_problems_are_reported_at_once() {
        let err = cfg_with(
            r#"
[identity.a]
[identity.b]
pubkey = "nothexatall"
[identity.c]
pubkey = "aabbccdd"
"#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("[identity.a]"), "{msg}");
        assert!(msg.contains("[identity.b]"), "{msg}");
        assert!(msg.contains("[identity.c]"), "{msg}");
    }

    #[test]
    fn unknown_grant_targets_are_flagged() {
        let err = cfg_with(&format!(
            r#"
[identity.a]
pubkey = "{k}"
[channel.c]
post = ["ghost"]
read = []
"#,
            k = key_for("a")
        ))
        .unwrap_err();
        assert!(err.to_string().contains("ghost"), "{}", err);
    }

    #[test]
    fn config_with_no_identities_is_rejected() {
        let err = cfg_with("[channel.c]\npost = [\"*\"]\n").unwrap_err();
        assert!(err.to_string().contains("no usable"), "{}", err);
    }

    #[test]
    fn fingerprints_are_derived_not_configured() {
        let c = cfg_with(&standard()).unwrap();
        let id = c.identity("eng-01").unwrap();
        assert_eq!(id.fingerprint.len(), 16);
        assert_eq!(
            id.fingerprint,
            fingerprint_of(&id.public_key),
            "fingerprint must be computed from the key, not trusted from config"
        );
    }

    /// A pasted key is often uppercase, because it came out of something that
    /// formats hex that way. `LocalSigner::public_hex` is lowercase, and the
    /// wrapper compares the two for equality to detect key drift — so an
    /// uppercase key used to produce exit 4 `KeyMismatch` naming two different
    /// keys that were in fact the same key.
    ///
    /// The same key in three spellings must resolve to one identity.
    #[test]
    fn hex_case_never_changes_the_registered_key() {
        let lower = key_for("eng-01");
        for spelling in [lower.clone(), lower.to_ascii_uppercase(), format!("  {lower}  ")] {
            let c = cfg_with(&format!(
                "[identity.eng-01]\npubkey = \"{spelling}\"\n[channel.general]\npost = [\"*\"]\nread = [\"*\"]\n"
            ))
            .unwrap();
            let id = c.identity("eng-01").unwrap();
            assert_eq!(id.pubkey_hex, lower, "spelling {spelling:?} did not normalise");
        }
    }

    #[test]
    fn a_symlinked_config_is_refused_rather_than_followed() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.toml");
        std::fs::write(&real, standard()).unwrap();
        let link = dir.path().join("config.toml");

        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_file(&real, &link);
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(&real, &link);
        if made.is_err() {
            // Creating a symlink can require a privilege this host withholds. Say
            // so rather than passing silently — a skipped test is not a green one.
            eprintln!("skipping: cannot create a symlink here ({:?})", made.unwrap_err());
            return;
        }

        let err = Config::load(&link).unwrap_err().to_string();
        assert!(err.contains("symlink"), "a symlinked trust root must be refused: {err}");
    }

    #[test]
    fn a_config_that_is_not_a_regular_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Config::load(dir.path()).is_err(), "a directory is not a config");

        let missing = dir.path().join("nope.toml");
        assert!(Config::load(&missing).is_err(), "a missing config must not silently load");
    }

    #[test]
    fn an_ordinary_config_file_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, standard()).unwrap();
        let c = Config::load(&path).expect("a plain owned config must load");
        assert_eq!(c.identity_count(), 3);
    }

    /// A custody statement that over-claims is worse than none, because an
    /// operator reads it and stops looking.
    #[test]
    fn the_config_custody_statement_does_not_over_claim() {
        let s = Config::custody_statement();
        assert!(s.contains("check-custody.ps1"), "must say how to verify: {s}");

        #[cfg(unix)]
        {
            // Owner and mode really are checked here, so claiming them is honest.
            assert!(s.contains("owned by you"), "{s}");
            assert!(s.contains("enforced"), "{s}");
        }
        #[cfg(not(unix))]
        {
            // They are not checked here, so the statement must say so plainly
            // rather than letting "custody" imply enforcement that does not exist.
            assert!(s.contains("NOT"), "must admit the DACL is not checked: {s}");
            assert!(
                !s.contains("enforced (DACL)"),
                "must not imply the DACL is enforced: {s}"
            );
        }
    }

    #[test]
    fn summary_lists_every_identity_and_channel() {
        let s = cfg_with(&standard()).unwrap().summary();
        for needle in ["eng-01", "eng-02", "lead", "general", "deploy-approvals", "pubkey="] {
            assert!(s.contains(needle), "summary missing {needle}:\n{s}");
        }

        // Pull out exactly one identity's block: the header line plus the two
        // grant lines that follow it.
        let lines: Vec<&str> = s.lines().collect();
        let block = |name: &str| -> Vec<&str> {
            let i = lines
                .iter()
                .position(|l| l.starts_with(&format!("  {name} ")) && l.contains("role="))
                .unwrap_or_else(|| panic!("no header line for {name} in:\n{s}"));
            lines[i..i + 3].to_vec()
        };

        // lead posts to deploy-approvals; eng-01 does not. The whole point of
        // printing this at startup is that the difference is visible.
        assert!(
            block("lead").iter().any(|l| l.contains("post ->") && l.contains("deploy-approvals")),
            "lead should be able to post to deploy-approvals:\n{s}"
        );
        let eng1 = block("eng-01");
        assert!(
            eng1.iter().any(|l| l.trim_start().starts_with("post ->") && l.contains("general")),
            "eng-01 should post to general:\n{s}"
        );
        assert!(
            !eng1.iter().any(|l| l.trim_start().starts_with("post ->") && l.contains("deploy-approvals")),
            "eng-01 must not be able to post to deploy-approvals:\n{s}"
        );
    }

    #[test]
    fn invalid_identity_and_channel_names_are_rejected() {
        let err = cfg_with(&format!(
            r#"
[identity."../evil"]
pubkey = "{k}"
[identity."CON"]
pubkey = "{k}"
[channel."bad name"]
post = ["*"]
"#,
            k = key_for("x")
        ))
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("../evil"), "{msg}");
        // A device name is not a traversal, but it cannot be a key file either.
        assert!(msg.contains("CON"), "{msg}");
        assert!(msg.contains("bad name"), "{msg}");
    }
}
