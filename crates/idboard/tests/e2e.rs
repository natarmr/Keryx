//! End-to-end tests: real binaries, real sockets, real signatures.
//!
//! These drive the shipped `keryx` and `keryxd` executables. Nothing is
//! stubbed, because the properties under test are exactly the ones a unit test
//! with an injected clock and an in-memory store would paper over.
//!
//! # How the tests attack the board
//!
//! Two different routes, on purpose:
//!
//! - **As a legitimate agent.** Spawn `keryx run --identity X -- keryx post
//!   ...`, which is the supported path, and check what the board records.
//! - **As an attacker.** The test holds the private keys (it generated them) and
//!   the daemon socket path (it chose the path), so it can put arbitrary bytes
//!   on the wire: forged senders, replayed envelopes, tampered bodies, and
//!   signatures from the wrong key. This is the same capability the local-socket
//!   non-goal grants any same-user process, so it is the honest upper bound.
//!
//! Every rejection is asserted as a *specific* [`ErrorCode`], never merely "not
//! ok". A test that accepts any failure proves nothing about which defence fired.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use idboard_core::envelope::Provenance;
use idboard_core::error::ErrorCode;
use idboard_core::keys::LocalSigner;
use idboard_core::wire::{DaemonRequest, DaemonResponse};
use idboard_core::{PROTOCOL_VERSION, layout};
use idboard_ipc::IpcError;

/// Path to a sibling binary in `target/debug`, derived from the test executable.
///
/// `env!("CARGO_BIN_EXE_keryx")` only works for the package that owns the bin,
/// and these tests need `keryxd` too, which is a different package.
fn sibling_bin(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("test exe path");
    // target/debug/deps/<test-bin>.exe -> target/debug/<name>.exe
    let dir = exe.parent().and_then(|p| p.parent()).expect("target/debug");
    let path = dir.join(format!("{name}.exe"));
    assert!(path.exists(), "{} not built; run `cargo build` first", path.display());
    path
}

/// A running daemon, a config, and a keystore, all in a temp directory.
struct TestBoard {
    home: tempfile::TempDir,
    socket: PathBuf,
    db: PathBuf,
    config: PathBuf,
    daemon: Option<Child>,
    /// Captured daemon stderr, for asserting on rejections.
    log: PathBuf,
}

/// The default config used by most tests: one open channel, one restricted one.
const CONFIG_TEMPLATE: &str = r#"
[identity.eng-01]
role = "engineer"
pubkey = "{eng01}"

[identity.eng-02]
role = "engineer"
pubkey = "{eng02}"

[identity.lead]
role = "lead"
pubkey = "{lead}"

[channel.general]
post = ["*"]
read = ["*"]

[channel.deploy-approvals]
post = ["lead"]
read = ["*"]
"#;

impl TestBoard {
    /// Start a daemon with the default identities and channels.
    fn start() -> Self {
        let home = tempfile::tempdir().expect("tempdir");
        let socket = unique_socket();
        let db = home.path().join("board.db");
        let config = home.path().join("config.toml");
        let log = home.path().join("daemon.log");

        let mut board = Self { home, socket, db, config, daemon: None, log };
        let keys = board.generate_keys(&["eng-01", "eng-02", "lead"]);
        std::fs::write(
            &board.config,
            CONFIG_TEMPLATE
                .replace("{eng01}", &keys["eng-01"])
                .replace("{eng02}", &keys["eng-02"])
                .replace("{lead}", &keys["lead"]),
        )
        .expect("write config");
        board.spawn_daemon();
        board
    }

    /// Run `keryx keygen` for each identity, returning identity -> pubkey.
    fn generate_keys(&self, identities: &[&str]) -> std::collections::HashMap<String, String> {
        let mut out = std::collections::HashMap::new();
        for id in identities {
            let out_cmd = self.keryx(&["keygen", id, "--pubkey-only"]);
            let stdout = String::from_utf8_lossy(&out_cmd.stdout).trim().to_string();
            assert_eq!(out_cmd.status.code(), Some(0), "keygen {id} failed: {out_cmd:?}");
            assert_eq!(stdout.len(), 64, "pubkey for {id} should be 64 hex chars, got {stdout:?}");
            out.insert((*id).to_string(), stdout);
        }
        out
    }

    fn env(&self) -> Vec<(String, String)> {
        vec![
            (layout::ENV_HOME.into(), self.home.path().display().to_string()),
            (layout::ENV_DAEMON.into(), self.socket.display().to_string()),
            (layout::ENV_CONFIG.into(), self.config.display().to_string()),
            ("KERYX_CURSOR_HOME".into(), self.home.path().join("keryx-cursors").display().to_string()),
        ]
    }

    /// Run the `keryx` CLI directly, outside any wrapper.
    fn keryx(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(sibling_bin("keryx"));
        cmd.args(args);
        for (k, v) in self.env() {
            cmd.env(k, v);
        }
        cmd.output().expect("run keryx")
    }

    /// Run the CLI as `identity`, through the wrapper. This is the supported path.
    fn as_identity(&self, identity: &str, args: &[&str]) -> Output {
        let mut cmd = Command::new(sibling_bin("keryx"));
        cmd.arg("run").arg("--identity").arg(identity).arg("--");
        cmd.arg(sibling_bin("keryx"));
        cmd.args(args);
        for (k, v) in self.env() {
            cmd.env(k, v);
        }
        cmd.output().expect("run keryx run")
    }

    fn post(&self, identity: &str, channel: &str, body: &str) -> Output {
        self.as_identity(identity, &["post", channel, body])
    }

    fn read(&self, identity: &str, channel: &str, since: &str) -> Output {
        self.as_identity(identity, &["read", channel, "--since", since, "--json"])
    }

    /// Speak to the daemon directly, as an attacker with the keys would.
    fn daemon_raw(&self, req: &DaemonRequest) -> Result<DaemonResponse, IpcError> {
        idboard_ipc::round_trip(&self.socket, req)
    }

    /// Sign a request with a given identity, as the wrapper would.
    fn signed_post(&self, identity: &str, channel: &str, body: &str, seq: i64) -> DaemonRequest {
        let signer = self.signer(identity);
        DaemonRequest {
            v: PROTOCOL_VERSION,
            envelope: signer
                .sign_post(channel, body, Provenance::SelfOriginated, seq, idboard_core::now_ms())
                .expect("sign"),
            since: 0,
            limit: 100,
        }
    }

    /// Load an identity's key out of the test's own keystore.
    fn signer(&self, identity: &str) -> LocalSigner {
        let bytes = std::fs::read(self.home.path().join("keys").join(format!("{identity}.key")))
            .unwrap_or_else(|e| panic!("no key for {identity}: {e}"));
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        LocalSigner::from_seed(&seed, identity).expect("signer")
    }

    fn spawn_daemon(&mut self) {
        let log = std::fs::File::create(&self.log).expect("create log");
        let err = log.try_clone().expect("clone log");
        let mut cmd = Command::new(sibling_bin("keryxd"));
        cmd.arg("--config").arg(&self.config);
        cmd.arg("--socket").arg(&self.socket);
        cmd.arg("--db").arg(&self.db);
        for (k, v) in self.env() {
            cmd.env(k, v);
        }
        let child = cmd
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("spawn keryxd");
        self.daemon = Some(child);
        self.wait_until_listening();
    }

    fn wait_until_listening(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if idboard_ipc::connect(&self.socket).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!(
            "keryxd did not start listening on {}\n--- log ---\n{}",
            self.socket.display(),
            self.daemon_log()
        );
    }

    fn daemon_log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The identity of every message in a channel, in order.
    ///
    /// Reads as `eng-02`, a bystander, because several tests deliberately break
    /// `eng-01` (rotating its key, and so on) and the observer must keep working
    /// when they do. Both channels in the test config are readable by anyone.
    fn senders(&self, channel: &str) -> Vec<String> {
        messages_of(&self.read("eng-02", channel, "0"))
            .iter()
            .filter_map(|m| m.get("sender_id").and_then(|v| v.as_str()).map(str::to_string))
            .collect()
    }
}

/// Parse the messages out of a `read --json` response.
///
/// Handed back as `serde_json::Value` rather than `StoredMessage` so assertions
/// can address wire fields directly, which is what these tests are about.
fn messages(stdout: &[u8]) -> Vec<serde_json::Value> {
    let res: DaemonResponse = serde_json::from_slice(stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not a DaemonResponse JSON ({e})\nstdout: {}",
            String::from_utf8_lossy(stdout)
        )
    });
    res.messages
        .into_iter()
        .map(|m| serde_json::to_value(m).expect("StoredMessage serialises"))
        .collect()
}

/// Parse the messages out of a completed command's stdout.
fn messages_of(out: &Output) -> Vec<serde_json::Value> {
    messages(&out.stdout)
}

/// A unique socket name for one test.
///
/// The counter is essential. An earlier version derived the name from the test
/// thread's id, which the harness recycles, so a later test could collide with a
/// daemon an earlier test had leaked. Since the daemon refuses to displace a live
/// one, that turned into a hang rather than a clean failure. A monotonic counter
/// plus the pid cannot collide within a run, and a fresh pid separates runs.
fn unique_socket() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if cfg!(windows) {
        PathBuf::from(format!(r"\\.\pipe\idboard-test-{}-{n}", std::process::id()))
    } else {
        std::env::temp_dir().join(format!("keryx-test-{}-{n}.sock", std::process::id()))
    }
}

fn code_of(res: &DaemonResponse) -> ErrorCode {
    res.error.expect("expected an error code, request succeeded")
}

// ---------------------------------------------------------------------------
// The headline requirement
// ---------------------------------------------------------------------------

/// Two subprocesses posting to one channel are recorded as two identities.
#[test]
fn two_harnesses_post_to_one_channel_and_are_distinguished() {
    let b = TestBoard::start();

    let a = b.post("eng-01", "general", "message from the first agent");
    assert_eq!(a.status.code(), Some(0), "post 1 failed: {a:?}");

    let c = b.post("lead", "general", "message from the second agent");
    assert_eq!(c.status.code(), Some(0), "post 2 failed: {c:?}");

    assert_eq!(b.senders("general"), ["eng-01", "lead"]);

    // And the bodies are intact, so nothing was crossed on the way through.
    let msgs = messages_of(&b.read("eng-01", "general", "0"));
    let bodies: Vec<&str> = msgs.iter().filter_map(|m| m["body"].as_str()).collect();
    assert_eq!(bodies, ["message from the first agent", "message from the second agent"]);
}

/// The one the plan actually asks for: one process tries to forge the other and
/// is rejected, with nothing attributed to the victim.
#[test]
fn a_process_cannot_forge_another_identity_through_the_daemon() {
    let b = TestBoard::start();
    assert_eq!(b.post("eng-01", "general", "honest message").status.code(), Some(0));

    // eng-01's key, but claiming to be lead, and borrowing lead's fingerprint,
    // which is public information.
    let mut forged = b.signed_post("eng-01", "general", "trust me, this is the lead", 2);
    forged.envelope.sender_id = "lead".into();
    forged.envelope.sender_pubkey_fp = b.signer("lead").fingerprint().to_string();

    let res = b.daemon_raw(&forged).expect("daemon reachable");
    assert!(!res.ok);
    assert_eq!(code_of(&res), ErrorCode::BadSignature, "response: {res:?}");

    // Nothing was attributed to lead, and nothing extra was stored.
    assert_eq!(b.senders("general"), ["eng-01"]);
    assert!(
        b.daemon_log().contains("bad_signature"),
        "the daemon should log the rejection with a code:\n{}",
        b.daemon_log()
    );
}

// ---------------------------------------------------------------------------
// Replay and tampering, straight at the daemon
// ---------------------------------------------------------------------------

#[test]
fn a_replayed_envelope_is_rejected_even_though_the_signature_is_valid() {
    let b = TestBoard::start();
    let captured = b.signed_post("eng-01", "general", "transfer 100 units", 1);

    let first = b.daemon_raw(&captured).expect("first send");
    assert!(first.ok, "{first:?}");

    let replay = b.daemon_raw(&captured).expect("replay send");
    assert_eq!(code_of(&replay), ErrorCode::Replay, "response: {replay:?}");

    assert_eq!(b.senders("general"), ["eng-01"], "the replay must not be stored");
}

#[test]
fn a_tampered_body_is_rejected() {
    let b = TestBoard::start();
    let mut req = b.signed_post("eng-01", "general", "ship it", 1);
    req.envelope.body = "ship it, and also disable the tests".into();

    let res = b.daemon_raw(&req).expect("daemon reachable");
    assert_eq!(code_of(&res), ErrorCode::BadSignature, "response: {res:?}");
    assert!(b.senders("general").is_empty());
}

#[test]
fn a_signature_from_the_wrong_key_is_rejected() {
    let b = TestBoard::start();
    // A key nobody registered, claiming to be the lead.
    let stranger = LocalSigner::generate("lead").expect("keygen").0;
    let mut env = stranger
        .sign_post("deploy-approvals", "approved", Provenance::SelfOriginated, 1, idboard_core::now_ms())
        .expect("sign");
    env.sender_pubkey_fp = b.signer("lead").fingerprint().to_string();

    let res = b
        .daemon_raw(&DaemonRequest { v: PROTOCOL_VERSION, envelope: env, since: 0, limit: 0 })
        .expect("daemon reachable");
    assert_eq!(code_of(&res), ErrorCode::BadSignature, "response: {res:?}");
    assert!(b.senders("deploy-approvals").is_empty());
}

#[test]
fn an_unregistered_identity_is_refused() {
    let b = TestBoard::start();
    let stranger = LocalSigner::generate("intruder").expect("keygen").0;
    let env = stranger
        .sign_post("general", "let me in", Provenance::SelfOriginated, 1, idboard_core::now_ms())
        .expect("sign");

    let res = b
        .daemon_raw(&DaemonRequest { v: PROTOCOL_VERSION, envelope: env, since: 0, limit: 0 })
        .expect("daemon reachable");
    assert_eq!(code_of(&res), ErrorCode::UnknownIdentity, "response: {res:?}");
}

// ---------------------------------------------------------------------------
// ACLs
// ---------------------------------------------------------------------------

#[test]
fn a_verified_identity_without_permission_is_refused() {
    let b = TestBoard::start();
    let out = b.post("eng-01", "deploy-approvals", "shipping to prod");
    assert_ne!(out.status.code(), Some(0), "posting to a restricted channel should fail: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unauthorized"), "stderr: {stderr}");
    // The message names the *verified* identity, which is the whole point.
    assert!(stderr.contains("eng-01"), "stderr should name the verified identity: {stderr}");
    assert!(b.senders("deploy-approvals").is_empty());

    // The lead can.
    assert_eq!(b.post("lead", "deploy-approvals", "approved").status.code(), Some(0));
    assert_eq!(b.senders("deploy-approvals"), ["lead"]);
}

#[test]
fn an_unknown_channel_is_distinguished_from_a_forbidden_one() {
    let b = TestBoard::start();
    let out = b.post("eng-01", "no-such-channel", "hi");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown_channel"), "stderr: {stderr}");
}

#[test]
fn reads_are_also_authorised() {
    // A config whose only channel denies reads, so the read ACL is what rejects.
    let mut b = TestBoard::start();
    let keys = b.generate_keys(&["eng-01"]);
    std::fs::write(
        &b.config,
        format!(
            "[identity.eng-01]\npubkey = \"{k}\"\n[channel.locked]\npost = [\"eng-01\"]\nread = []\n",
            k = keys["eng-01"]
        ),
    )
    .unwrap();
    b.restart_daemon();

    // Posting to it is allowed.
    assert_eq!(b.post("eng-01", "locked", "mine").status.code(), Some(0));

    // Reading it is not, and the refusal names the verified identity.
    let out = b.as_identity("eng-01", &["read", "locked", "--since", "0"]);
    assert_ne!(out.status.code(), Some(0), "read should be denied: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unauthorized"), "stderr: {stderr}");
    assert!(stderr.contains("eng-01"), "stderr should name the verified identity: {stderr}");
}

// ---------------------------------------------------------------------------
// The wrapper's guarantees
// ---------------------------------------------------------------------------

/// The CLI refuses to act when it was not launched by the wrapper.
///
/// This is the structural half of the design: with no relay there is no path to
/// the board, so an agent cannot work around the wrapper by talking to the
/// daemon directly.
#[test]
fn the_cli_refuses_to_act_outside_a_wrapper() {
    let b = TestBoard::start();
    for args in [
        vec!["post", "general", "hello"],
        vec!["read", "general", "--since", "0"],
        vec!["whoami"],
    ] {
        // Deliberately no IDBOARD_RELAY / IDBOARD_TOKEN, even though the daemon
        // socket is known and reachable.
        let out = b.keryx(&args);
        assert_ne!(out.status.code(), Some(0), "{args:?} should fail: {out:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("keryx run"), "{args:?} stderr should name the wrapper: {stderr}");
    }
    assert!(b.senders("general").is_empty(), "nothing may reach the board");
}

#[test]
fn whoami_reports_the_launching_identity() {
    let b = TestBoard::start();
    let out = b.as_identity("eng-02", &["--json", "whoami"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("whoami json");
    assert_eq!(v["identity"], "eng-02");
    assert_eq!(v["fingerprint"], b.signer("eng-02").fingerprint());
}

#[test]
fn a_second_wrapper_for_a_live_identity_is_refused() {
    let b = TestBoard::start();

    // A long-lived child, so the first wrapper is still holding the identity.
    let mut first = Command::new(sibling_bin("keryx"));
    first
        .arg("run")
        .arg("--identity")
        .arg("eng-01")
        .arg("--")
        .arg(sibling_bin("keryx"))
        .args(["subscribe", "general", "--interval-ms", "50"]);
    for (k, v) in b.env() {
        first.env(k, v);
    }
    let mut first = first.spawn().expect("spawn first wrapper");
    std::thread::sleep(Duration::from_millis(1500));

    let second = b.as_identity("eng-01", &["post", "general", "from the second wrapper"]);
    assert_eq!(second.status.code(), Some(2), "expected the lock exit code: {second:?}");
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(stderr.contains("already in use"), "stderr: {stderr}");

    let _ = first.kill();
    let _ = first.wait();
}

#[test]
fn a_rotated_keystore_is_caught_before_the_child_starts() {
    let b = TestBoard::start();

    // Replace the key on disk, leaving the config pointing at the old one.
    let (new_signer, seed) = LocalSigner::generate("eng-01").expect("keygen");
    std::fs::write(b.home.path().join("keys").join("eng-01.key"), seed).unwrap();

    let out = b.post("eng-01", "general", "should not work");
    assert_eq!(out.status.code(), Some(4), "expected the key-mismatch exit code: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("does not match"), "stderr: {stderr}");
    assert!(b.senders("general").is_empty());

    // The two fingerprints are genuinely different, so this is not a false alarm.
    assert_ne!(new_signer.fingerprint(), b.signer("lead").fingerprint());
}

#[test]
fn an_identity_absent_from_the_config_is_refused_with_the_fix() {
    let b = TestBoard::start();
    let out = b.as_identity("never-registered", &["post", "general", "hi"]);
    assert_eq!(out.status.code(), Some(3), "expected the not-in-config exit code: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("keryx keygen never-registered"), "stderr: {stderr}");
}

#[test]
fn an_unreachable_daemon_is_reported_clearly() {
    let b = TestBoard::start();
    let missing = unique_socket();
    let mut cmd = Command::new(sibling_bin("keryx"));
    cmd.args(["run", "--identity", "eng-01", "--"]).arg(sibling_bin("keryx")).arg("whoami");
    for (k, v) in b.env() {
        cmd.env(k, v);
    }
    cmd.env(layout::ENV_DAEMON, missing);
    let out = cmd.output().expect("run");
    assert_eq!(out.status.code(), Some(5), "expected the daemon-unreachable code: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("keryxd"), "stderr should say how to start it: {stderr}");
}

/// Killing a wrapper mid-flight must not damage the board for anyone else.
#[test]
fn killing_a_wrapper_leaves_the_board_usable() {
    let b = TestBoard::start();
    assert_eq!(b.post("eng-01", "general", "before the kill").status.code(), Some(0));

    let mut victim = Command::new(sibling_bin("keryx"));
    victim
        .arg("run")
        .arg("--identity")
        .arg("eng-02")
        .arg("--")
        .arg(sibling_bin("keryx"))
        .args(["subscribe", "general", "--interval-ms", "50"]);
    for (k, v) in b.env() {
        victim.env(k, v);
    }
    let mut victim = victim.spawn().expect("spawn");
    std::thread::sleep(Duration::from_millis(1200));

    victim.kill().expect("kill");
    victim.wait().expect("wait");

    // The survivor can still post, and the killed identity's lock is released.
    let after = b.post("eng-01", "general", "after the kill");
    assert_eq!(after.status.code(), Some(0), "{after:?}");

    // And the killed identity can be restarted, proving the lock was released.
    let restarted = b.as_identity("eng-02", &["post", "general", "back again"]);
    assert_eq!(restarted.status.code(), Some(0), "lock should be free after a kill: {restarted:?}");

    assert_eq!(b.senders("general"), ["eng-01", "eng-01", "eng-02"]);
}

// ---------------------------------------------------------------------------
// Board mechanics
// ---------------------------------------------------------------------------

#[test]
fn cursors_are_monotonic_across_identities() {
    let b = TestBoard::start();
    for (identity, n) in [("eng-01", 3), ("lead", 3), ("eng-02", 2)] {
        for i in 0..n {
            let out = b.post(identity, "general", &format!("{identity} {i}"));
            assert_eq!(out.status.code(), Some(0), "{out:?}");
        }
    }
    let msgs = messages_of(&b.read("eng-01", "general", "0"));
    let cursors: Vec<i64> = msgs.iter().filter_map(|m| m["cursor"].as_i64()).collect();
    assert_eq!(cursors.len(), 8);
    assert!(cursors.windows(2).all(|w| w[0] < w[1]), "cursors must strictly increase: {cursors:?}");

    // Resuming from a cursor returns exactly the tail.
    let cut = cursors[4];
    let tail = messages_of(&b.read("eng-01", "general", &cut.to_string()));
    assert_eq!(tail.len(), 3);
    assert_eq!(tail[0]["cursor"].as_i64(), Some(cut + 1));
}

#[test]
fn a_sequence_number_is_not_reusable_across_restarts_of_the_wrapper() {
    let b = TestBoard::start();
    assert_eq!(b.post("eng-01", "general", "one").status.code(), Some(0));
    assert_eq!(b.post("eng-01", "general", "two").status.code(), Some(0));

    // Each `keryx run` is a fresh wrapper, so each resumes from the daemon's
    // high-water mark rather than restarting at 1.
    assert_eq!(b.post("eng-01", "general", "three").status.code(), Some(0));
    assert_eq!(b.post("eng-01", "general", "four").status.code(), Some(0));

    let msgs = messages_of(&b.read("eng-01", "general", "0"));
    let seqs: Vec<i64> = msgs.iter().filter_map(|m| m["seq"].as_i64()).collect();
    assert_eq!(seqs, [1, 2, 3, 4], "the counter must resume, not rewind");
}

#[test]
fn the_board_survives_a_daemon_restart() {
    let mut b = TestBoard::start();
    assert_eq!(b.post("eng-01", "general", "before restart").status.code(), Some(0));
    assert_eq!(b.post("eng-01", "general", "also before").status.code(), Some(0));

    b.restart_daemon();

    assert_eq!(b.post("eng-01", "general", "after restart").status.code(), Some(0));
    let msgs = messages_of(&b.read("eng-01", "general", "0"));
    let seqs: Vec<i64> = msgs.iter().filter_map(|m| m["seq"].as_i64()).collect();
    assert_eq!(seqs, [1, 2, 3], "the counter must survive a restart: {seqs:?}");
    assert_eq!(msgs.len(), 3);
}

#[test]
fn provenance_is_carried_through_to_readers() {
    let b = TestBoard::start();
    assert_eq!(b.as_identity("eng-01", &["post", "general", "my own conclusion", "--provenance", "self"]).status.code(), Some(0));
    assert_eq!(b.as_identity("eng-01", &["post", "general", "text copied from a page", "--provenance", "external"]).status.code(), Some(0));

    let msgs = messages_of(&b.read("eng-01", "general", "0"));
    let provs: Vec<&str> = msgs.iter().filter_map(|m| m["provenance"].as_str()).collect();
    assert_eq!(provs, ["self", "external"]);

    // And the text output marks it, so a reader can see the distinction today
    // even though nothing enforces it.
    let text = b.as_identity("eng-02", &["read", "general", "--since", "0"]);
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(stdout.contains("[external]"), "external provenance should be visible: {stdout}");
}

#[test]
fn a_second_daemon_cannot_displace_a_live_one() {
    let b = TestBoard::start();
    let mut second = Command::new(sibling_bin("keryxd"));
    second.arg("--config").arg(&b.config).arg("--socket").arg(&b.socket).arg("--db").arg(&b.db);
    for (k, v) in b.env() {
        second.env(k, v);
    }
    let out = second.output().expect("run second daemon");
    assert_ne!(out.status.code(), Some(0), "a second daemon must not silently take over");
    // And the original is still serving.
    assert_eq!(b.post("eng-01", "general", "still here").status.code(), Some(0));
}

/// Spawn a wrapper with its relay socket and token pinned, so the test can talk
/// to the relay directly.
///
/// This drives `run_child` from the library rather than the `keryx` binary,
/// which is the only way to learn the socket path and token without adding a
/// subcommand whose entire purpose would be to print a credential to whatever
/// process asked. The child is a `subscribe`, so the wrapper stays up while the
/// test probes.
///
/// `--count` is deliberately far above the number of messages any test posts.
/// It used to be 1, which only kept the wrapper alive because `subscribe` had a
/// cursor bug and never saw a message at all — so its "long-running child"
/// was an accident of the bug, and fixing the bug made the wrapper exit the
/// moment a test posted one. A probe harness that depends on a defect in the
/// thing under test is not a probe harness.
struct PinnedWrapper {
    handle: Option<std::thread::JoinHandle<i32>>,
    relay: PathBuf,
    token: String,
}

impl TestBoard {
    fn start_pinned_wrapper(&self, identity: &str) -> PinnedWrapper {
        let identity = identity.to_string();
        let relay = unique_socket();
        let token = "0123456789abcdef".repeat(4); // 64 hex chars, as a real one is

        let mut opts = idboard::wrapper::WrapperOptions::new(
            &identity,
            vec![
                sibling_bin("keryx").display().to_string(),
                "subscribe".into(),
                "general".into(),
                "--interval-ms".into(),
                "100".into(),
                "--count".into(),
                "999".into(),
            ],
        );
        opts.config_path = self.config.clone();
        opts.daemon_socket = self.socket.clone();
        opts.keystore = idboard::keystore::Keystore::at(self.home.path().join("keys"));
        opts.lock_path = Some(self.home.path().join("run").join(format!("{identity}.lock")));
        opts.relay_path = Some(relay.clone());
        opts.token = Some(token.clone());

        let handle = std::thread::spawn(move || match idboard::wrapper::run_child(&opts) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("pinned wrapper for {identity} failed to start: {e}");                -1
            }
        });

        // Wait for the relay to come up, then give the child time to complete its
        // initial read. The wrapper binds the socket *before* spawning the child,
        // so a successful connect does not yet mean the child is polling, and a
        // message posted in that gap would be missed by the subscriber.
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if idboard_ipc::connect(&relay).is_ok() {
                std::thread::sleep(Duration::from_millis(400));
                return PinnedWrapper { handle: Some(handle), relay, token };
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("the pinned wrapper never bound {}", relay.display());
    }
}

impl Drop for PinnedWrapper {
    /// The child is a `subscribe --count 1`, so it exits once the test's single
    /// legitimate post lands, which lets the wrapper return and this thread join.
    /// A generous timeout keeps a failing assertion from hanging the suite on a
    /// join that can never complete.
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !handle.is_finished() {
                if Instant::now() > deadline {
                    return;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            let _ = handle.join();
        }
        let _ = &self.token;
    }
}

impl TestBoard {
    /// Stop the daemon and start a new one against the same database.
    fn restart_daemon(&mut self) {
        self.kill_daemon();
        self.spawn_daemon();
    }

    fn kill_daemon(&mut self) {
        if let Some(mut d) = self.daemon.take() {
            let _ = d.kill();
            let _ = d.wait();
        }
    }
}

impl Drop for TestBoard {
    /// Reap the daemon.
    ///
    /// Without this the suite leaks one daemon per test. On Windows a child
    /// process is not terminated when its parent exits, so the leak outlives the
    /// test run entirely and the next run collides with the last.
    fn drop(&mut self) {
        self.kill_daemon();
    }
}

/// Send a raw relay request and read the reply.
///
/// Takes a `serde_json::Value` rather than a typed request on purpose: the test
/// needs to put fields on the wire that `RelayRequest` has no slot for, which is
/// the whole point of the forgery test.
fn relay_call(relay: &Path, req: &serde_json::Value) -> DaemonResponse {
    let mut writer = idboard_ipc::connect(relay).expect("connect to relay");
    let reader = idboard_ipc::split(&writer).expect("split");
    let mut reader = std::io::BufReader::new(reader);
    idboard_ipc::write_frame(&mut writer, req).expect("write request");
    idboard_ipc::read_frame_from::<DaemonResponse, _>(&mut reader)
        .expect("read reply")
        .expect("reply should be present")
}

/// The relay is the wrapper's front door, and its token is the only thing
/// standing between a local process and messages signed as somebody's identity.
#[test]
fn the_relay_refuses_a_request_without_its_token() {
    let b = TestBoard::start();
    let w = b.start_pinned_wrapper("eng-01");

    // A missing token field makes the request structurally invalid, so it never
    // reaches the token comparison. A token that is present but wrong does, and
    // is refused as unauthorised. Both are refused, for different reasons, and
    // the distinction is worth asserting rather than collapsing into "not ok".
    let cases: Vec<(serde_json::Value, ErrorCode)> = vec![
        (
            serde_json::json!({ "op": "post", "v": 1, "channel": "general", "body": "no token", "provenance": "self" }),
            ErrorCode::BadRequest,
        ),
        (
            serde_json::json!({ "op": "post", "v": 1, "token": "wrong", "channel": "general", "body": "bad token", "provenance": "self" }),
            ErrorCode::Unauthorized,
        ),
        // A prefix of the real token must not be accepted either.
        (
            serde_json::json!({ "op": "post", "v": 1, "token": w.token[..62], "channel": "general", "body": "prefix", "provenance": "self" }),
            ErrorCode::Unauthorized,
        ),
        // And neither does a token for a different, equally long, value.
        (
            serde_json::json!({ "op": "post", "v": 1, "token": "f".repeat(64), "channel": "general", "body": "other", "provenance": "self" }),
            ErrorCode::Unauthorized,
        ),
    ];
    for (req, expected) in cases {
        let res = relay_call(&w.relay, &req);
        assert!(!res.ok, "should have been refused: {res:?}");
        assert_eq!(res.error, Some(expected), "request: {req}");
    }

    // Nothing reached the board.
    assert!(b.senders("general").is_empty());

    // And the real token is accepted, proving the refusals above were about the
    // token rather than the request being malformed.
    let good = serde_json::json!({
        "op": "post", "v": 1, "token": w.token, "channel": "general",
        "body": "with the right token", "provenance": "self"
    });
    let res = relay_call(&w.relay, &good);
    assert!(res.ok, "the correct token should be accepted: {res:?}");
    assert_eq!(b.senders("general"), ["eng-01"]);
    let _ = w.handle;
}

/// A child that knows the relay token still cannot choose who it is.
///
/// `RelayRequest` has no field for a sender, so injected identity fields are
/// dropped during parsing and the wrapper signs the message as the identity it
/// was launched with. This is the structural half of the design: a compromised
/// agent with a valid token can post freely, but only ever as itself.
#[test]
fn a_child_with_a_valid_token_still_cannot_choose_its_identity() {
    let b = TestBoard::start();
    let w = b.start_pinned_wrapper("eng-01");

    // Every identity-bearing field an attacker might try to inject, all at once.
    let spoof = serde_json::json!({
        "op": "post",
        "v": 1,
        "token": w.token,
        "channel": "general",
        "body": "this is really the lead",
        "provenance": "self",
        "sender_id": "lead",
        "sender_pubkey_fp": b.signer("lead").fingerprint(),
        "seq": 9999,
        "timestamp": 0,
        "signature": "deadbeef"
    });
    let res = relay_call(&w.relay, &spoof);
    assert!(res.ok, "the post itself is legitimate: {res:?}");

    // It landed as the launching identity, not as the injected one.
    assert_eq!(b.senders("general"), ["eng-01"], "the injected sender_id must be ignored");
    let msgs = messages_of(&b.read("eng-02", "general", "0"));
    assert_eq!(msgs[0]["sender_id"], "eng-01");
    assert_ne!(msgs[0]["sender_id"], "lead");
    // And the injected sequence number did not take effect either.
    assert_eq!(msgs[0]["seq"].as_i64(), Some(1), "the wrapper owns the counter");

    // A second post through the same relay must get seq 2, proving the wrapper
    // really is allocating and not just echoing what we sent.
    let again = serde_json::json!({
        "op": "post", "v": 1, "token": w.token, "channel": "general",
        "body": "second", "provenance": "self", "seq": 1
    });
    assert!(relay_call(&w.relay, &again).ok);
    let msgs = messages_of(&b.read("eng-02", "general", "0"));
    let seqs: Vec<i64> = msgs.iter().filter_map(|m| m["seq"].as_i64()).collect();
    assert_eq!(seqs, [1, 2], "the wrapper must own the sequence counter: {seqs:?}");
    let _ = w.handle;
}

/// A peer that connects to the daemon and then writes nothing must not withhold
/// the board from *other* identities.
///
/// The daemon has one `Mutex<Board>` for every identity on the machine, and the
/// worker used to take it *before* the first byte was read. So an unauthenticated
/// local process could open a pipe handle, send zero bytes, and stop every other
/// identity's requests from being dispatched — a cross-identity outage from one
/// connect and no crafted input at all. Windows named pipes carry no read
/// deadline, so the read that spans the guard has nothing to bound it.
///
/// The lock is now taken around `Board::handle` only. This is the observable
/// version of that claim.
///
/// Deliberately one stalled handle. The original analysis noted that taking the
/// whole pool needs several more connections and a full queue; that figure was
/// analytic, not observed, and testing it is not worth the machine time.
#[test]
fn a_peer_that_never_writes_cannot_withhold_the_board_from_other_identities() {
    let b = TestBoard::start();

    // A legitimate round trip first, so a later failure is about the stall and not
    // about the harness.
    assert!(b.post("eng-01", "general", "before").status.success());

    // Connect and send nothing. No key, no valid frame, nothing to forge.
    let stalled = idboard_ipc::connect(&b.socket).expect("an unauthenticated peer can connect");
    std::thread::sleep(Duration::from_millis(500));

    // A *different* identity must still be served while that handle is open.
    let res = b.post("eng-02", "general", "during");
    assert!(
        res.status.success(),
        "a second identity was blocked by an unrelated stalled connection: {res:?}"
    );
    assert_eq!(b.senders("general"), ["eng-01", "eng-02"]);

    // Closing the peer must also be harmless, and the board must still work.
    drop(stalled);
    assert!(b.post("eng-01", "general", "after").status.success());
    assert_eq!(b.senders("general"), ["eng-01", "eng-02", "eng-01"]);
}

/// The same failure on the relay, where it was worse: permanent, and it held the
/// identity lock.
///
/// `serve_one` runs synchronously in the wrapper's accept loop, so a process that
/// found the per-invocation relay pipe and never wrote stopped the wrapper
/// accepting, stopped it reaping the child, and kept the identity locked — for as
/// long as it cared to hold the handle. The token does not help, because the token
/// is checked *inside* the handler, which is only reached after a complete frame
/// arrives.
#[test]
fn a_peer_that_never_writes_to_the_relay_cannot_wedge_the_wrapper() {
    let b = TestBoard::start();
    let w = b.start_pinned_wrapper("eng-01");

    let stalled = idboard_ipc::connect(&w.relay).expect("a peer can connect to the relay");
    std::thread::sleep(Duration::from_millis(300));

    // The genuine child must still get served through the same relay.
    let res = relay_call(
        &w.relay,
        &serde_json::json!({
            "op": "post", "v": 1, "token": w.token, "channel": "general",
            "body": "the relay is still alive", "provenance": "self"
        }),
    );
    assert!(res.ok, "the wrapper was wedged by a stalled relay peer: {res:?}");
    assert_eq!(b.senders("general"), ["eng-01"]);

    drop(stalled);
}

/// A read page has to fit in one frame on one connection. A backlog larger than
/// the frame cap used to be unreadable rather than paged: the store built a
/// response the transport then refused to write.
///
/// Posted over the wire rather than through the CLI, because a 64 KiB body on a
/// command line exceeds the Windows command-line limit — which is a property of
/// `CreateProcess`, not of keryx, and would make this test fail for the wrong
/// reason.
#[test]
fn a_backlog_larger_than_one_frame_is_still_readable() {
    let b = TestBoard::start();

    // Comfortably past `MAX_FRAME_BYTES` once these land. Exactly at the body cap,
    // since one byte more is a `bad_request` before this test is about anything.
    let body = "z".repeat(64 * 1024);
    for seq in 1..=24i64 {
        let res = b
            .daemon_raw(&b.signed_post("eng-01", "general", &body, seq))
            .expect("a large post must be accepted");
        assert!(res.ok, "post {seq} was rejected: {res:?}");
    }

    // One read must not fail, even though the backlog exceeds a single frame.
    let out = b.read("eng-01", "general", "0");
    assert!(
        out.status.success(),
        "reading a large backlog failed outright: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let first_page = messages_of(&out);
    assert!(!first_page.is_empty(), "a large backlog returned nothing");
    assert!(first_page.len() < 24, "the page was not bounded: {} messages", first_page.len());

    // And it must be walkable: reading from where the first page stopped returns
    // more, rather than repeating or stalling.
    let cursor = first_page.last().unwrap()["cursor"].as_i64().unwrap();
    let next = messages_of(&b.read("eng-01", "general", &cursor.to_string()));
    assert!(!next.is_empty(), "the second page was empty; the backlog is unreadable");
    assert!(
        next[0]["cursor"].as_i64().unwrap() > cursor,
        "the second page did not advance past {cursor}"
    );
    // A message read back must still name the channel it was signed into.
    assert_eq!(first_page[0]["channel"], "general", "the read projection dropped the channel");
}


// ---------------------------------------------------------------------------
// MCP: the board as a tool list rather than a shell command.
// ---------------------------------------------------------------------------

/// A live `keryx mcp` process, driven over its stdio pipes.
///
/// The server reads one JSON-RPC line and writes one line per request, so the
/// helper reads a byte at a time rather than wrapping stdout in a `BufReader`:
/// a buffered reader would pull the *next* reply into a buffer this helper then
/// drops, which turns a protocol bug into a confusing partial read.
struct McpProcess {
    child: Child,
    line: Vec<u8>,
}

impl McpProcess {
    /// Spawn `keryx mcp`, either under the wrapper (with an identity) or bare.
    fn spawn(board: &TestBoard, identity: Option<&str>) -> Self {
        let mut cmd = Command::new(sibling_bin("keryx"));
        if let Some(name) = identity {
            cmd.arg("run").arg("--identity").arg(name).arg("--");
            cmd.arg(sibling_bin("keryx"));
        }
        cmd.arg("mcp");
        for (k, v) in board.env() {
            cmd.env(k, v);
        }
        let child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn keryx mcp");
        Self { child, line: Vec::new() }
    }

    fn send(&mut self, request: serde_json::Value) -> serde_json::Value {
        let stdin = self.child.stdin.as_mut().expect("the server must keep stdin open");
        writeln!(stdin, "{request}").expect("write an MCP request");
        stdin.flush().expect("flush an MCP request");

        let stdout = self.child.stdout.as_mut().expect("stdout");
        let mut byte = [0u8; 1];
        loop {
            let n = stdout.read(&mut byte).expect("read an MCP reply");
            assert_ne!(n, 0, "the MCP server closed stdout without replying");
            if byte[0] == b'\n' {
                break;
            }
            self.line.push(byte[0]);
        }
        let line = String::from_utf8(std::mem::take(&mut self.line)).expect("utf-8 reply");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("not one JSON object: {line:?}: {e}"))
    }

    fn call(&mut self, id: i64, tool: &str, arguments: serde_json::Value) -> serde_json::Value {
        self.send(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": tool, "arguments": arguments },
        }))
    }

    /// Close stdin and wait, so a leaked child cannot outlive the test.
    fn close(mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}

fn initialize_request() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "e2e", "version": "1" },
        },
    })
}

fn tool_text(response: &serde_json::Value) -> &str {
    response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("a tool result must carry text, got: {response}"))
}

#[test]
fn mcp_serves_the_wrappers_identity_and_the_board_tools() {
    let b = TestBoard::start();
    let mut mcp = McpProcess::spawn(&b, Some("eng-01"));

    let init = mcp.send(initialize_request());
    assert_eq!(init["result"]["serverInfo"]["name"], "keryx");

    let tools = mcp.send(serde_json::json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }));
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .expect("tools/list must return an array")
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["whoami", "post", "read", "inbox", "peers"]);

    let who = mcp.call(3, "whoami", serde_json::json!({}));
    assert_eq!(who["result"]["isError"], false);
    let text = tool_text(&who);
    assert!(text.contains("\"identity\":\"eng-01\""), "wrong identity over MCP: {text}");

    // `inbox` is the discovery call, so it has to work over MCP too: an agent
    // that can only post and read still cannot find out what exists.
    mcp.call(4, "post", serde_json::json!({ "channel": "general", "body": "seed" }));
    let inbox = mcp.call(5, "inbox", serde_json::json!({ "limit": 0 }));
    assert_eq!(inbox["result"]["isError"], false);
    let text = tool_text(&inbox);
    assert!(text.contains("\"channel\":\"general\""), "{text}");
    assert!(text.contains("\"can_post\":true"), "{text}");
    assert!(
        text.contains("\"channel\":\"deploy-approvals\""),
        "a readable channel the caller cannot post to must still be discoverable: {text}"
    );

    // `peers` is diagnostic only, but MCP-only agents still need the roster.
    let peers = mcp.call(6, "peers", serde_json::json!({}));
    assert_eq!(peers["result"]["isError"], false);
    let text = tool_text(&peers);
    let v: serde_json::Value = serde_json::from_str(text).expect("peers must return JSON");
    let list = v["peers"].as_array().expect("a peers array");
    for name in ["eng-01", "eng-02", "lead"] {
        assert!(list.iter().any(|p| p["identity"] == name), "{name} missing from MCP peers: {list:?}");
    }
    let eng = list.iter().find(|p| p["identity"] == "eng-01").unwrap();
    assert!(
        eng["last_seen_ms"].as_i64().unwrap() > 0,
        "the caller has acted and must be seen: {eng:?}"
    );

    mcp.close();
}

#[test]
fn a_post_made_through_mcp_is_signed_by_the_wrapper() {
    let b = TestBoard::start();
    let mut mcp = McpProcess::spawn(&b, Some("eng-01"));
    mcp.send(initialize_request());

    let posted = mcp.call(
        2,
        "post",
        serde_json::json!({ "channel": "general", "body": "posted over mcp", "provenance": "external" }),
    );
    assert_eq!(posted["result"]["isError"], false, "MCP post failed: {posted}");
    let cursor = serde_json::from_str::<serde_json::Value>(tool_text(&posted))
        .expect("the post result must be JSON")["cursor"]
        .as_i64()
        .expect("the post result must carry a cursor");

    // A caller cannot pick an identity, so the stored sender must be the one the
    // wrapper was launched with - and a different identity must see it.
    mcp.close();
    let out = b.read("eng-02", "general", "0");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let msgs = messages_of(&out);
    assert_eq!(msgs.len(), 1, "expected exactly one message, got: {msgs:?}");
    assert_eq!(msgs[0]["sender_id"], "eng-01");
    assert_eq!(msgs[0]["body"], "posted over mcp");
    assert_eq!(msgs[0]["provenance"], "external");
    assert_eq!(msgs[0]["cursor"], cursor);
}

/// Without the wrapper there is no identity, and that must surface as a tool
/// error the model can read - not as a server that fails to start, which a
/// harness reports as "MCP server broken" and which tells the model nothing.
#[test]
fn mcp_without_a_wrapper_starts_and_explains_the_missing_relay() {
    let b = TestBoard::start();
    let mut mcp = McpProcess::spawn(&b, None);

    let init = mcp.send(initialize_request());
    assert_eq!(init["result"]["serverInfo"]["name"], "keryx");

    let who = mcp.call(2, "whoami", serde_json::json!({}));
    assert!(who.get("error").is_none(), "a missing relay must not kill the server: {who}");
    assert_eq!(who["result"]["isError"], true);
    let text = tool_text(&who);
    assert!(text.contains("no keryx relay"), "unhelpful failure: {text}");
    assert!(text.contains("keryx run"), "the message must name the fix: {text}");

    mcp.close();
}

// ---------------------------------------------------------------------------
// Live harness conformance.
//
// The integration is harness-agnostic on purpose: `keryx run --identity X --
// <anything>` hands the child a relay and a token, and the child has no need to
// know what a harness is. These tests prove that for a *real* harness, not a
// stub, and are `#[ignore]`d because they need a model, a network, and money.
//
// Run with:  .\scripts\harness-smoke.ps1 -Harness opencode
// ---------------------------------------------------------------------------

/// Wait for a child to exit, but not forever. A harness that hangs is a test
/// failure, not a reason for the suite to stop responding.
fn wait_bounded(child: &mut Child, limit: Duration, what: &str) -> std::process::ExitStatus {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait on a live child") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what} did not finish within {}s and was killed", limit.as_secs());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn drain(child: &mut Child) -> (String, String) {
    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_string(&mut out);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    (out, err)
}

/// Run a prompt through a real harness under the wrapper and require that the
/// agent's post reached the board, signed by the wrapper's identity.
///
/// `argv` is the harness's own headless invocation. It is the only part that is
/// harness-specific; everything about identity, signing, and transport is
/// `keryx`'s and is identical for every harness.
fn live_harness_posts(harness: &str, argv: &[String], prompt: &str, nonce: &str) {
    let b = TestBoard::start();

    // The agent must be able to resolve `keryx` the way a real operator's
    // agent would, so put the built binary on PATH rather than relying on where
    // this test happens to live.
    let bin_dir = sibling_bin("keryx").parent().expect("target/debug").to_path_buf();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let joined = format!("{};{}", bin_dir.display(), path.to_string_lossy());

    let mut cmd = Command::new(sibling_bin("keryx"));
    cmd.arg("run").arg("--identity").arg("eng-01").arg("--");
    cmd.arg(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.arg(prompt);
    for (k, v) in b.env() {
        cmd.env(k, v);
    }
    cmd.env("PATH", joined);
    // A scratch directory, so the harness does not pick up this repository's
    // own AGENTS.md and follow a different set of instructions than the prompt.
    cmd.current_dir(b.home.path());
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn the harness under the wrapper");
    let status = wait_bounded(&mut child, Duration::from_secs(180), harness);
    let (stdout, stderr) = drain(&mut child);

    // The board is the authority. A model can say anything; a signed message is
    // the only claim this test accepts.
    let out = b.read("eng-02", "general", "0");
    let messages = messages_of(&out);
    let found = messages
        .iter()
        .find(|m| m["body"].as_str().is_some_and(|body| body.contains(nonce)));

    let Some(message) = found else {
        panic!(
            "{harness} finished ({status:?}) without a signed post carrying {nonce:?}.\n\
             --- harness stdout ---\n{stdout}\n--- harness stderr ---\n{stderr}\n\
             --- board ---\n{messages:#?}"
        );
    };

    // Printed for the operator running the live smoke; this is board data, not a
    // model self-report, so it is safe to quote in a local terminal.
    eprintln!(
        "board accepted live post from {} to {}: body={:?}",
        message["sender_id"], message["channel"], message["body"]
    );

    assert_eq!(
        message["sender_id"], "eng-01",
        "the harness posted under the wrong identity: {message:#?}"
    );
    assert_eq!(message["provenance"], "self");
    assert!(
        stdout.contains("eng-01"),
        "the agent never learned its identity; stdout was:\n{stdout}"
    );
}

fn live_nonce() -> String {
    format!("live-{}-{}", std::process::id(), idboard_core::now_ms())
}

fn live_prompt(nonce: &str) -> String {
    format!(
        "You are checking a local message bus. Do exactly this and nothing else:\n\
         1. Run the shell command `keryx whoami` and note the identity it prints.\n\
         2. Run `keryx post general \"{nonce} from <identity>\"`, replacing <identity> with the \
         identity from step 1 and keeping the nonce exactly as written.\n\
         3. Reply with one line: WHOAMI <identity>\n\
         Do not read or modify any files. Do not post more than once."
    )
}

/// A headless harness must be able to run the wrapper's child and inherit the
/// relay from its environment. Ignored on purpose: it needs a model, network
/// access, and possibly money. Drive it via `scripts\harness-smoke.ps1`.
#[test]
#[ignore = "spends model tokens; run scripts\\harness-smoke.ps1 -Harness opencode"]
fn opencode_posts_through_the_wrapper() {
    if std::env::var("IDBOARD_LIVE_HARNESS").ok().as_deref() != Some("opencode") {
        eprintln!("skipping: set IDBOARD_LIVE_HARNESS=opencode to run this");
        return;
    }

    // `opencode` on PATH is an npm shim (.cmd/.ps1), and `CreateProcess` cannot
    // run a shim. The script resolves the real executable and passes it here.
    let bin = std::env::var("IDBOARD_LIVE_HARNESS_BIN").unwrap_or_else(|_| "opencode".to_string());
    let nonce = live_nonce();
    let prompt = live_prompt(&nonce);

    // The model is an account property, not a property of keryx, and a free
    // model can be retired mid-week. With no model the harness picks its own
    // default, which may fail for reasons that have nothing to do with this
    // integration.
    let mut argv = vec![bin, "run".into(), "--auto".into(), "--format".into(), "json".into()];
    if let Ok(model) = std::env::var("IDBOARD_LIVE_HARNESS_MODEL") {
        if !model.is_empty() {
            argv.push("--model".into());
            argv.push(model);
        }
    }

    live_harness_posts("opencode", &argv, &prompt, &nonce);
}

/// `muse exec` is the headless path. `--yolo` disables approval and the sandbox
/// so the agent can run `keryx` inside the wrapper non-interactively; the
/// prompt still constrains what it is asked to do.
#[test]
#[ignore = "spends model tokens; run scripts\\harness-smoke.ps1 -Harness muse"]
fn muse_posts_through_the_wrapper() {
    if std::env::var("IDBOARD_LIVE_HARNESS").ok().as_deref() != Some("muse") {
        eprintln!("skipping: set IDBOARD_LIVE_HARNESS=muse to run this");
        return;
    }

    let bin = std::env::var("IDBOARD_LIVE_HARNESS_BIN").unwrap_or_else(|_| "muse".to_string());
    let nonce = live_nonce();
    let prompt = live_prompt(&nonce);

    let mut argv = vec![bin, "exec".into(), "--yolo".into()];
    if let Ok(model) = std::env::var("IDBOARD_LIVE_HARNESS_MODEL") {
        if !model.is_empty() {
            argv.push("--model".into());
            argv.push(model);
        }
    }

    live_harness_posts("muse", &argv, &prompt, &nonce);
}

// ---------------------------------------------------------------------------
// Discovery: inbox and peers.
// ---------------------------------------------------------------------------

#[test]
fn inbox_shows_the_newest_messages_and_flags_what_the_caller_may_post_to() {
    let b = TestBoard::start();
    for body in ["one", "two", "three"] {
        let out = b.post("eng-01", "general", body);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
    let out = b.post("lead", "deploy-approvals", "ship it");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let out = b.as_identity("eng-01", &["inbox", "--limit", "2", "--json"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("inbox --json must print JSON");
    let channels = v["channels"].as_array().expect("a channels array");

    let general = channels
        .iter()
        .find(|c| c["channel"] == "general")
        .expect("general must be in the digest");
    let bodies: Vec<&str> = general["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["body"].as_str().unwrap())
        .collect();
    assert_eq!(bodies, ["two", "three"], "the digest must be the newest page, oldest first");
    assert_eq!(general["can_post"], true);
    assert_eq!(general["cursor"], 3, "the cursor must point at the newest message");

    let approvals = channels
        .iter()
        .find(|c| c["channel"] == "deploy-approvals")
        .expect("a readable channel must appear even when the caller cannot post to it");
    assert_eq!(approvals["can_post"], false);
    assert_eq!(approvals["messages"][0]["body"], "ship it");

    // The text path is what an agent actually reads in a terminal.
    let text = b.as_identity("eng-01", &["inbox", "--limit", "0"]);
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(text.status.success(), "{}", String::from_utf8_lossy(&text.stderr));
    assert!(stdout.contains("== general == (read+post, cursor 3)"), "{stdout}");
    assert!(
        stdout.contains("== deploy-approvals == (read, cursor"),
        "a read-only channel must not claim post access: {stdout}"
    );
}

#[test]
fn peers_shows_the_roster_and_never_invents_presence() {
    let b = TestBoard::start();
    let out = b.post("eng-01", "general", "hello");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let out = b.as_identity("eng-01", &["peers", "--json"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("peers --json must print JSON");
    let peers = v["peers"].as_array().expect("a peers array");

    for name in ["eng-01", "eng-02", "lead"] {
        assert!(
            peers.iter().any(|p| p["identity"] == name),
            "{name} is registered and must be listed: {peers:?}"
        );
    }
    let eng = peers.iter().find(|p| p["identity"] == "eng-01").unwrap();
    assert!(eng["last_seen_ms"].as_i64().unwrap() > 0, "a poster is seen");

    let lead = peers.iter().find(|p| p["identity"] == "lead").unwrap();
    assert_eq!(
        lead["last_seen_ms"], 0,
        "an identity that has never acted must not be reported as seen"
    );

    let text = b.as_identity("eng-01", &["peers"]);
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(stdout.contains("never"), "the text path must say 'never', not a date: {stdout}");
}

/// Outside the wrapper there is no relay, and that is the documented answer for
/// every command, not a special case for the new ones.
#[test]
fn inbox_and_peers_are_inert_outside_a_wrapper() {
    let b = TestBoard::start();
    for args in [&["inbox"][..], &["peers"][..]] {
        let out = b.keryx(args);
        assert!(!out.status.success(), "{args:?} must fail without a relay");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("no keryx relay"), "{args:?}: {stderr}");
    }
}

#[test]
fn post_json_errors_include_actionable_machine_hints() {
    let b = TestBoard::start();

    let out = b.as_identity("eng-01", &["post", "deploy-approvals", "not allowed", "--json"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("post --json must print JSON");
    assert_eq!(v["error"], "unauthorized");
    assert!(v["hint"].as_str().unwrap().contains("acl") || v["hint"].as_str().unwrap().contains("grant"), "{v}");
    assert!(v["visible_channels"].as_array().is_some(), "{v}");

    let out = b.as_identity("eng-01", &["post", "genesral", "typo", "--json"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("post --json must print JSON");
    assert_eq!(v["error"], "unknown_channel");
    let closest = v["closest_channels"].as_array().expect("closest channel list");
    assert!(closest.iter().any(|n| n == "general"), "{closest:?}");
}

#[test]
fn task_create_claim_done_and_list_use_plain_board_messages() {
    let b = TestBoard::start();

    let out = b.as_identity("eng-01", &["task", "create", "general", "Investigate auth drift"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let posted = String::from_utf8_lossy(&out.stdout);
    let task_id = posted
        .split_whitespace()
        .find(|s| s.starts_with("t-"))
        .expect("task id is printed in the confirmation")
        .trim_end_matches(['\n', '"'])
        .to_string();

    let listed = b.as_identity("eng-01", &["task", "list", "general", "--json"]);
    assert!(listed.status.success(), "{}", String::from_utf8_lossy(&listed.stderr));
    let v: serde_json::Value = serde_json::from_slice(&listed.stdout).expect("task list --json must be JSON");
    assert!(v["tasks"].as_array().unwrap().iter().any(|t| t["title"] == "Investigate auth drift"));
    assert_eq!(v["tasks"][0]["done"], false);

    let claimed = b.as_identity("eng-01", &["task", "claim", "general", &task_id]);
    assert!(claimed.status.success(), "{}", String::from_utf8_lossy(&claimed.stderr));
    let listed = b.as_identity("eng-01", &["task", "list", "general", "--mine", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert!(v["tasks"].as_array().unwrap().iter().any(|t| t["claimed_by"] == "eng-01"));

    let done = b.as_identity("eng-01", &["task", "done", "general", &task_id]);
    assert!(done.status.success(), "{}", String::from_utf8_lossy(&done.stderr));
    let listed = b.as_identity("eng-01", &["task", "list", "general", "--all", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert!(v["tasks"].as_array().unwrap().iter().any(|t| t["done"] == true));
}

#[test]
fn task_next_and_complete_make_the_whole_agent_flow_one_step() {
    let b = TestBoard::start();

    let created = b.as_identity("eng-01", &["task", "create", "general", "UX console task"]);
    assert!(created.status.success(), "{}", String::from_utf8_lossy(&created.stderr));
    let created_out = String::from_utf8_lossy(&created.stdout);
    let task_id = created_out
        .split_whitespace()
        .find(|s| s.starts_with("t-"))
        .expect("task id")
        .trim_end_matches(['\n'])
        .to_string();

    let next = b.as_identity("eng-01", &["task", "next", "general"]);
    let stdout = String::from_utf8_lossy(&next.stdout);
    assert!(next.status.success(), "{}", String::from_utf8_lossy(&next.stderr));
    assert!(stdout.contains("task claim"), "{stdout}");

    let complete = b.as_identity("eng-01", &["task", "complete", "general", &task_id, "--body", "completed by agent"]);
    assert!(complete.status.success(), "{}", String::from_utf8_lossy(&complete.stderr));

    let listed = b.as_identity("eng-01", &["task", "list", "general", "--all", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    let tasks = v["tasks"].as_array().unwrap();
    assert!(tasks.iter().any(|t| t["id"] == task_id && t["done"] == true));

    let transcript_out = b.read("eng-01", "general", "0");
    let transcript = String::from_utf8_lossy(&transcript_out.stdout);
    assert!(transcript.contains("completed by agent"), "{transcript}");
}

#[test]
fn console_shows_local_and_board_state() {
    let b = TestBoard::start();

    let inside = b.as_identity("eng-01", &["console"]);
    let stdout = String::from_utf8_lossy(&inside.stdout);
    assert!(
        inside.status.success(),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&inside.stderr)
    );
    assert!(stdout.contains("keryx console: ok"), "{stdout}");
    assert!(stdout.contains("identity: eng-01"), "{stdout}");
    assert!(stdout.contains("tasks:"), "{stdout}");

    let outside = b.keryx(&["console"]);
    let stdout = String::from_utf8_lossy(&outside.stdout);
    assert!(outside.status.success(), "{}", String::from_utf8_lossy(&outside.stderr));
    assert!(stdout.contains("keryx console: ok"), "{stdout}");
    assert!(stdout.contains("board: unavailable outside"), "{stdout}");

    let inside_json = b.as_identity("eng-01", &["console", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&inside_json.stdout).expect("console --json must be JSON");
    assert_eq!(v["ok"], true);
    assert_eq!(v["report_version"], 1);
    assert!(v["board"]["available"].as_bool().unwrap());
}

#[test]
fn task_recovers_from_reopen_and_abandon_without_losing_the_board() {
    let b = TestBoard::start();

    let created = b.as_identity("eng-01", &["task", "create", "general", "recover me"]);
    let created_out = String::from_utf8_lossy(&created.stdout);
    let task_id = created_out
        .split_whitespace()
        .find(|s| s.starts_with("t-"))
        .expect("task id")
        .to_string();

    b.as_identity("eng-01", &["task", "claim", "general", &task_id]);
    b.as_identity("eng-01", &["task", "abandon", "general", &task_id]);

    let next = b.as_identity("eng-01", &["task", "next", "general"]);
    let stdout = String::from_utf8_lossy(&next.stdout);
    assert!(stdout.contains(&task_id), "abandoned tasks must return to the pool: {stdout}");

    b.as_identity("eng-01", &["task", "complete", "general", &task_id, "--body", "helped"]);
    let listed = b.as_identity("eng-01", &["task", "list", "general", "--all", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert!(v["tasks"].as_array().unwrap().iter().any(|t| t["id"] == task_id && t["done"] == true));

    b.as_identity("eng-01", &["task", "reopen", "general", &task_id]);
    let listed = b.as_identity("eng-01", &["task", "list", "general", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    let t = v["tasks"].as_array().unwrap().iter().find(|t| t["id"] == task_id).expect("task returned to the open list");
    assert_eq!(t["done"], false);
    assert!(t["claimed_by"].is_null());
}

#[test]
fn console_brief_reports_agents_and_recent_board_age() {
    let b = TestBoard::start();

    b.post("eng-01", "general", "context");
    b.as_identity("eng-01", &["task", "create", "general", "console task"]);
    b.as_identity("eng-02", &["task", "claim", "general", "console task-absent-id"]); // will fail, but does not disturb state

    let inside = b.as_identity("eng-01", &["console", "--brief"]);
    let stdout = String::from_utf8_lossy(&inside.stdout);
    assert!(inside.status.success(), "{}", String::from_utf8_lossy(&inside.stderr));
    assert!(stdout.contains("STATE="), "{stdout}");
    assert!(stdout.contains("tasks_open="), "{stdout}");
    assert!(stdout.contains("last_age="), "{stdout}");
}

#[test]
fn focus_reports_the_next_task_and_mixed_workload() {
    let b = TestBoard::start();

    b.as_identity("eng-01", &["task", "create", "general", "focus candidate"]);
    let out = b.as_identity("eng-01", &["focus"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("focus: eng-01"), "{stdout}");
    assert!(stdout.contains("your claimed tasks:"), "{stdout}");
    assert!(stdout.contains("recent messages"), "{stdout}");
}

#[test]
fn replay_shows_history_and_respects_cursor_resume() {
    let b = TestBoard::start();

    b.post("eng-01", "general", "first");
    b.post("eng-02", "general", "second");

    let first = b.as_identity("eng-01", &["replay", "general", "--save-cursor"]);
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert!(first.status.success(), "{}", String::from_utf8_lossy(&first.stderr));
    assert!(stdout.contains("first"));
    assert!(stdout.contains("second"));

    b.post("eng-01", "general", "after resume");
    let second = b.as_identity("eng-01", &["replay", "general", "--since-last"]);
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(second.status.success(), "{}", String::from_utf8_lossy(&second.stderr));
    assert!(stdout.contains("after resume"));
    assert!(!stdout.contains("first"));
    assert!(!stdout.contains("second"));
}

#[test]
fn mention_and_structured_subscribe_stops_on_json_field() {
    let b = TestBoard::start();

    let out = b.as_identity("eng-01", &["mention", "eng-02", "please review auth-42"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let out = b.as_identity("eng-02", &["post", "general", r#"{"kind":"done","id":"x"}"#]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let out = b.as_identity(
        "eng-01",
        &["subscribe", "general", "--since", "0", "--exit-on-json", "kind=done"],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("\"kind\":\"done\""), "{stdout}");
}

#[test]
fn cursor_commands_round_trip_a_saved_position() {
    let b = TestBoard::start();
    b.post("eng-01", "general", "for cursor commands");

    let set = b.as_identity("eng-01", &["cursor", "general", "--set", "1"]);
    assert!(set.status.success(), "{}", String::from_utf8_lossy(&set.stderr));

    let show = b.as_identity("eng-01", &["cursor", "general"]);
    let stdout = String::from_utf8_lossy(&show.stdout);
    assert!(show.status.success(), "{}", String::from_utf8_lossy(&show.stderr));
    assert!(stdout.contains("cursor[general] = 1"), "{stdout}");

    let clear = b.as_identity("eng-01", &["cursor", "general", "--clear"]);
    assert!(clear.status.success(), "{}", String::from_utf8_lossy(&clear.stderr));
}

#[test]
fn saving_and_resuming_a_cursor_is_idempotent() {
    let b = TestBoard::start();
    let out = b.post("eng-01", "general", "resume this cursor");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    // First call reads the existing message and records the position.
    let out = b.as_identity("eng-01", &["read", "general", "--since", "0", "--save-cursor"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    // Resuming from the saved position must not re-deliver it.
    let out = b.as_identity("eng-01", &["read", "general", "--since-last"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!stdout.contains("resume this cursor"), "cursor resume re-delivered old history: {stdout}");

    // A new post becomes visible to the resumed reader.
    let out = b.post("eng-02", "general", "after saved position");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let out = b.as_identity("eng-01", &["read", "general", "--since-last"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("after saved position"), "resumed read missed the new message: {stdout}");
}

#[test]
fn subscribe_exit_on_stops_after_a_matching_body() {
    let b = TestBoard::start();
    b.post("eng-01", "general", "start");
    b.post("eng-02", "general", "stop here");

    // `--since 0` starts from the beginning; the subscriber exits on the trigger.
    let out = b.as_identity(
        "eng-01",
        &["subscribe", "general", "--since", "0", "--exit-on", "stop here"],
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("stop here"));
}


#[test]
fn post_body_file_is_read_as_the_message_body() {
    let b = TestBoard::start();
    let body_path = b.home.path().join("body.txt");
    std::fs::write(&body_path, "body loaded from a file\nwith a newline").unwrap();

    let path = body_path.to_str().expect("temp paths are utf-8");
    let out = b.as_identity("eng-01", &["post", "general", "--body-file", path]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let out = b.read("eng-02", "general", "0");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(text.contains("body loaded from a file"), "{text}");
}

#[test]
fn doctor_reports_a_healthy_scratch_installation() {
    let b = TestBoard::start();
    let out = b.keryx(&["doctor"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "doctor reported failure:\n{stdout}\n{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("doctor: ok"), "{stdout}");
    assert!(stdout.contains("key:eng-01"), "{stdout}");
    assert!(stdout.contains("daemon-socket"), "{stdout}");
}

#[test]
fn doctor_json_uses_a_stable_report_shape() {
    let b = TestBoard::start();
    let out = b.keryx(&["doctor", "--json"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("doctor --json must be JSON");
    assert_eq!(v["ok"], true);
    assert_eq!(v["report_version"], 1);
    assert!(v["checks"].as_array().is_some());
    assert!(v["problems"].as_array().unwrap().is_empty());
}

#[test]
fn doctor_reports_a_missing_registered_key() {
    let b = TestBoard::start();
    std::fs::remove_file(b.home.path().join("keys").join("eng-01.key")).unwrap();

    let out = b.keryx(&["doctor"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "doctor must refuse an unusable install:\n{stdout}");
    assert!(!out.status.success());
    assert!(stdout.contains("eng-01"), "{stdout}");
}

/// The old binaries are kept as compatibility aliases during the rename.
#[test]
fn the_legacy_command_aliases_are_still_installed() {
    for (name, expected) in [("idboard", "keryx"), ("idboardd", "keryxd")] {
        let out = Command::new(sibling_bin(name)).arg("--version").output().expect("run compatibility binary");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{name} alias must run, got {out:?}");
        assert!(stdout.contains(expected) || stderr.contains(expected), "{name} did not produce {expected}'s output: {stdout} {stderr}");
    }
}
