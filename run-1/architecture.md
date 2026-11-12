# Architecture and trust-boundary summary — `idboard` (directory `a2aboard`)

## 1. Product, principals, protected resources

A local, cryptographically identified message bus for coordinating several AI agent CLIs on one machine. Not a network service: nothing listens on the network. Three processes per logical agent — a long-lived `idboardd` daemon, a per-invocation `idboard run` wrapper that owns a private key, and an arbitrary child program the wrapper spawns.

Principals, lowest trust first:

1. **Any local process on the machine, unauthenticated.** Can connect to the daemon named pipe `\\.\pipe\idboardd-<USERNAME>` and the per-invocation relay pipe, submit one JSON frame of at most 1 MiB, and read one reply. The pipe name is not a secret — `\\.\pipe\*` is enumerable, and the relay name embeds the identity in cleartext.
2. **The spawned child agent process.** Holds `IDBOARD_RELAY` and a 32-byte `IDBOARD_TOKEN`. Holds no key. Its authority is exactly its wrapper's identity, on the channels that identity may use.
3. **A same-user process holding a keystore seed.** Obtains full authority for that identity with no wrapper, no lock, and no token. An explicit, documented non-goal.
4. **A writer of `config.toml`.** Total control: the identity→key map and every channel ACL. Read with a plain `read_to_string`, no signature and no permission check.
5. **The operator.** Authors config, runs `keygen` and `run`, reads the CLI.

Protected resources, in order of value: the ed25519 identity keys in `~/.idboard/keys/`; the identity→key registry and every channel ACL in `config.toml`; the per-identity monotonic sequence counter in `idboard.db`; the message bodies themselves; the daemon's availability as a shared coordination point for all concurrent identities.

## 2. Comparable baseline

None that is source-grounded. The only externally-named reference in the tree is aspirational prose in `README.md:13-15` ("a single-machine version of what A2A does with Signed Agent Cards and OAuth"). No A2A endpoint, card format, OAuth flow, spec version, RFC, or upstream URL is implemented, referenced in code, or cited. Severity calibration therefore rests on the design's own stated threat model, not on a comparable system.

## 3. Stack, deployment, offline limits

Rust workspace, edition 2024, six crates with one-way dependency flow: `idboard-core` (no I/O beyond the system CSPRNG) → `idboard-acl` (config, registry, roles, channel ACLs) → `idboard-store` (SQLite, replay counter) and `idboard-ipc` (local sockets, newline-delimited JSON) → `idboardd` (`Board` plus a thin `main.rs`) → `idboard` (CLI, keystore, identity lock, wrapper, relay). No async runtime, no web framework, no plugin system, no CI, no `build.rs`.

Crypto: `ed25519-dalek` 3.0.0 with `verify_strict`; `sha2` 0.11; `getrandom` 0.4. Storage: `rusqlite` 0.40 `bundled`. Transport: `interprocess` 2.4.4.

**Execution limits for this run.** No OS-enforced sandbox exists on the audit host: no container or VM isolation, no empty-allowlisted-environment launcher, no read-only target or toolchain mount, and no CPU, memory, process, file-size, disk, or wall-clock enforcement. Windows Smart App Control is additionally documented as refusing some locally built unsigned test binaries. No target-controlled code was executed. Every check in this run is source-level, so no candidate can reach a bounded observed result and the run will report zero confirmed records by construction.

## 4. Entry surfaces and the important paths

| Surface | Entry | Strongest source-visible control |
|---|---|---|
| Daemon pipe frame | `idboardd/src/main.rs:168` `serve` → `read_frame` | none at the transport hop; no token, no DACL, no peer credential |
| `DaemonRequest` dispatch | `idboardd/src/lib.rs:94` `Board::dispatch` | single verification point `keys.rs:281` `verify_with_key`, using the key the *config* registers for the claimed name |
| `RelayRequest` dispatch | `idboard/src/relay.rs:107` `Relay::dispatch` | 32-byte CSPRNG bearer token, constant-time compare `relay.rs:114` |
| Child process env | `idboard/src/wrapper.rs:306` `spawn_child` | the child holds no key; `IDBOARD_DAEMON`/`CONFIG`/`HOME` stripped as defence in depth only |
| `config.toml` | `idboard-acl/src/lib.rs:250` `Config::load` | no signature, no ACL; this file *is* the trust root |
| Key file | `idboard/src/keystore.rs:87` `load_seed` | exact 32-byte length check; 0600 is `#[cfg(unix)]` only |
| Per-identity lock | `idboard/src/lock.rs:59` `try_acquire_at` | advisory `File::try_lock`, pid in a separate file |
| `idboard.db` | `idboard-store/src/lib.rs:113` `Store::open` | single writer by convention; no file ACL, no `PRAGMA key` |
| Environment | `idboard-core/src/layout.rs:60-134` | none; `IDBOARD_HOME`/`IDBOARD_CONFIG`/`IDBOARD_DAEMON` redirect the trust root |

Load-bearing paths:

- **Child → board.** child `RelayRequest` → token check → wrapper fills `sender_id`, `sender_pubkey_fp`, `seq`, `timestamp`, `signature` from its own signer → daemon pipe → `Board::dispatch` → `verify_with_key` against the config key → `authorize` against the *verified* `&Identity` → `Store::append` writing the config-derived name.
- **Attacker → board.** raw `DaemonRequest` on the daemon pipe with a forged `sender_id` → fails at `verify_strict` because `sender_id` is inside the signed bytes → the persisted `sender_id` column is bound from the config name, not the envelope.

## 5. Trust boundaries and their strongest control

1. **Any local process → daemon.** No authentication at the transport hop. The only real credential is the ed25519 signature, checked once, at `keys.rs:281`. Bounded work per request by `MAX_FRAME_BYTES` (1 MiB) and a 4-worker pool.
2. **Child process → wrapper identity.** The 32-byte relay token (`relay.rs:114`), plus the structural fact that `RelayRequest` has no `sender_id`, `seq`, `timestamp`, or `signature` field and serde discards unknown fields — a child cannot construct an envelope.
3. **Claimed name → signing key.** Resolved by config lookup (`idboardd/src/lib.rs:105`), enforced by the signature over length-prefixed canonical bytes that include `sender_id` (`envelope.rs:197`), and re-checked by a fingerprint cross-check (`keys.rs:308`). No trust on first use: `pubkey` is mandatory (`acl/lib.rs:169`).
4. **Verified identity → channel ACL.** `authorize(config, identity, channel, op)` takes no argument that could substitute for the identity (`idboardd/src/lib.rs:155`). Grant matching is a flat OR over `*`, identity name, and role (`acl/lib.rs:86`).
5. **Post → replay counter.** Guarded `UPDATE ... WHERE last_seq < ?2` inside an `IMMEDIATE` transaction, plus a `UNIQUE(sender_id, seq)` index and `AUTOINCREMENT` cursor (`store/lib.rs:216`, `:79`, `:92`).
6. **Filesystem custody.** On Windows, `ensure_private_dir` is a no-op beyond `create_dir_all` and no pipe DACL is ever set, so the confidentiality story for `keys/`, `config.toml`, `idboard.db`, and both pipes reduces to inherited NTFS ACLs plus the Windows default pipe DACL. None of those is set or verified by this code.

## 6. Starting paths

`crates/idboard-core/src/{envelope,keys,wire,ids,layout,error,lib}.rs`; `crates/idboard-acl/src/lib.rs`; `crates/idboard-store/src/lib.rs`; `crates/idboard-ipc/src/lib.rs`; `crates/idboardd/src/{lib,main}.rs`; `crates/idboard/src/{wrapper,relay,keystore,lock,client,cli,lib,main}.rs`; `crates/idboard/tests/e2e.rs`; `scripts/test.ps1`; `Cargo.toml`; `Cargo.lock`.

## 7. Prior coverage, gaps, exclusions

No prior ledger or findings file exists for this repository. The only prior run on this host is for an unrelated project. Every unit is therefore seeded `prior_status: "none"` and this run is the first coverage baseline. There are no carried same-source confirmations and no changed-source revalidation targets.

`wrapper.rs` has no `#[cfg(test)]` module at all, so the entire child-process environment contract — including the documented stripping of `IDBOARD_DAEMON`, `IDBOARD_CONFIG`, and `IDBOARD_HOME` — has no test in unit or e2e form. Several crypto branches are unexercised by any test, including the fingerprint-mismatch branch at `keys.rs:308` and any assertion that `verify_strict` actually rejects a weak registered key. These are coverage gaps in the test suite, not audit exclusions, and they inform priority rather than suppress any unit.

## 8. Companion selection summary

Selected: `PROTOCOLS-RPC-AND-MESSAGING.md` (custom framing, canonicalization, envelope-vs-payload identity, replay/ordering), `DESKTOP-MOBILE-AND-LOCAL-IPC.md` (local daemon and per-invocation IPC helper, peer authentication, claimed principal vs channel identity, local credential custody, IPC lifecycle), `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md` (4-worker pool, single board mutex, no named-pipe I/O deadline on the primary platform), and `AI-AND-LLM.md` (narrowly: the signed-but-never-enforced `provenance` field and unescaped terminal rendering of attacker-influenceable bodies).

Excluded with source reasons, recorded per unit in the ledger: `WEB-PROTOCOL-AND-AUTH.md` (no HTTP/TLS/session code), `CLIENT-SIDE.md` (no browser or webview), `CLOUD-AND-DEPLOYMENT.md` (no cloud, IAM, or infrastructure code), `DATA-ISOLATION-AND-LIFECYCLE.md` (single local SQLite file, no tenant/export/backup/migration path), `MEMORY-SAFETY-AND-BINARY.md` (safe Rust; only unsafe is test-helper env mutation; no FFI, allocator, loader, or JIT), and `SUPPLY-CHAIN-AND-RELEASE.md` (no CI, `build.rs`, release, signing, or plugin path; dependency hygiene is covered under the ordinary `Obvious things` unit).
