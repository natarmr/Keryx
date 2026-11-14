# AGENTS.md

## What this is

A local, cryptographically identified message bus (`keryx`) for coordinating several AI
agent CLIs on one machine. The security model is the product: read the trust-boundary
section of `README.md` before changing anything in `idboard-core`, `idboardd` (the
implementation crate; the installed daemon command is `keryxd`), or the wrapper.

**The directory is named `a2aboard`; the implementation crates and protocol string remain
`idboard`, while the command and daemon binaries are `keryx` and `keryxd`.** The state dir
`~/.idboard/`, the `IDBOARD_*` env vars, the protocol domain `"idboard/v1\0"`, and all key/message
compatibility are intentionally unchanged by the command rename.

This tree is a git repository. `cargo test --workspace` is the gate; there is no CI.

## Commands

```sh
cargo build --workspace      # REQUIRED before the e2e suite - see below
cargo test --workspace       # 370 tests, ~60s   <-- this is the normal path
.\scripts\check-custody.ps1 # read-only: who can reach the trust root and the socket
.\scripts\check-custody-claims.ps1 # do the custody statements still tell the truth?
.\scripts\harness-smoke.ps1 # opt-in: drive a real agent harness (costs tokens)
```

370 = 301 unit + 69 e2e (368 pass, 2 `#[ignore]`d live-harness tests). The slow half is
`idboard-core`'s 46 tests at ~8-20s (key generation) and e2e at ~21s; everything else is
under a second. A passing run prints only `test result: ok`
lines and the rejections e2e *expects* on stderr — daemon-unreachable and wrapper-gone
lines are test output, not failures. There is no CI, no pre-commit hook, and no formatter
or linter config in the tree; this suite is the only gate.

**In PowerShell, do not judge a cargo run by a pipeline's exit code.** e2e writes to
stderr, PowerShell turns native stderr into error records, and `cargo test --workspace 2>&1 |
Select-String …` can report exit 1 with every test passing. Redirect to a file and read
`$LASTEXITCODE`, or grep the `test result:` lines.

Config-only validation, no daemon needed: `keryxd --check` (reports every problem at
once) and `keryxd --show-acl` (resolved channel matrix).

**Smart App Control is currently OFF on this machine, so `cargo test --workspace` just works
and `scripts\test.ps1` is not needed.** That is a machine setting, not a property of the repo;
if it is ever turned back on, read the note below before trusting a test result.

- `scripts\test.ps1` is a *fallback* for machines where Smart App Control refuses some locally
  built unsigned test binaries, keyed on content hash (`An Application Control policy has blocked
  this file`, os error 4551). It appends and then strips a
  `__SM_APP_CONTROL_PROBE` const in `crates/idboard-core/src/lib.rs` to perturb codegen. That
  line must be **absent** in a finished tree; if you see it, a run was interrupted.
  The probe lives in `idboard-core` **on purpose**: a source change only reaches a test binary
  that links the changed library, so probing a leaf crate unblocks that crate's test binary
  and nothing else. `idboard-core` is linked by every crate, so one probe covers every test
  binary. Only a real error causes the script to stop — an App Control block triggers a retry.
- **The probe workaround cannot fix Smart App Control blocking the toolchain.** On this host
  that manifested as `rustc.exe` exiting `0xC0E90002` with no output. It was *not* `rustc.exe`
  being refused: Code Integrity event 3077 showed `rustc.exe` launching and then failing to load
  its own `std-*.dll` ("did not meet the Enterprise signing level requirements"). All the Rust
  binaries here are Authenticode `NotSigned`, and only `rustc` dynamically loads that DLL, so
  `cargo` kept working while `rustc` could not. No source perturbation can change whether a DLL
  is permitted to load. If `rustc --version` fails, check
  `Get-WinEvent -LogName Microsoft-Windows-CodeIntegrity/Operational` — filtering for `rust`
  matters, the log is noisy and the rust entries are not the first ones.

Single test:

```sh
cargo test -p idboard-core -- --exact envelope::tests::no_field_boundary_ambiguity
cargo test -p idboard --test e2e -- --exact a_tampered_body_is_rejected   # needs the build below
```

- **`cargo build --workspace` first, always.** `crates/idboard/tests/e2e.rs` locates the
  real binaries as *siblings in `target/debug`* (`sibling_bin`), not via
  `CARGO_BIN_EXE_*`, because the tests need `keryxd` — a different package. `cargo build -p
  idboard` does **not** build `keryxd.exe` (verified), so a package-scoped run on a clean
  target dir fails with `keryxd not built; run cargo build first`. This also means
  `scripts\test.ps1 -Package idboard` is only safe once the workspace has been built.
- **`rustfmt` and `clippy` are not installed** on this toolchain. `cargo fmt` and
  `cargo clippy` both fail with `not installed for the toolchain`. Don't try; don't
  "fix" formatting by guessing.
- Toolchain is 1.98.1 MSVC; VS 2026 lives at `D:\MSvisualStudios\main` and the SDK at
  `D:\Windows Kits\10`, both off default paths. Cargo finds them via the registry, so no
  Developer Command Prompt is needed. `rusqlite` uses `bundled`, so SQLite is compiled from
  source and a working MSVC C toolchain is a hard prerequisite.

## Layout

Six crates, dependencies flow one way. `idboard-core` has **no I/O** beyond the system
CSPRNG and is deliberately kept free of sockets, storage, and config — keep it that way.

| Crate | Owns |
|---|---|
| `idboard-core` | `Envelope`, canonical bytes, ed25519 keys, `ErrorCode`, paths/env contract |
| `idboard-acl` | config parsing, identity registry, role resolution, channel ACLs, `[limits]` |
| `idboard-store` | SQLite; the replay counter, forward reads, tail reads, last-seen roster |
| `idboard-ipc` | `interprocess` local sockets, newline-delimited JSON framing |
| `idboardd` crate (`keryxd` binary) | `Board` (all security decisions: authorisation, digests, post budget) + a thin `main.rs` |
| `idboard` crate (`keryx` binary) | CLI, keystore, identity lock, wrapper, relay, MCP front-end |

Entry points: `keryx run --identity X -- <cmd>` is the wrapper (owns the key, signs for
the child); `keryxd` is the daemon. The child reaches the board *only* through a
per-invocation relay socket. The child-facing surface is `post`, `read`, `subscribe`,
`whoami`, `inbox`, `peers` (last-seen roster, diagnostic only), `doctor`,
`task`, `dm`, `notify`, `mention`, `react`, `cursor`, `console`, `focus`, `next`,
`replay`, `web`, `mcp`.
`keryx instructions` prints
the harness wiring blocks and needs no relay. `keryx post` reads its body from the
command argument, a file via `--body-file`, or stdin with `--body-file -`.

**The CLI is deliberately inert outside a wrapper.** `keryx post` in a plain shell fails
on the missing `IDBOARD_RELAY`/`IDBOARD_TOKEN` — that is the design, not a broken install,
so do not add a fallback path to the daemon to "make it work". To exercise the CLI by hand,
go through `keryx run --identity X -- <cmd>`; e2e's `as_identity` is the same thing.

`run-1/` is **not source**. It is the output tree of a prior security audit (report,
ledger, per-hunter scratch). All six findings are `needs_validation` from a source-only
run — nothing was built or executed, so none is confirmed, and two candidates were dropped
unvalidated. Read it as leads; do not treat it as a bug list to "fix", and do not delete or
edit it. Where it and the code disagree, the code is newer: its headline finding (board
mutex held across the peer read) has since been fixed and is pinned by
`a_peer_that_never_writes_cannot_withhold_the_board_from_other_identities`.
`docs/audit-reconciliation.md` records the disposition of all six; keep it in step if you
re-touch any of those areas rather than re-deriving the mapping.

## Invariants — do not break these

These are the load-bearing rules. Most have a test that will fail loudly; a few are only
enforced by review.

- **Verification happens in exactly one place**, `keys::verify_with_key`, and the daemon
  must call it with the key the *config* registers for the claimed name — never a key from
  the request. `Store::append` takes `verified: &str` and deliberately does not re-derive
  it; do not add a second check there.
- **Check order in `Board::dispatch` is version → registration → signature → per-op
  invariants → freshness → ACL.** Registration precedes signature so an unregistered name
  yields `unknown_identity` rather than a confusing `bad_signature`.
- **Use `verify_strict`, never `verify`.** `verify` accepts weak low-order keys, which
  would validate a signature over almost any message.
- **Two auth mechanisms, split structurally.** `post` authenticates by monotonic sequence
  number; `read`/`handshake` by signed timestamp (±5 min) + nonce, and must *not* consume a
  sequence number or `subscribe` burns counter values at its poll rate.
  `Envelope::check_op_invariants` enforces the shape so neither can borrow the other's
  mechanism. Posts get no clock window. `inbox` and `peers` are queries, not a third
  mechanism: they join the same channel-less arm (`Handshake | Inbox | Peers`) and must stay
  there, because a query that could carry a channel or a sequence number would let one
  mechanism impersonate another. `LocalSigner::sign_channel_less` is the only signer for
  that shape.
- **External provenance is policy, not inference.** A channel's `allow_external = false`
  rejects `post` envelopes marked `Provenance::External` at the daemon boundary, after
  ACL reachability and before the post budget/store append. It never inspects message
  text; the caller declares provenance and the daemon enforces the configured policy.
- **Advertising a permission is the same call as enforcing it.** The handshake's
  `readable_channels`/`postable_channels` and every `inbox` digest are built by calling
  `authorize()`, never by re-reading grant lists. A second implementation is free to
  disagree with enforcement and the disagreement would surface only when an agent tried a
  channel it had been told about. The lists are advisory: every real read and post is
  authorised again. `inbox` omits a channel the caller can neither read nor post to, so the
  roster is not leaked, and reports `can_read = false` channels with no messages rather than
  hiding a channel it can post to.
- **The post budget is charged after authorisation and before the append.** Anywhere earlier
  lets an identity holding a valid key burn another identity's allowance with posts that
  were never going to be stored; nowhere at all makes `[limits]` decorative. Reads,
  handshakes, `inbox` and `peers` are never charged — a poll loop is how an agent waits.
  Default is unlimited; `Limits::is_unlimited()` is the one predicate, and the window is in
  memory, so a restart resets it (bounded and visible, unlike a schema migration for a soft
  limit).
- **Presence is diagnostic and is never an authorisation input.** `peers` reads
  `identities.last_seen_ms`; nothing in the authorisation path consults it. Do not use it
  for liveness, lock ownership, or eligibility — `last_seen_ms = 0` is a normal state for a
  configured identity that has not acted yet, and the wrapper lock is the only thing that
  says a process is live.
- **Local cursor files are convenience state, never authority.** `read` and
  `subscribe` may use `$IDBOARD_HOME/cursors/<identity>.json` with `--since-last` /
  `--since-last --save-cursor`. The daemon never reads it; a corrupt or missing file is
  an explicit error, not a silent reset to `0`; the file carries only per-channel cursors.
- **`keryx mcp` is a front-end, not a second auth path.** It goes through `RelayClient`
  like the CLI, and it must never reach `keryxd` directly — that route needs the key,
  which is the thing the wrapper exists to withhold. Its tool arguments are only
  `channel`/`body`/`provenance`/`since`/`limit`; an `identity` or `token` argument is
  ignored rather than honoured, and the sender comes from the relay handshake. Starting
  without a wrapper must still serve, returning the "no relay" text as a tool error, so a
  harness reports a refused call instead of a dead server.
- **Signatures cover `Envelope::to_canonical_bytes`, never serialised JSON.** JSON field
  order is not stable across `serde_json` versions. The layout is documented on that
  function; `canonical_bytes_round_trip_through_an_independent_decoder` re-parses it with an
  independently written decoder, so any field reorder or dropped length prefix fails.
- **`SignedFields` is the exact set the signature covers.** It is a separate borrow of the
  envelope precisely so a new field forces a decision. The compiler will *not* catch a
  field added to `Envelope` but omitted from `SignedFields` — that shows up in the review
  diff. `signature` is the one field intentionally excluded.
- **`RelayRequest` must never gain a sender/seq/timestamp/signature field.** Its lack of
  them is the reason a child cannot construct an envelope. The wrapper fills all of them in.
- **No trust-on-first-use.** Every identity needs an explicit `pubkey` in the config;
  `keryxd` refuses to start without one. Learning a key from the first message claiming a
  name would let any local process claim `lead` and lock the real one out permanently.
- **One live wrapper per identity** (advisory lock). Two wrappers would interleave sequence
  numbers and destroy post-incident attribution. The pid lives in a *separate* `.pid` file
  because a Windows byte-range lock also blocks reads of the locked file.
- **Authorisation always uses the verified identity.** `authorize()` takes no argument that
  could substitute for one.
- `Store::register_identities` never resets `last_seq`; a daemon restart must not hand an
  identity a reusable counter. A changed pubkey is returned as "rotated" so the daemon can
  warn loudly. `Store::last_seq` returns `Err(UnknownIdentity)` for an identity the registry
  does not hold — the wrong direction to fail in is `Ok(0)`, which is a reusable counter.
- **Never hold a shared lock across a peer-paced read.** The daemon's `Mutex<Board>` is
  taken around `Board::handle` only. It is one lock for every identity on the machine, so a
  guard spanning a read lets one unauthenticated connect-with-zero-bytes withhold the board
  from *other* identities. The relay's sequence mutex already follows this rule, and
  `serve_one` is bounded for the same reason: the token check runs inside the handler, so it
  cannot gate the read.
- **`apply_timeouts` installs nothing on Windows, and says so.** `interprocess` returns
  `ErrorKind::Unsupported` unconditionally for a named-pipe stream, so the deadline is
  enforced by `read_frame_deadline` (a reader thread plus `recv_timeout`) rather than by the
  socket. Don't reintroduce a trust decision on the socket having a deadline; log
  `deadlines_installed()` instead.
- **A read projection must carry every signed field it claims to.** `channel` is inside the
  canonical bytes; dropping it on the way out produced a message that could no longer be
  re-verified, because `validate_channel` rejected the empty string before the signature was
  even reached. `a_read_back_message_still_verifies_against_its_signer` pins this.
- **Everything that reaches a human's terminal or a log is untrusted.** Message bodies and
  claimed identities were signed by *some* identity, which may be hostile. `rejection_line`
  quotes and bounds them; `render_message` escapes control characters. Both deliberately
  leave non-ASCII alone — over-escaping corrupts honest prose to defend against an attack.
  `--json` is intentionally unfiltered.
- **A key is never replaced.** `Keystore::save_seed` links into place rather than renaming,
  so a second save fails with `AlreadyExists` instead of clobbering. `rename` replaces on
  Windows, which turned two racing `keygen` runs into an operator pasting a public key that
  was not the key on disk.
- **`SINCE_CURRENT_END` (`i64::MAX`) is a request for a position, not a claim about one.**
  A read asked that way answers with `store.high_water_cursor()`. Echoing the sentinel back
  hands a poller a cursor no row can ever match, which is what made `keryx subscribe` poll
  silently forever. Any other empty read still echoes the caller's own cursor.

## Windows / platform notes

- Named pipes have no I/O timeout. `interprocess` returns `ErrorKind::Unsupported`
  unconditionally, so `idboard-ipc` records that in `deadlines_installed()` rather than
  reporting a success it did not achieve, and the bound comes from
  `read_frame_deadline` instead. The residual is a *parked thread* per stalled peer, not a
  busy worker: the reader thread is not cancelled, because cancelling a blocked read on a
  pipe handle is not exposed. The fixed pool (`WORKERS = 4`, `QUEUE_DEPTH = 64`) is the
  outer bound.
- A pipe name is not a secret — any process can enumerate `\\.\pipe\*`. The relay's actual
  credential is the 32-byte `IDBOARD_TOKEN`, compared in constant time.
- The e2e harness hardcodes a `.exe` suffix in `sibling_bin`, so it is Windows-only as
  written.
- `ensure_private_dir` is a no-op beyond `create_dir_all` on Windows; NTFS inherits ACLs
  from `%USERPROFILE%`. There is no Windows file-ACL code anywhere in the tree, and
  `Config::custody_statement` says so on every daemon start rather than implying otherwise.
  Note it also chmods a directory that already exists, so it resets a deliberately loosened
  mode on every call — deliberate for the keystore, be aware before adding a call site.
- The daemon and relay listeners carry **no security descriptor**, and say so.
  `interprocess` exposes `ListenerOptionsExt::security_descriptor` but no way to adopt an SDDL
  string, so the only route is a hand-built `ACL` (`InitializeAcl` +
  `AddAccessAllowedAceEx`) — ~80 lines of `unsafe` Win32 and the first platform dependency in
  this crate. **Measured and declined:** a NULL security descriptor makes the listener inherit the
  creating token's default DACL, which on a standard profile is owner + SYSTEM + Administrators
  and excludes `BUILTIN\Users` — the same source as the state root's inherited ACLs, so the only
  in-scope principal (a second non-administrative account) is already excluded. Do not
  re-raise this without a machine whose token default DACL is broader than a standard profile;
  `scripts\check-custody.ps1` is how you would notice. `deadlines_installed()` and
  `listener_custody_statement()` are the two things a caller should log rather than assume.
- **`Config::custody_statement` and `idboard_ipc::listener_custody_statement` must not
  over-claim.** They are the operator's only statement of what is actually enforced, and a
  statement that implies enforcement that does not exist is worse than silence. Both name
  `scripts\check-custody.ps1`, and both are pinned by tests that reject over-claiming
  language.
  **Every `#[cfg]` arm must satisfy the same assertions, not just the one the CI platform
  compiles.** An assertion placed before a `#[cfg]` branch runs on every platform, so an arm
  that omits a required phrase fails the suite somewhere nobody is looking. That happened
  here once: the `unix` arms were missing a phrase the test required, and the test passed on
  Windows. `scripts\check-custody-claims.ps1` now checks every arm mechanically and does not
  need a compiler — run it after touching either statement.

## Testing conventions

- **Assert a specific `ErrorCode`, never "not ok".** A test that accepts any failure proves
  nothing about which defence fired. `CoreError::detail` is operator-facing prose and is
  explicitly *not* a stable contract — never assert on it.
- e2e attacks the board two ways on purpose: as a legitimate agent (`as_identity`, through
  the wrapper) and as an attacker holding the keys and the socket (`daemon_raw`) — forged
  senders, replays, tampered bodies, wrong-key signatures.
- Tests must never touch a real `~/.idboard`. Unit tests set `IDBOARD_HOME` to a temp dir;
  env vars are process-global, so those tests are serialised behind a `static Mutex`
  (`ENV_LOCK` in `lock.rs`). `std::env::set_var` is wrapped in `unsafe` because the crate
  is edition 2024.
- **One environment lock, and every test that mutates `IDBOARD_*` takes it.** `ENV_LOCK`
  lives in `lock.rs` and is exposed as `pub(crate) fn env_lock()`; `wrapper`'s child-env
  test takes the same lock rather than defining its own. It used to not, and the race was
  visible: `wrapper` writes `IDBOARD_HOME=SENTINEL-VALUE`, a concurrent `lock::tests::*`
  resolved `run/eng-01.lock` under `crates/idboard/SENTINEL-VALUE/`, succeeded, and failed
  `unwrap_err()`. Observed once in five runs. If a new test needs to set an env var, take
  `env_lock()` — a second mutex serialises nothing.
- **Live-harness tests are `#[ignore]`d and env-gated on purpose.** A test that launches a
  real agent CLI costs tokens, needs a network, and depends on a model that may be retired
  mid-week; the default suite must stay offline and deterministic. They assert on the
  *board* (was a signed message stored, under which identity), never on the agent's
  transcript, because a model can say anything. `docs/harnesses.md` holds the measured
  matrix — which harnesses can be driven headlessly here, which cannot, and the failure
  catalogue — and `scripts\harness-smoke.ps1` is the runner.
- `keryxd`'s `Board` takes an injectable `Clock` (`with_clock` / `with_fixed_clock`) so
  skew-window tests never sleep. Use it rather than adding sleeps.
- Storage tests use `Store::open_in_memory()`.
- There is no migration framework. The schema is one `SCHEMA` const of
  `CREATE TABLE IF NOT EXISTS` statements applied on every `open`. A change that an existing
  `~/.idboard/idboard.db` would reject needs a hand-written migration.

## Known inaccuracy

`rust-version = "1.85"` in the workspace manifest is wrong — `idboard/src/lock.rs` uses
`File::try_lock`, stable since 1.89. Trust the code over the manifest; fixing the manifest
is a separate, deliberate change.

## Environment contract

`~/.idboard/` (or `$IDBOARD_HOME`) holds `config.toml`, `idboard.db`, `keys/<id>.key`,
`run/<id>.lock`, `run/<id>.pid`. Overrides: `IDBOARD_CONFIG`, `IDBOARD_DAEMON`,
`IDBOARD_HOME`.

Wrapper children may be given `KERYX_CURSOR_HOME` instead of the real
`~/.idboard/` when they need a writable, test/fixture-specific cursor root; the
wrapper does not strip that one. These files remain convenience state and are
never an authorisation input.

`IDBOARD_RELAY` and `IDBOARD_TOKEN` are set **by the wrapper for its child**. The wrapper
also strips `IDBOARD_RELAY`'s siblings — `IDBOARD_DAEMON`, `IDBOARD_CONFIG`, `IDBOARD_HOME`
— from the child. That stripping is defence in depth, not the control: the control is that
the child holds no key. Don't treat a stripped env var as a guarantee.

`keryx run` exit codes are a contract for supervising scripts: 0 is the child's code, then
2 locked, 3 not-in-config, 4 key mismatch, 5 daemon unreachable, 6 spawn failed, 7 relay
failed, 130 interrupted. `clamp_code` truncates to a `u8`, deliberately keeping 2/3/4 exact.

Useful for agents: `--json` is a global flag on any subcommand.
