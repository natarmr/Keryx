# Needs validation — prioritized leads, no severity

Six records. Each is a **source-grounded boundary hypothesis whose decisive check could not be made on this host**, not a confirmed vulnerability. None carries a severity: severity is assigned only to `confirmed` records.

**Common blocker on all six:** the audit host provides no OS-enforced sandbox (no container/VM isolation, no empty-allowlisted-environment launcher, no read-only target, no resource limits), and Windows Smart App Control blocks some locally built unsigned test binaries. No target-controlled code was executed at any point in this run. Each `local` plan below is written to be run by an owner on an isolated machine. Each `deployment` plan is a **read**, never a probe of a live system.

Two further candidates — `idboard/cli.rs:render_message:unescaped-body-in-operator-terminal` and `idboard/keystore.rs:save_seed:ungated-check-then-act-replace` — were **not** validated to completion and are therefore **excluded from this file as well**. They are unvalidated ledger candidates, not leads with a plan. Do not act on them as if they were characterised.

---

## 1. `idboardd.serve.board_mutex_held_across_peer_blocking_io`

**The single process-wide board mutex is acquired before the peer-paced read, so one stalled unauthenticated pipe connection holds the board for every identity.**

**Affected principal:** a *different* identity than the attacker's. **Affected resource:** the shared coordination point itself.

An unauthenticated local process opens the daemon pipe and sends **zero bytes**, keeping the handle open. A worker has already taken the one `Arc<Mutex<Board>>` (`crates/idboardd/src/main.rs:117`) at `main.rs:135`, *before any byte is read*, and passes the live guard into `serve` at `main.rs:139`. The guard therefore spans the blocking read at `main.rs:177`. Every other identity's connection is picked up by another worker that blocks on the same mutex at `main.rs:135`.

**Scale, corrected by validation:** the cross-identity effect begins with the **first** connection from another identity. Total loss of the accept loop additionally needs the other three workers blocked and the 64-deep channel (`main.rs:111`) full — roughly 67 further connections. That figure is **analytic, not observed**; do not test it. Recovery requires the attacker to close the handle.

**Validation correction that must be preserved:** the *write*-side trigger was **refuted**. Pre-authentication responses are small and absorbed by the OS pipe buffer, so `write_all` (`crates/idboard-ipc/src/lib.rs:262`) does not block for an unauthenticated peer. Only the read trigger is real.

**Bounded local check (one connection, no saturation):** scratch state root, two identities, one channel permitting both to post and read. Start the daemon; confirm workers ready. Open **one** pipe handle, write zero bytes, hold 15 s. From a second process, post as the other identity under a 30 s timeout. Confirming: the handle stays open, the second process gets no response, the accept loop stops draining. Control: close the handle, re-run the same post, confirm it now succeeds. Stop at the first confirmed timeout. **Do not** open more than one stalled handle. **Do not** probe the write path.

**Deployment read:** confirm whether any real installation runs two or more identities concurrently through one daemon — that is what makes the board mutex a shared multi-tenant resource rather than a per-invocation one. Record the pipe's platform ACL if a cross-account attacker is in scope.

**Fix, if confirmed:** move `board.lock()` to immediately around `board.handle(&req)`; run `read_frame`, the response write, and the `eprintln!` at `main.rs:183` outside the guard. `Board::handle` (`crates/idboardd/src/lib.rs:87`) does bounded local work and never touches the stream, so this weakens no check. The wrapper already applies exactly this discipline to its own sequence mutex (`crates/idboard/src/relay.rs:69`) — same tree, same class of shared mutex, applied correctly in one place and not the other.

---

## 2. `idboard-ipc.apply_timeouts.unsupported_swallow_removes_read_deadline`

**`apply_timeouts` discards `ErrorKind::Unsupported` and still reports success, so no socket in the tree is proven to carry an I/O deadline.**

`apply_timeouts` (`crates/idboard-ipc/src/lib.rs:181-194`) calls `set_recv_timeout`/`set_send_timeout` (`:183-184`), discards `Unsupported` in an empty arm (`:189`), and returns `Ok(())` (`:193`). A function whose whole purpose is installing a deadline reports success having installed none. `IO_TIMEOUT` (`:51`) becomes dead configuration.

**Validation correction that must be preserved:** the deadline belongs to the **`Stream`** handed over by `accept` (`:137`), `try_accept` (`:154`) or `connect` (`:166`) — **not** to `read_frame_from`, which is generic over `BufRead`. And the decisive fact is **not source-provable**: whether `interprocess` 2.4.4 returns `Unsupported` (dead configuration) or `Ok` with a real 10 s deadline is third-party behaviour absent from this repository. The only in-repo support is a comment at `:172`; the test at `:423` asserts only `is_ok()`, which is satisfied identically by both outcomes, so **the suite pins the swallow, not the deadline**.

**Not the same as record 1.** The cross-identity outage belongs to record 1, which consumes this precondition. Standalone, this is the already-documented residual (`README.md:326-329`): the fixed pool, plus — newly recorded — the per-invocation relay supervisor at `crates/idboard/src/wrapper.rs:367`/`:403`, which also polls child exit at `:356`. On the relay path the affected principal is the **same** identity, so it is within-identity, not cross-tenant.

**Bounded local check — Fact A, the decisive question:** bind, connect one client, accept, have the client write zero bytes, and time one server-side `read_frame`. *Refuting:* returns before 10 s with a timeout error, meaning a deadline **is** installed and this does not manifest. *Confirming:* still blocked well past 10 s under a hard 60 s cap. Close the handle at once. **Fact B**, symmetric send-path check. **Control (required before trusting either):** a client that writes a complete frame plus a newline must be served normally. Do not attempt a reply larger than the pipe buffer on the unauthenticated path. If fixing: on Windows the mechanism cannot be a receive timeout, so a watchdog that closes/cancels the handle after `IO_TIMEOUT` — checked not to race the worker's own use of the same `Stream` at `main.rs:177-194`.

**Deployment read:** record the deployed platform. On Unix a receive timeout maps to `SO_RCVTIMEO` and this does not manifest; the e2e harness (`crates/idboard/tests/e2e.rs:41`) is Windows-only.

---

## 3. `idboard-ipc.read_frame.unbounded-envelope-strings.daemon-rejection-log`

**Unbounded, unescaped envelope strings reach the daemon's rejection log through every `!ok` path.**

`Envelope.sender_id` (`crates/idboard-core/src/envelope.rs:119`) and `.channel` (`:125`) are bare `String`s with no length bound. `validate_identity`/`validate_channel` exist in `crates/idboard-core/src/ids.rs` but run only inside `Envelope::validate` (`:258`), reached only via `verify_with_key` (`crates/idboard-core/src/keys.rs:282`). `rejection_line` formats both with `Display {}` (`crates/idboardd/src/lib.rs:246-247`) and `main.rs:183` writes the result to the operator's stderr for **every** `!ok` response.

**Validation correction:** the original candidate scoped the sink to the two pre-cryptography branches (version at `crates/idboardd/src/lib.rs:95`, registration at `:105`). It is actually **every** `!ok` response, so a registered-key holder also reaches it — but that principal is same-user, which this design places **inside** its documented boundary, so it adds no cross-boundary reach.

**Affected resource:** the post-incident attribution record. One request can emit several lines shaped like genuine rejections, naming another identity as the claimed sender on a restricted channel. No board state, key, or body is affected; no identity gains authority. **Impact is audit-trail integrity, not privilege gain.**

**Bounded local check:** scratch state root, explicit socket/db paths, stderr to a file. From a separate process write **one** line whose `sender_id` contains a JSON-escaped `\r\n` followed by a forged rejection-shaped line. Expect not-ok, and the file to grow by 2+ lines, the second matching the rejection shape. Repeat ten times (expect ≥20 lines); control with a single-character `sender_id` (expect exactly 10).

**Deployment read:** record the daemon pipe's security descriptor and who may open it. If only the creating account and SYSTEM are granted, the affected principal is same-user; if broader, it extends to cross-account log forgery.

**Fix, if confirmed:** escape **at the render**, in `rejection_line` — format with a debug formatter, as the `UnknownIdentity` detail already does at `crates/idboardd/src/lib.rs:107-113` — and bound each field to a fixed prefix. The defence-in-depth complement is to apply `validate_identity`/`validate_channel` in `Board::dispatch` before the version and registration branches. Keep `rejection_lines_are_greppable_and_name_the_claim` (`crates/idboardd/src/lib.rs:632`) green.

---

## 4. `idboard-acl.Config.load.trust-root-file-read-without-custody-check`

**`config.toml` is the sole trust root and is consumed by a bare read with no ownership, permission, or reparse-point check, while the only confinement helper in the tree compiles out on the primary platform.**

`Config::load` is `std::fs::read_to_string` (`crates/idboard-acl/src/lib.rs:252`) — no owner, permission, DACL, reparse-point, canonicalisation, or integrity check. A substituted key is **self-consistent**: the fingerprint is derived from the parsed key (`:207`) rather than read from config, so the cross-check at `crates/idboard-core/src/keys.rs:308-317` cannot detect it. The only signal is the rotation warning (`crates/idboardd/src/main.rs:86-93`).

The state root is created by `ensure_dir` (bare `create_dir_all`, `crates/idboard-store/src/lib.rs:115`) and a second permissive call site at `crates/idboard/src/lock.rs:60`; `ensure_private_dir`'s only added action is `#[cfg(unix)]` and its non-unix arm is `let _ = dir;` (`crates/idboard-core/src/layout.rs:174-177`). **Verified:** a workspace-wide search for `security_descriptor`, `set_dacl`, `set_permissions`, `PermissionsExt`, `sddl` returns **three** hits, all `#[cfg(unix)]`. There is no Windows file-ACL code anywhere.

**Validation correction — the affected principal is narrow.** `README.md:42-49` puts a same-user process inside the documented boundary and `:54` puts root/SYSTEM/administrator outside the threat model entirely. **The only in-scope principal is a second non-administrative local account.** Whether the inherited DACL permits that account to write is a platform fact asserted only in a comment at `layout.rs:163-166`.

**Bounded local check:** throwaway Windows VM, two local accounts. Create the state root and a config with one identity whose pubkey came from `keygen` under the second account; as that account, try to append a second entry and separately to delete-and-replace. Then start the daemon and read the startup summary. **Stop after reading the summary; do not exercise the substituted identity against a live board.**

**Deployment read:** `icacls` the state root and `config.toml`; record owner, inheritance source, and every principal with write or modify. Compare against the intended list (owning account + SYSTEM). Write access to any other principal resolves in favour of the finding; otherwise it closes as an inherited-ACL assumption that holds here.

---

## 5. `idboard-store.read-projection-drops-signed-channel`

**The read projection omits the persisted `channel` column and substitutes an empty one, so a message read back from the board is not the envelope that was authenticated.**

`Store::read`'s `SELECT` list (`crates/idboard-store/src/lib.rs:275`) omits `channel` even though it is both the `WHERE` predicate (`:277`) and a persisted column written from the authenticated envelope (`:239`); `row_to_message` hardcodes `channel: String::new()` (`:357`). The JSON path publishes the empty field verbatim because `StoredMessage` flattens the envelope (`crates/idboard-core/src/wire.rs:21-22`).

**Two validation corrections:** `envelope.rs:212` is `put_u16`, not `put_u32`; and re-verification fails **earlier** than originally stated — `verify_with_key` calls `env.validate()` (`crates/idboard-core/src/keys.rs:282`) before building canonical bytes, and the post invariants call `validate_channel` (`crates/idboard-core/src/envelope.rs:286`), which rejects the empty string (`crates/idboard-core/src/ids.rs:74-76`) with `bad_request`. It fails closed.

**Containment, established not overstated:** no cross-channel disclosure. The filter is parameterised, the ACL is checked against the verified identity at `crates/idboardd/src/lib.rs:203` before the query at `:209`, and the stored `sender_id` is bound from the config-derived name (`store/lib.rs:240`). `handle_post` returns the full cloned envelope (`:253`), so a poster sees its channel intact while a reader does not. **Verified:** no production code re-verifies a read-back message.

**Bounded local check:** in `crates/idboard-store`, add a test that posts to a channel, reads it back, and asserts both that the read-back channel equals the original and that re-verification against the signer's public key succeeds. Both must fail now, both must pass after the fix.

**Deployment read:** run the JSON read form against a scratch board holding one message and observe the empty channel field. Display confirmation only; no mutation.

**Fix:** add `channel` to the `SELECT` list and pass the row value into the envelope. The fixed `op` and empty `nonce` may stay — a post with an empty nonce is the correct shape for the only thing `append` ever persists.

---

## 6. `idboard-store.open-creates-state-root-without-private-mode`

**`Store::open` creates the state root holding `idboard.db` with the permissive directory helper, while sibling directories in the same root use the owner-only helper.**

`Store::open` calls `ensure_dir` (`crates/idboard-store/src/lib.rs:115`, bare `create_dir_all` at `crates/idboard-core/src/layout.rs:157-159`). Siblings: `crates/idboard/src/keystore.rs:112` and `crates/idboard/src/wrapper.rs:227` use `ensure_private_dir`; `crates/idboard/src/lock.rs:60` (found by the validator) uses the permissive one again. The file carrying every message body gets the permissive treatment while the directory carrying the seeds does not.

**Validation correction — this bounds the finding sharply.** On the project's **primary** platform the two helpers are **behaviourally identical**, because `ensure_private_dir`'s only added action is `#[cfg(unix)]` and its non-unix arm is `let _ = dir;` (`crates/idboard-core/src/layout.rs:174-177`). **The divergence has no effect on Windows at all.** This is a **Unix-only** hardening gap, and on Unix its size is set by the process umask and the SQLite library default for a new file — neither visible in this repository.

**Bounded local check (Unix only):** known umask, scratch state root, `idboardd --check` (reaches `Store::open` via `crates/idboardd/src/main.rs:83` and `:95`). `stat` the state root and the database; compare with the `keys` directory. Expect the root and database to be less restrictive.

**Deployment read:** list permissions/ACLs for the state root, `keys`, and the database files. If the deployment is Windows-only, record that the code path is the no-op and the divergence has no effect there.

**Fix:** call `ensure_private_dir(parent)` at `store/lib.rs:115` and the same at `crates/idboard/src/lock.rs:60`. A stronger variant also opens the database with an explicit owner-only mode, since directory mode alone does not constrain an already-existing file.
