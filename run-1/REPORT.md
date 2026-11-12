# Security audit report — `idboard` (repository directory `a2aboard`)

**Run status: INCOMPLETE.** `incomplete_reason: validation_budget_exhausted_then_resource_exhaustion_before_phase_5`. This is a partial pass. Read section 1 before treating anything below as coverage.

---

## 1. Run shape, and the two things that most limit this report

| | |
|---|---|
| Profile | `standard`, unscoped, no user-set budget |
| Source ref | No version control (no `.git`). Reviewed tree as of 2026-09-29: 6 crates, 22 `.rs` files, ~10.4k lines, 7 manifests, 1 script, `README.md`, `AGENTS.md`, `.gitignore`. `target/` excluded. |
| Execution policy | `sandboxed-source-and-local-only`, **degraded to source-only by user selection and host capability** |
| Agents spent | 16 — 4 reconnaissance, 9 wave-1 hunters, 1 post-wave critic, 2 Phase 3 validators, **0 Phase 5 verifiers** |
| Prior runs | None for this repository. The only prior run on this host is `OpenNote/run-1`, an unrelated project. This run is the **first coverage baseline**; there is no prior ledger, no carried confirmation, and no changed-source revalidation. |
| Deferred coverage | 8 ledger units |
| Out-of-scope coverage | 0 units — the run was unscoped |
| Confirmed findings | **0** |
| Needs-validation leads | 6 |

### Limit 1 — nothing was executed, so nothing can be `confirmed`

The audit host has **no OS-enforced sandbox**: no container or VM isolation, no empty-allowlisted-environment launcher, no read-only target or toolchain mount, and no CPU, memory, process, file-size, disk or wall-clock enforcement. Windows Smart App Control is additionally documented in `AGENTS.md:40-45` as refusing some locally built unsigned test binaries.

Therefore no `cargo build`, no `cargo test`, no `scripts/test.ps1`, no `idboard`/`idboardd`/relay process, and no test binary ran at any point. Every check in the ledger is `method: "source"`. A `confirmed` record requires a **bounded local observed result**, so **no candidate could reach `confirmed` by construction**. Every one of the eight surviving candidates that reached validation came back `needs_validation`.

**Zero confirmed findings is a statement about this host's capabilities, not a clean bill of health.** Do not read it as "nothing is wrong."

### Limit 2 — validation ran out before record verification

- **2 of 8 candidates were never validated** and are therefore *excluded from `findings.json`* rather than reported on incomplete evidence. They are candidates, not findings:
  - `idboard/cli.rs:render_message:unescaped-body-in-operator-terminal` — the Phase 3 verifier's result was truncated by the output limit after it had confirmed the mechanism and issued corrections.
  - `idboard/keystore.rs:save_seed:ungated-check-then-act-replace` — the verifier's result was lost entirely to truncation.
  - Both are archived as deferred ledger units with unresolved reasons. Their hunter traces survive in `_parent/candidates.json`.
- **Phase 5 independent record verification did not run.** The six retained records carry Phase 3 validation only. No `confirmed` record exists, so the absolute rule against skipping independent review of a `confirmed` record is not violated — but the skill's requirement to independently verify final `needs_validation` records is **not satisfied**, and a Phase 5 replacement pass found none.

### Limit 3 — the post-wave critic accepted work that was never hunted

The reserved post-wave coverage critic returned `stop: false` with six accepted missing units. They are seeded in the ledger as **deferred wave-2 work** with source-backed reasons. No wave-2 hunter ran, so the distinct final-clean critic never ran either. **No clean-coverage claim is made.** The critic's units are, in short: named-pipe/listener creation with no security descriptor; the wrapper's relay accept loop; `cmd_subscribe`'s cursor contract; the daemon's startup/`--check` lifecycle; the `rejection_line` operator sink; and the channel topic ACL / `subscribe` scope / self-declared `provenance` field.

### Corrections this audit made to its own work

- **A false exclusion reason was seeded and has been corrected in 17 ledger units.** The original wording claimed there is "no topic ACL, no wildcard subscription" in this codebase. That is **false**: the channel `post`/`read` grant lists *are* topic ACLs enforced per request, and `post = ["*"]` — the fixture every test and the README use — *is* a wildcard grant. The corrected reason is narrower and accurate. This error was introduced by the parent during coverage seeding and caught by the coverage critic.
- **Validator deviation.** Both skill validators open their input with `O_NOFOLLOW|O_NONBLOCK`, which Node does not expose on `win32`, so the stock CLIs exit before checking any rule. Wrappers in `_parent/` call the validators' own exported `validateDocument()` / `collect*` functions — identical rule sets — against a normally-opened file. Residual: the input's symlink/nonblocking-open hardening is not applied. The inputs are parent-written in the parent-owned output directory, not agent-controlled scratch, so the risk that hardening addresses does not apply.
- **Prompt-assembly deviation.** `architecture.md` was embedded verbatim in the first hunter prompt; for the remaining eight, hunters were pointed at the file and required to read it in full, with a faithful digest inline. Companion blocks were referenced by exact file path and section heading for the same reason, which also removed transcription risk.

---

## 2. Security posture, in one paragraph

The cryptographic core is genuinely well built and this audit confirmed it at source level. Verification happens in exactly one place, always with the config-registered key, always via `verify_strict`; a claimed sender name is bound to the signing key because `sender_id` is inside the domain-separated, length-prefixed canonical bytes; `authorize()` takes no argument that could substitute for the verified identity; the persisted `sender_id` is the config-derived name, not the request's; the replay counter is advanced atomically under an `IMMEDIATE` transaction with a `UNIQUE` index and never lowered by restart, rotation, or a rejected post; the two authentication mechanisms cannot borrow from each other; a child structurally cannot construct an envelope because `RelayRequest` has no field for one; and the no-trust-on-first-use control is real — `pubkey` is mandatory and `idboardd` refuses to start without it. The defects this run surfaced are overwhelmingly **not** in that core. They are in **lifecycle and custody**: a global lock held across a peer-paced read, a documented limitation whose *consequence* is materially worse than documented, unescaped operator-facing output and log sinks, a read projection that silently drops a signed field, an unauthenticated trust-root file whose only confinement helper compiles out on the primary platform, and key-file writes that are check-then-act rather than atomic.

---

## 3. Confirmed findings

None. See section 1, Limit 1. No candidate could satisfy the confirmed-record bar because the audit host provides no OS-enforced sandbox to execute the bounded local check.

---

## 4. Needs validation — priority order

Six records, all in `findings.json`, all `needs_validation`, **none carrying a severity** (severity is only for `confirmed` records). Ordered by the reader's exposure: what an unauthenticated local process can cause, first.

| # | Lead | Affected principal / resource | Exact blocker |
|---|---|---|---|
| 1 | `idboardd.serve.board_mutex_held_across_peer_blocking_io` — the single process-wide board mutex is acquired *before* the peer-paced read | **A different identity's** requests are never dispatched. Shared coordination point. One connect, zero crafted bytes, no key. | no sandbox to observe a second identity's request being withheld; pipe DACL not source-visible |
| 2 | `idboard-ipc.apply_timeouts.unsupported_swallow_removes_read_deadline` — `apply_timeouts` swallows `Unsupported` and still reports success | Fixed worker pool; per-invocation relay supervisor. | no sandbox; **and** whether `interprocess` returns `Unsupported` or a real 10 s deadline is third-party behaviour absent from this repository |
| 3 | `idboard-ipc.read_frame.unbounded-envelope-strings.daemon-rejection-log` — unbounded, unescaped envelope strings reach the daemon's rejection log | The post-incident attribution record the operator and any log-grepping agent rely on | no sandbox; pipe DACL not source-visible; terminal rendering is an emulator property |
| 4 | `idboard-acl.Config.load.trust-root-file-read-without-custody-check` — `config.toml` read with no ownership/permission/reparse-point check | The identity→key registry: a substituted key is self-consistent and defeats the fingerprint cross-check | no sandbox; **and** the state root's effective DACL is asserted only in a comment at `layout.rs:163-166` |
| 5 | `idboard-store.read-projection-drops-signed-channel` — read projection drops the signed `channel` | Board output can no longer be checked against the signature that produced it | no sandbox; whether any consumer depends on the field is a deployment fact |
| 6 | `idboard-store.open-creates-state-root-without-private-mode` — `Store::open` uses the permissive directory helper | `idboard.db` and its WAL sidecars | no sandbox; umask, SQLite file-mode and sidecar placement are all library/OS defaults outside source. **Bounded to Unix** — the two helpers are behaviourally identical on Windows |

The first two compound and are deliberately kept as **two** records: different files, different invariants, non-overlapping fixes. Fixing the lock ordering does not install a deadline; installing a deadline does not reorder the lock.

### Not a finding, and worth stating

`idboard/keystore.rs:save_seed` and `idboard/cli.rs:render_message` are the two most plausible-looking leads that this run **could not** clear. They are neither confirmed nor rejected here. Do not adopt or dismiss them on the strength of this report.

---

## 5. Hardening notes and positive patterns

Selected from the hunter `hardening` notes retained in the ledger. **None of these is a finding.**

**Positive source patterns, verified rather than assumed.** The module docs that document deliberate weakenings were each read and checked against the code, and each held up: `LocalSigner`'s deliberate non-zeroisation is a threat-model statement; the Unix-only key mode and the Windows no-op `ensure_private_dir` are disclosed in `README.md:42-49`; `verify_strict` really is the call; the ZIP-215 parse permissiveness really is mitigated by `verify_strict` plus the fingerprint cross-check. There are **zero** `TODO`/`FIXME`/`HACK`/`XXX` comments in 32 files, zero `cfg(feature=...)` in any manifest, zero `eval`/shell-mediated command strings, and every process launch is `Command::new` with an explicit argv. All 15 hygiene checklist items were worked and resolved; dependencies are fully pinned (single crates.io source, sha256 per package, zero `git+` sources), though **advisory status was not checked** — no network was used, and `cargo audit --file Cargo.lock` is a read-only owner-side check.

**Test-coverage gaps that the code's own comments invite a reviewer to trust.** `wrapper.rs` has **no `#[cfg(test)]` module at all**, so the documented stripping of `IDBOARD_DAEMON`/`IDBOARD_CONFIG`/`IDBOARD_HOME` from the child — stated as a contract in `AGENTS.md` and `README.md:291-294` — has zero unit and zero e2e coverage. The fingerprint-mismatch branch at `keys.rs:308-317` has never executed in any test. No test asserts that `verify_with_key` actually *rejects* a weak registered key (`keys.rs:511-519` only asserts `is_weak()`). `idboardd/src/main.rs` has no test module, so the accept loop, the worker pool, the board mutex and both poisoned-lock recovery paths are unexercised. `two_listeners_cannot_both_bind_the_same_name` asserts `is_ok() || is_err()` — a tautology.

**Correctness nits worth a look.** `canal_topic_acl`-adjacent grant matching is a flat OR, so a `role` equal to another identity's *name* makes one grant resolve to two identities and escapes `role_inheritance_warnings` (which fires only for roles with 2+ members) — but the resolved matrix is printed at startup, so it is not silent. `pubkey_hex` is trimmed but not lowercased, while `signer.public_hex()` is lowercase, so a pasted uppercase key fails the wrapper's equality check as a `KeyMismatch` (exit 4) — a misleading diagnostic for a correct key. `Store::last_seq` returns `Ok(unwrap_or(0))`, i.e. **fails open** for an unknown identity; unreachable today, but the wrong direction for a security counter. `write_frame` enforces its size bound *after* serialising, so a legal read page can reach ~64 MiB in the daemon's heap and then fail closed, making `idboard read` on a >1 MiB backlog impossible. `CANONICAL_DOMAIN` and `PROTOCOL_VERSION` are independent constants with nothing asserting they agree. `.gitignore:6` is `*.lock` with no slash, so it also matches the repository's own `Cargo.lock`; with no `.git` nothing is exposed today, but the lockfile is the only pinning anchor. `scripts/test.ps1` calls its probe-clearing function only on the success path, so the give-up path leaves `__SM_APP_CONTROL_PROBE` appended — the exact residue `AGENTS.md:44` says must be absent; the target file has no control flow, so it gates nothing.

---

## 6. Coverage summary

From `coverage-ledger.json` (27 units, validator-passing):

| Status | Count | |
|---|---|---|
| `covered` | 14 | wave-1 units closed with owned evidence and no candidate |
| `candidate` | 5 | units carrying the 6 validated fingerprints |
| `deferred` | 8 | 6 accepted by the post-wave critic (wave 2, never hunted) + 2 whose candidates were not validated |

**Final critic result: did not run.** The post-wave critic returned `stop: false` with six accepted missing units, so the loop required a second wave and a distinct final-clean critic. Run resources were exhausted after Phase 3, so neither ran. **No clean-coverage claim is made, and this is a partial pass.**

Every in-scope entry surface named in reconnaissance was assigned in wave 1: the daemon pipe frame and its dispatch, the daemon accept loop and board mutex, `apply_timeouts`, the wire shapes and `read_frame`, `verify_with_key`, the canonical bytes and `SignedFields`, `check_op_invariants`, environment-derived paths, ACL grant matching, pubkey registration, the replay guard, the read projection, the relay token, the relay field-filling, the child environment, the keystore, the identity lock, terminal rendering, and workspace dependency/secret hygiene. What the critic identified as missing is *lifecycle and composition* — listener creation, the relay supervisor loop, `subscribe`'s cursor contract, daemon startup ordering, the `rejection_line` sink, and the topic-ACL/provenance surface — not unexamined entry points in wave 1's scope.

**Artifacts.** `run-metadata.json`, `architecture.md`, `coverage-ledger.json`, `findings.json`, `NEEDS-VALIDATION.md`, `FINDINGS-DETAIL.md`, plus `_parent/` (build and validation scripts, `candidates.json`, `uncovered.json`) and per-agent directories.
