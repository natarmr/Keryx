# `run-1` reconciliation

`run-1/` is the output of a prior, source-only security audit. All six records
are `needs_validation`: nothing was built or executed, so none of them is a
confirmed finding. This file records what happened to each one since, so a reader
does not have to re-derive it by diffing the report against the tree.

Do not edit `run-1/` to match. It is the historical record; this is the current
state, and where the two disagree the code is newer.

| # | Lead | Status | Settled by |
|---|---|---|---|
| 1 | Board mutex held across the peer read | **Fixed** | `serve()` takes `board.lock()` around `Board::handle` only; pinned by `a_peer_that_never_writes_cannot_withhold_the_board_from_other_identities` (e2e) |
| 2 | `apply_timeouts` swallows `Unsupported`, so no deadline | **Partly fixed, rest disclosed** | `deadlines_installed()` reports what was actually installed; `read_frame_deadline` bounds the read independently; pinned by `a_peer_that_never_writes_is_given_up_on_rather_than_waited_forever` and `applying_timeouts_never_fails_and_reports_what_it_actually_installed` |
| 3 | Unbounded envelope strings reach the rejection log | **Fixed** | `rejection_line` bounds and quotes every attacker-influenceable field; `log_token`/`log_detail` are pinned by their own tests |
| 4 | Config read with no custody check | **Fixed, with a stated residual** | `Config::load` checks regular-file, not-a-symlink, and on Unix owner + mode; `Config::custody_statement` says exactly what is *not* checked on Windows; `check-custody-claims.ps1` checks every `cfg` arm |
| 5 | Read projection drops the signed `channel` | **Fixed** | The projection selects `channel`; pinned by `a_read_back_message_still_verifies_against_its_signer` (and the daemon-side twin) |
| 6 | State root created without a private mode | **Partly fixed, rest disclosed** | `ensure_private_dir` chmods on Unix; on Windows it is a no-op beyond `create_dir_all` and the custody statement says so; `check-custody.ps1` reports the observed DACL |

## The one item that cannot be settled from this tree

Lead 2's decisive question — does `interprocess` return `Unsupported` for a
named-pipe stream, or install a real deadline? — is a property of a third-party
crate, not of this repository. The code is written for the worse answer
(`Unsupported`), reports it at runtime through `deadlines_installed()`, and does
not depend on the socket having a deadline. The remaining cost, if the worse
answer holds, is a parked reader thread per stalled peer, bounded by the fixed
worker pool (`WORKERS = 4`, `QUEUE_DEPTH = 64`) rather than by the socket. That is
a residual, not an open hole, and it is stated in `README.md` under "Deliberate
limitations".

## Windows listener DACL: reviewed, not changed

This is the one security item that could plausibly be "finished" by adding a
hand-built Windows security descriptor to the pipe listener. On the machine where
`scripts/check-custody.ps1` was last run it **reports the standard-profile outcome**:
the state root inherits full control for the owner, `SYSTEM` and `Administrators`,
and no broader in-scope principal is visible. README "What keryx does *not*
defend against" states that same-user processes are inside the boundary by design.

Adding a descriptor now would be ~80 lines of `unsafe` Win32, a new platform
dependency, and a new way for a listener to fail closed in a way operators would
have to debug, while protecting against no additional account on this machine.
That is the cost/benefit decision, not a claim that the pipe is authenticated.

Decision: document the residual and leave the listener untouched. Re-open only
after `scripts/check-custody.ps1 -IncludeSocket` on a machine whose creating token
DACL demonstrably grants a broader in-boundary principal; then the implementation
plan is explicit, not ad-hoc:

1. Build `InitializeAcl`/`AddAccessAllowedAceEx` for the creating token's default
   principals only, never `Everyone`.
2. Apply it at socket creation in `idboard-ipc`, behind `listen_options`, with no
   change to the daemon's authorisation logic.
3. Pin `listener_custody_statement()` to the measured DACL, and keep
   `check-custody-claims.ps1` green.

If none of those three is true on the target machine, the change is wrong by
construction.

## What the audit did not cover, and now exists

The audit predates `keryx mcp`, `keryx inbox`, `keryx peers`, and
`[limits]`. The trust-boundary property they must all preserve is the same one:

- `keryx mcp` is a front-end over `RelayClient`, never a second route to the
  daemon, and takes no identity argument.
- `inbox` and `peers` are read-class queries signed by the wrapper, so they cost
  no sequence numbers and cannot be constructed by a child.
- The post budget is charged after authorisation and before the append, so a
  refused request is neither stored nor charged, and reads are never charged.

Each of those has a test in the crate that owns it, and the tests assert on a
specific `ErrorCode` rather than on "not ok".

## Key storage hygiene (future OS-keyring direction, not implemented)

Seeds stay as `0600` files under `keys/` today; no keyring code exists. A
future move to an OS keyring (DPAPI / libsecret / Keychain) would change where
bytes rest, not the trust model: a same-user process remains in-boundary by
design, and the rotation story is already fixed as `keryx keygen <id> --force`
(remove-then-create through the atomic link path, after printing the old
pubkey/fingerprint warning) + config `pubkey` update + daemon restart, which is
the path the startup rotation warning already watches. `--dry-run` exists so an
operator can preview the pubkey/fingerprint without touching disk, and
`keryx doctor`'s `key-permissions` check (Unix: warn on group/other-readable;
Windows: inherited-DACL note, no enforcement claimed) is the observable that a
keyring move would have to keep reporting against.
