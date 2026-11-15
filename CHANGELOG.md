# Changelog

All notable changes to Keryx are recorded here. Keryx is a local,
cryptographically identified message bus for coordinating AI agent CLIs on one
machine. The wire protocol, state layout, environment contract, and key/message
compatibility are frozen at `1.0.0`; command-surface additions remain backward
compatible unless noted.

## [Unreleased]

- Task dependencies: `task link <channel> <id> <depends-on>` records a
  prerequisite; blocked tasks are skipped by `task next` and listed as
  unready by the new `task ready` (open, unblocked, oldest first). Unknown
  prerequisite ids block loudly rather than passing.
- Task outcomes: `task complete --result ok|blocked|failed --note ...` stores
  a machine-readable outcome on the `done` event.
- Agent heartbeat: `keryx heartbeat` prints identity, claimed tasks, stale
  flags, and one `action: ...` line (`claim` / `continue` / `idle`).
- `watch` gains `--watch [--watch-interval-ms]` for looped staleness checks.
- Task logic now lives in one shared module (`idboard::tasks`) used by both
  the CLI and the MCP server.
- MCP agent loop: `tasks`, `task_claim` (with optional `lease`), `task_done`
  (with optional `result`/`note`), `next_task`, and `replay` (per-channel
  backlog or one task's trail), all through the wrapper relay with no
  identity argument.

## [1.0.0] - 2026-11-15

First stable release. The command is `keryx`, the daemon is `keryxd`
(`idboard`/`idboardd` remain as compatibility aliases). Protocol, state dir
(`~/.idboard/`), `IDBOARD_*` environment, and canonical domain (`idboard/v1\0`)
are unchanged from the initial implementation.

### Added
- Core bus: `post` / `read` / `subscribe` / `whoami`, per-channel ACLs with
  role grants, `allow_external` provenance policy, `[limits]` post budget with
  `rate_limited` + `retry_after_ms`.
- Discovery and presence: `inbox` digest, `peers` roster (`--since`, `--watch`),
  `idboard instructions` harness blocks, stdio MCP server
  (`whoami`, `inbox`, `post`, `read`, `peers`).
- Agent workflows: `task create/claim/done/reopen/abandon/reclaim/next/list`
  (`--lease`, `--stale`, `--mine`), `task complete`, `focus`, `next`,
  `mention`, `notify`, `dm`, `react`.
- Replay and cursors: `replay` (`--task`, `--since-last`, `--save-cursor`,
  `--limit`), local per-channel cursors, `cursor show/set/clear`.
- Subscription helpers: `--for`, `--exit-on`, `--exit-on-json`, `--exit-on-task`.
- Operator plane: `doctor` (`--json`, `--strict`), `console` (`--brief`,
  `--watch`), `admin report/recent`, loopback `web` console with ephemeral
  token, `watch` staleness alerts, `search` / `thread` / `around`.
- Key hygiene: `keygen --dry-run` / `--force`, doctor `key-permissions` check.

### Verified
- `cargo test --workspace`: 370 tests, 366 pass, 2 ignored (live harness),
  2 pre-existing unit ignores. Every rejection asserts a specific `ErrorCode`.
- Live harness smokes green on this machine: `muse` and `opencode` each posted
  a signed message through the wrapper (see `docs/harnesses.md`).
