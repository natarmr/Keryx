# E4 — Which Part C cuts become trivial after E3

No feature deleted or moved (per brief). This note records which rows of the
Part C cut list (`docs/phase0-and-part-c.md` §8) are now one-file or one-crate
operations because `crates/idboard/src/cli.rs` (4422 lines) was split into
`cli/mod.rs` + `cli/bus.rs` + `cli/workflow.rs` + `cli/operator.rs` with no
behavior change (E3).

## Cut list (7 rows) vs. E3 modules

| # | Cut | Where it lives after E3 | Trivial after E3? | Why / what remains |
|---|---|---|---|---|
| 1 | `search` / `thread` / `around` + flags | `cli/operator.rs` (`cmd_search`, `cmd_thread` + `collect_search_hits`, `thread_window`) | **Yes — delete or crate-move is one module** | All three are `operator` only; no `bus` or `workflow` caller touches them. Removing the three `Command` variants and the two `fn cmd_*` plus their helpers is a single-file edit; moving them to `keryx-view` is `operator.rs` → crate. |
| 2 | `watch` (poll-based staleness) + `console --watch` / `peers --watch` | `cli/workflow.rs` (`cmd_watch`) + `cli/operator.rs` (`cmd_console`/`cmd_peers` watch arms) | **Half trivial** | `cmd_watch` itself is one `workflow` file. The `--watch` arms of `console`/`peers` live in `operator`, so a full “remove all watch” still touches two modules, but each is isolated. |
| 3 | `web` console | `cli/operator.rs` (`cmd_web` + `web_data`, `web_board`, `response_for_request`, `host_is_acceptable`, `header_value`, `web_bind_is_loopback`, `WEB_HTML`) | **Yes** | Entire console is `operator`; no `bus`/`workflow` import. Delete `Command::Web` + `fn cmd_web` and its helpers, or move `operator.rs` web section to a `keryx-web` crate. |
| 4 | `focus` + `heartbeat` | `cli/workflow.rs` (`cmd_focus`, `cmd_heartbeat`) | **Yes** | Both are `workflow` only; `focus` uses `board_summary` (now `super::board_summary` via `super::*`) but that helper lives in `mod.rs` as `pub(crate)` and is not `operator`-only. Moving them is one file; deleting is two `Command` variants + two fns. |
| 5 | `cursor` save/load (`--since-last`, `--save-cursor`, `cursor` subcommand) | `crates/idboard/src/cursor.rs` (300 LOC) + `cli/operator.rs` (`cmd_cursor`) + `cli/bus.rs`/`workflow.rs` (`--since-last` arms in `cmd_read`/`cmd_subscribe`/`cmd_replay`) | **Not trivial from E3 alone** | `cursor.rs` was already a separate file (good). The `cmd_cursor` handler is now `operator`, but `--since-last`/`--save-cursor` handling is spread across `bus` (`read`, `subscribe`) and `workflow` (`replay`). A full cut still touches three modules plus `cursor.rs`. E3 did not centralize cursor flag handling. |
| 6 | Agent workflow **as a crate** (move, not delete) — `tasks.rs` (686 LOC) + `task`/`next`/`replay --task` + MCP task tools | `crates/idboard/src/tasks.rs` (already separate) + `cli/workflow.rs` (all `TaskCommand` handlers, `ensure_task_write_allowed`, `cmd_task`, `cmd_replay` task filter, `cmd_watch` staleness uses `tasks::*`) + `crates/idboard/src/mcp.rs` task tools | **Yes — trivial to crate-move** | This was the main payoff of E3. Before E3, `cmd_task` (333 lines) lived inside `cli.rs` with `bus` helpers. After E3, every line that touches `idboard::tasks` is in `workflow.rs` (plus `tasks.rs` itself). Moving `workflow.rs` + `tasks.rs` + the four MCP task tools to `keryx-task` is `use idboard::tasks::*;` and `use super::*;` → `use keryx_task::*;`. No `bus` or `operator` helper is dragged; `bus` only re-exports `Provenance` via `super::*`. Deleting it would likewise be one `mod workflow` removal plus `tasks.rs`. |
| 7 | `mcp` (all 10 tools) | `crates/idboard/src/mcp.rs` (1222 LOC, already separate) + `cli/operator.rs` (`Command::Mcp` one-liner) | **Already trivial before E3** | `mcp.rs` was a separate file since `782f0eb`. E3 changes nothing; the `mcp` CLI entry is one line in `operator` (`operator::cmd_*` would be `mcp::run_stdio` but it just delegates). Deleting `mcp.rs` + `Command::Mcp` remains one-file. |

## Summary

After E3, **rows 1, 3, 4, 6 are one-module operations** (`operator` or `workflow` alone) and **row 7 was already**. Row 2 is split across `workflow` + `operator` but each half is isolated. Row 5 remains cross-cutting because `cursor` flag handling was not centralized by the split; centralizing it (e.g., a `cli/cursor.rs` that owns `--since-last`/`--save-cursor` parsing) would make row 5 trivial as well, but was out of scope for E3's “no behavior change”.

No file was deleted or moved in E4; this is a report-only assessment. The next step that would make row 5 trivial is to move `cursor.rs` flag handling into a dedicated `cli/cursor.rs` and have `bus`/`workflow` call it, but that is not done here.

## Verification

```
# Modules after E3
ls crates/idboard/src/cli/
# bus.rs 499 lines, workflow.rs 951 lines, operator.rs 1477 lines, mod.rs 2933 lines (was 4422)
# No feature removed
git diff --stat HEAD~1
# shows only the split, no deletion
```
