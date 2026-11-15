# Phase 0 baseline and Part C scope

Measured after `abf7a53` (`cargo test --workspace` → 356 distinct
test functions, 278 unit + 78 e2e, 354 pass + 2 ignored). The counts below
are `wc -l` over `*.rs` on that commit; they include blank lines and
comments and are intended as a baseline, not a beauty contest.

## 1. LOC per crate (src only, tests excluded except where noted)

| crate | src files | LOC (src/*.rs) | notes |
|---|---|---|---|
| `idboard` (`keryx` lib) | 11 | **8448** (pre-E3; after E3 `cli.rs` → `cli/mod.rs` 2933 + `cli/bus.rs` 499 + `cli/workflow.rs` 951 + `cli/operator.rs` 1477 = 5860, `idboard` src ≈ 9886) | `cli.rs` alone was 4422; see per-module table (post-E3 split noted below) |
| `idboard-core` | 7 | **2307** | no I/O beyond CSPRNG; `envelope.rs` 685, `keys.rs` 587 |
| `idboardd` (`keryxd`) | 2 | **1653** | `lib.rs` 1441 (`Board`), `main.rs` 212 |
| `idboard-acl` | 1 | **973** | config, identity registry, ACL, `[limits]` |
| `idboard-store` | 1 | **978** | SQLite, replay counter, budgets for frames |
| `idboard-ipc` | 1 | **668** | `interprocess` sockets, newline-delimited JSON, frame caps |
| **total src** | 23 | **14027** (pre-E3; ≈ 15465 after E3) | plus `crates/idboard/tests/e2e.rs` **2853** |

## 2. LOC per top-level module in `crates/idboard/src`

| module | LOC | owns |
|---|---|---|
| `cli.rs` | 4422 | all subcommands, `cmd_*` handlers, web console, focus/heartbeat/watch |
| `mcp.rs` | 1222 | MCP stdio server, 10 tools, `Backend` trait |
| `tasks.rs` | 686 | task fold, `trusted_task_event`, `ready_tasks`, `live_claimer`, `owns_or_created` |
| `wrapper.rs` | 575 | `keryx run`, key check, handshake, relay bind, child env, serve loop |
| `keystore.rs` | 382 | `keys/<id>.key` (32 bytes), atomic link, no replace |
| `relay.rs` | 363 | per-invocation socket, token, signing, `Relay::handle` |
| `cursor.rs` | 300 | `cursors/<id>.json`, `CursorStore`, 1 MiB cap, `create_new` flush |
| `lock.rs` | 209 | `run/<id>.lock` advisory lock + `run/<id>.pid` |
| `client.rs` | 203 | `RelayClient` (child side) |
| `lib.rs` | 54 | re-exports |
| `main.rs` | 32 | binary shell around `cli::run` |

## 3. Subcommand count

No `clap` alias (`alias = ...`) is declared on any subcommand. The binary
aliases `idboard`/`idboardd` are compatibility shims (Cargo `[[bin]]`).

* **Top-level `Command` variants:** 28

  `post`, `read`, `subscribe`, `watch`, `inbox`, `peers`, `dm`, `react`,
  `task`, `console`, `web`, `focus`, `next`, `heartbeat`, `replay`,
  `mention`, `notify`, `cursor`, `doctor`, `search`, `thread`, `around`,
  `whoami`, `mcp`, `instructions`, `keygen`, `admin`, `run`

* **`TaskCommand` (under `task`):** 11

  `create`, `claim`, `done`, `next`, `complete`, `reopen`, `abandon`,
  `reclaim`, `link`, `ready`, `list`

* **`AdminCommand` (under `admin`):** 2

  `report`, `recent`

**Total distinct invocations: 41** (28 + 11 + 2). Including binary aliases:
43 entry points, 41 subcommands.

## 4. Which subcommands are reachable via MCP

`keryx mcp` exposes **10 tools**, all through `RelayClient` (no second auth
path):

| MCP tool | CLI equivalent | notes |
|---|---|---|
| `whoami` | `whoami` | relay handshake identity |
| `post` | `post` | `channel`+`body`+`provenance` |
| `read` | `read` | `channel`+`since`+`limit` |
| `inbox` | `inbox` | discovery, per-channel digests |
| `peers` | `peers` | last-seen roster |
| `tasks` | `task list` | filtered by `trusted_task_event` |
| `task_claim` | `task claim` | `channel`+`task_id`+`lease` |
| `task_done` | `task complete` (and `done`) | `report`+`result`+`note` |
| `next_task` | `task next` / `next` | oldest unblocked, unclaimed |
| `replay` | `replay` | per-channel or per-task trail |

Everything else (`subscribe`, `watch`, `console`, `web`, `focus`,
`heartbeat`, `search`/`thread`/`around`, `dm`/`react`/`mention`/`notify`,
`cursor`, `doctor`, `keygen`, `admin`, `run`, `instructions`) is CLI-only.

## 5. Classification

### 5.1 Subcommands

* **Core bus** — primitives the daemon enforces; without these there is no bus:

  `post`, `read`, `subscribe`, `whoami`, `inbox`, `peers`,
  `run` (the wrapper that makes the bus real), `keygen` (trust root provisioning).

* **Agent workflow** — conventions over signed messages, no new envelope type,
  no ACL input, evaluated client-side by `crates/idboard/src/tasks.rs`:

  `task` + all 11 `TaskCommand`s, `next` (alias for `task next`),
  `heartbeat`, `focus`, `replay` (also operator, but its `task=` filter is an
  agent primitive), `watch` (task staleness), `dm` (sugar for `post dm/<id>`),
  `mention`/`notify`/`react` (lightweight task-adjacent posts).

* **Agent interface** — how an agent reaches the bus; no new auth path, no
  identity choice:

  `mcp` (stdio server, 10 tools via `RelayClient`; `tasks`/`task_claim`/
  `task_done`/`next_task`/`replay` compose the same `tasks.rs` fold).

* **Operator** — diagnostics, local convenience, or human-facing views.
  They never authorise and a missing cursor/file is an error, not authority:

  `console`, `web`, `doctor`, `admin`/`admin recent`/`admin report`,
  `cursor`, `search`/`thread`/`around` (read-only projections),
  `replay` (when used as board history), `instructions`.

`cursor`/`search`/`thread`/`around`/`replay` are dual-use (agent + operator)
but classified **operator** because they are pure reads and add no state type.

### 5.2 Modules in `crates/idboard/src`

| module | class | reason |
|---|---|---|
| `client.rs` | **core bus** | child side of the relay; speaks `RelayRequest` |
| `relay.rs` | **core bus** | wrapper side of the relay; signs, sequence counter |
| `wrapper.rs` | **core bus** | owns key, lock, handshake, child env |
| `lock.rs` | **core bus** | one-live-wrapper invariant |
| `keystore.rs` | **core bus** | trust root on disk |
| `cli/mod.rs` | **mixed** | dispatches all classes; pure formatting + I/O (2933 LOC after E3 split) |
| `cli/bus.rs` | **core bus** | `post`/`read`/`subscribe`/`inbox`/`peers`/`whoami`/`run` (499 LOC) |
| `cli/workflow.rs` | **agent workflow** | `task`/`next`/`heartbeat`/`focus`/`replay`/`watch`/`dm`/`mention`/`notify`/`react` (951 LOC) |
| `cli/operator.rs` | **operator** | `console`/`web`/`doctor`/`admin`/`cursor`/`search`/`thread`/`around`/`instructions`/`keygen` (1477 LOC) |
| `tasks.rs` | **agent workflow** | single task fold shared by CLI and MCP |
| `mcp.rs` | **agent interface** | translates MCP → `RelayClient`; adds no auth (1222 LOC) |
| `cursor.rs` | **operator** | local convenience, never authority |

## 6. What could move without touching `idboard-core`, `idboard-acl`, `idboardd`, or the relay

The four bases are:

* `idboard-core` — `Envelope`, canonical bytes, `ErrorCode`, `validate_*`, paths/env.
* `idboard-acl` — config parsing, `Identity`/`Channel`, `Limits`.
* `idboardd` (`Board`) — the only place verification/authorisation happens.
* `idboard::relay` + `idboard::client::RelayClient` — the wrapper↔child contract
  (`RelayRequest`/`DaemonRequest`).

**Could move to a `keryx-workflow` / `keryx-operator` crate with only `idboard`
as a dependency (no core/acl/daemon/relay changes):**

* `tasks.rs` entirely — it is `collect_tasks_from_messages*` over
  `StoredMessage`s returned by `RelayClient::read`/`inbox`. Moving it changes
  imports only.
* `cursor.rs` — file I/O under `KERYX_CURSOR_HOME`/`<state>/cursors`; no daemon
  interaction.
* `mcp.rs` task tools (`tasks`, `task_claim`, `task_done`, `next_task`,
  `replay`) — they compose `Backend::read`/`inbox`/`post` already. The transport
  loop (`serve`) is generic over `Backend`.
* CLI handlers for `task`, `next`, `heartbeat`, `focus`, `watch`,
  `search`/`thread`/`around`/`replay`/`mention`/`notify`/`react`/`dm` — they are
  thin wrappers around `RelayClient` + `tasks` or `cursor` + formatting.

**Could move with a small seam (add a trait or a free function, no new auth path):**

* `console`/`web`/`admin`/`doctor`/`instructions` — they call `RelayClient`,
  `Config::load`/`summary`, and `collect_doctor_checks`. Moving them needs a
  `DoctorChecks` trait or a re-export, not a protocol change.

**Cannot move without touching a base:**

* `post`/`read`/`subscribe`/`whoami`/`inbox`/`peers` — they are the wire
  (`Envelope`/`DaemonRequest` vs `Provenance` etc.). Changing their shape touches
  `idboard-core`.
* `run`/`lock`/`keystore` — they define the wrapper invariant; any move drags the
  relay with it. Keeping `relay.rs` in the base is cheaper than extracting it.

Recommendation: keep `idboard-core` and `idboardd` exactly as they are. If a
split is desired, extract one crate `keryx-task` containing `tasks.rs` + the
task CLI/MCP handlers, and optionally a `keryx-view` for `cursor` + `search`/
`thread`/`around`/`replay`. Both depend only on the published `idboard`
`RelayClient` surface.

## 7. Tests that only protect non-core features

> Non-core = agent workflow + operator + agent interface. A failure here does not break
> `post`/`read`/`subscribe` or the trust boundary; it breaks discovery,
> ergonomics, or task conventions. Tests that guard signing or the trust boundary
> are **core** even if they live in `relay`/`keystore`/`client` (see re-sort below).

### 7.1 Unit tests (crate `idboard`, `cargo test -p idboard --lib` etc.)

* `tasks::tests::*` — 11 tests (link/ready/blocked, liveness, `an_external_task_event_never_moves_state`, `force_external_task_events_are_ignored_by_the_fold`, etc.)
* `mcp::tests::task_tools_list_claim_and_complete_through_the_relay`,
  `task_claim_posts_a_lease_and_replay_filters_by_task`,
  `task_tools_ignore_identity_and_token_arguments`
* `cli::tests::expired_task_leases_read_as_unclaimed`,
  `task_claim_accepts_an_optional_lease_duration`,
  `task_event_filter_selects_one_tasks_trail`,
  `task_list_accepts_a_stale_window_and_doctor_accepts_strict`,
  `task_records_carry_create_and_claim_timestamps`,
  `unleased_task_claims_never_expire`,
  `watch_and_exit_on_task_parse_from_the_cli`,
  `watch_staleness_predicates_are_pure_functions_of_now_vs_timestamps`,
  `select_stale_tasks_flags_unclaimed_and_stalled_claims` (via `watch`/`tasks`),
  `console_brief_and_watch_compose_and_json_shape_is_stable`,
  `web_dashboard_renders_claims_oldest_and_last_message_age`,
  `web_console_*`, `web_response_*`, `web_page_escapes_*`,
  `heartbeat*`, `focus*`, `replay_truncation_*`, `search_*`,
  `thread_window_*`, `exit_on_json_*`, `external_provenance_is_visible_in_text_output`,
  `admin_report_shape_carries_acls_and_never_key_material`,
  `cursor::tests::*` (6)

Re-sorted: `relay`/`keystore`/`client` tests that guard signing or the trust boundary are **core** and must stay, not non-core:

* `client::tests::no_relay_request_field_can_carry_an_identity` — structural “child cannot forge” (core)
* `relay::tests::channel_and_body_validation_happen_before_signing` — validation before signing (core)
* `relay::tests::a_valid_token_passes_authorisation_and_reaches_the_forward_step`, `a_missing_token_is_refused`, `a_prefix_of_the_token_is_refused`, `constant_time_eq_behaves_like_equality`, `tokens_are_long_and_unique` — token/bearer auth (core)
* `keystore::tests::saving_never_replaces_an_existing_key`, `seed_round_trips_exactly`, `keys_are_isolated_per_identity`, `saving_creates_the_directory` — trust-root hygiene (core)
* `lock::tests::*` — one-live-wrapper invariant (core)

Only pure-formatting / naming tests in those crates remain non-core and are not listed above (e.g., `relay_socket_names_are_namespaced_by_identity_and_suffix`, `random_suffixes_differ`).

Full list (50 `cli::tests`, 19 `mcp::tests`, 10 `tasks::tests`, 6 `cursor::tests`):

```
tasks::tests::link_marks_only_the_named_prerequisite_as_blocking
tasks::tests::ready_skips_blocked_claimed_and_done_tasks_oldest_first
tasks::tests::an_unknown_prerequisite_blocks_loudly_rather_than_passing
tasks::tests::done_tasks_are_ready_never_and_carry_result_and_note
tasks::tests::a_done_from_a_non_claimant_is_ignored
tasks::tests::the_claimer_and_the_creator_can_complete
tasks::tests::abandon_only_works_for_the_holder
tasks::tests::reclaim_is_refused_while_live_and_allowed_after_the_lease_lapses
tasks::tests::an_external_task_event_never_moves_state
tasks::tests::reopen_is_the_creators_or_the_last_holders_call
mcp::tests::task_tools_list_claim_and_complete_through_the_relay
mcp::tests::task_claim_posts_a_lease_and_replay_filters_by_task
mcp::tests::task_tools_ignore_identity_and_token_arguments
cli::tests::expired_task_leases_read_as_unclaimed ... (and 30+ cli formatting/search/thread/watch/console/web/heartbeat tests)
cursor::tests::* (6)
```

### 7.2 End-to-end tests (`crates/idboard/tests/e2e.rs`, 78 functions)

Non-core e2e (do not exercise `post`/`read`/`subscribe` as primitives):

`task_create_claim_done_and_list_use_plain_board_messages`,
`task_link_blocks_dependents_until_prerequisites_are_done`,
`task_next_and_complete_make_the_whole_agent_flow_one_step`,
`task_complete_records_result_and_note_on_the_done_event`,
`task_recovers_from_reopen_and_abandon_without_losing_the_board`,
`task_claim_lease_expiry_returns_the_task_to_the_pool`,
`task_claim_lease_is_stored_in_the_message_body`,
`task_list_stale_surfaces_old_unclaimed_work`,
`a_non_claimant_cannot_complete_or_abandon_someone_elses_task`,
`an_external_task_event_is_data_not_a_state_change`,
`replay_shows_history_and_respects_cursor_resume`,
`replay_task_shows_one_tasks_event_trail`,
`replay_limit_and_since_last_apply_per_channel`,
`message_plane_search_*` (3), `message_plane_thread_*` (2),
`focus_*` (2), `heartbeat_recommends_*`, `watch_flags_stale_*`,
`console_*` (2), `web_*` (3), `cursor_commands_round_trip_a_saved_position`,
`cursors_are_monotonic_across_identities`, `saving_and_resuming_a_cursor_is_idempotent`,
`doctor_*` (4), `admin_report_*`, `admin_recent_reuses_the_read_path`,
`mention_and_structured_subscribe_stops_on_json_field`,
`mcp_*` (2), `opencode_posts_through_the_wrapper`, `muse_posts_through_the_wrapper`,
`subscribe_exit_on_task_stops_on_the_matching_done_event`

Core e2e that *must* stay (trust boundary, ACL, framing, wrapper/relay/amount of budget):

`a_process_cannot_forge_another_identity_through_the_daemon`,
`a_verified_identity_without_permission_is_refused`, `reads_are_also_authorised`,
`provenance_is_carried_through_to_readers`, `allow_external_only_checks_the_declared_provenance`,
`an_oversized_unauthenticated_frame_is_refused_and_the_daemon_survives`,
`a_backlog_larger_than_one_frame_is_still_readable`, `an_unreachable_daemon_is_reported_clearly`,
`a_second_wrapper_for_a_live_identity_is_refused`, `a_sequence_number_is_not_reusable_*`,
`a_signature_from_the_wrong_key_is_rejected`, `a_tampered_body_is_rejected`,
`a_replayed_envelope_is_rejected*`, `the_board_survives_a_daemon_restart`,
`unknown_channel_is_distinguished_from_forbidden_one`, `an_unknown_channel*`,
`the_relay_refuses_a_request_without_its_token`, `whoami_reports_the_launching_identity`,
etc. (roughly 38 e2e)

## 8. Recommended cut list (if the repo must shrink) — with risks

Do not delete anything now (per brief). If a cut is required later, in this order:

| cut | what goes | est. LOC | tests removed | risk |
|---|---|---|---|---|
| 1 | `search`/`thread`/`around` + their CLI flags | ~210 (operator: `cmd_search` 67 + `cmd_thread` 43 + `collect_search_hits` 20 + `thread_window` 20 + `search`/`thread`/`around` CLI flags and tests) | 5 unit + 5 e2e (`message_plane_*`, `search_*`, `thread_window_*`) | Low. Pure read projections. Agents lose `--channel` search and `replay` already covers the trail; operators lose the fastest way to grep a flood. |
| 2 | `watch` (poll-based staleness) + `console --watch`/`peers --watch` | ~130 (workflow: `cmd_watch` 55 + `select_stale_tasks` + `watch` helpers; operator: `console`/`peers` --watch arms) | 3 unit + 1 e2e (`watch_flags_stale*`, `watch_and_exit_on*`, `select_stale*`) | Low. `watch` is polling the same `tasks` state `replay` can show. `--watch` is convenience. |
| 3 | `web` console | ~520 (operator: `cmd_web` 82 + `web_data`/`web_board`/`response_for_request`/`host_is_acceptable`/`header_value` + `WEB_HTML` 380) | 4 unit + 3 e2e | Low. Human dashboard; no agent path. The board is still `read`/`inbox`. Keeping `console` (text) is cheaper. |
| 4 | `focus` + `heartbeat` | ~150 (workflow: `cmd_focus` 59 + `cmd_heartbeat` 92) | 4 unit + 3 e2e | Low–Medium. Designed for harness loops, but an agent can replicate `focus` as `whoami`+`tasks`+`read`. Heartbeat loses the single-line supervisor contract. |
| 5 | `cursor` save/load (`--since-last`, `--save-cursor`, `cursor` subcommand) | ~400 (cursor.rs 300 + operator: `cmd_cursor` 58 + `bus`/`workflow` --since-last arms) | 6 unit + 3 e2e | Medium. Convenience, but poll loops that rely on `--since-last` must track cursors themselves. The daemon never reads the file, so correctness does not regress. |
| 6 | Agent workflow **as a crate** (move, do not delete) — `tasks.rs` + `task`/`next`/`replay --task` + MCP task tools + e2e task suite | ~2100 (tasks.rs 686 + workflow.rs 951 + mcp task tools ~300 + e2e task suite) | 11 unit + 13 e2e (`tasks::tests::*`, `task_*`, `an_external_task*`, `a_non_claimant*`, `force_external_task*`) | **Medium–High if deleted, low if extracted.** Deleting it removes the only cooperative primitive; agents must invent their own `task:…` convention and lose the shared fold. Extracting it to `keryx-task` keeps the tests and the wire unchanged. After E3, this is one `workflow` module + `tasks.rs` (now trivial to crate-move). |
| 7 | `mcp` (agent interface, 10 tools) | ~1300 (mcp.rs 1222 + operator: `Command::Mcp` one-liner) | 19 unit + 2 e2e (`mcp_*`) + 2 harness smokes (ignored) | **High.** Without MCP, a harness must shell out; prompt-based agents remain, but MCP-only harnesses stop working. No trust impact, but a product impact. |

**Not recommended to cut:**

* Any `idboard-core`, `idboard-acl`, `idboardd`, `relay`, `wrapper`, `lock`,
  `keystore`, `client`, `idboard-ipc`, `idboard-store` tests — they pin the
  trust boundary, the frame cap, the monotonic counter, the ACL, the post budget,
  the cursor sentinel, the single-place signature check, and the lack of trust
  on first use. Cutting them would be cutting the product.
* `allow_external` planner pin, `provenance_is_carried_through_to_readers`,
  `a_read_back_message_still_verifies_against_its_signer` — small tests with
  large consequence (see D2).
* `post`/`read`/`subscribe`/`whoami`/`inbox`/`peers` e2e — they are the only
  reason the other tests mean anything.

## 9. How to verify this report

```sh
# LOC (src only)
py -c "import pathlib; [print(p, len(p.read_text().splitlines())) for p in sorted(pathlib.Path('crates/idboard/src').glob('*.rs'))]"
# Subcommands
grep -n "enum Command\|enum TaskCommand\|enum AdminCommand" crates/idboard/src/cli.rs
# MCP tools
grep -n '"name":' crates/idboard/src/mcp.rs
# Tests by group
cargo test --workspace -- --list | grep -E "tasks::|cursor::|mcp::|cli::|e2e::"
```
