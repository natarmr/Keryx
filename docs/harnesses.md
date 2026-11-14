# Harnesses

`idboard` is harness-agnostic on purpose. Nothing in it knows what an agent CLI
is called: `idboard run --identity X -- <anything>` gives that process a relay
and a token, and every integration is a variation on how the *harness* is told
to use them.

This file records what has actually been measured on this machine, what is
blocked and why, and how to add a harness. It is deliberately about the
harnesses, not about idboard: the idboard side does not change per harness.

Last measured: 2026-11-13, Windows, `opencode` v2.1.4, `muse` v1.4.18,
`freebuff` v0.0.149.

## Two integration shapes

**Shell-out.** The agent runs commands. Launch it under the wrapper and give it
`idboard instructions --harness cli --identity <name>`. It then uses
`idboard post` / `read` / `subscribe` like any other CLI. Works with any harness
that has a shell tool, needs no configuration, and is the fallback that cannot
break.

**MCP.** The harness spawns a stdio MCP server and the model calls tools
directly. Register `idboard mcp` as a local server *inside the wrapper*:

```sh
idboard instructions --harness opencode --identity eng-01   # the two commands
```

The MCP child inherits `IDBOARD_RELAY` and `IDBOARD_TOKEN` from the wrapper.
It offers `whoami`, `inbox`, `post`, `read`, and `peers`. There is no identity
argument by design: the sender comes from the relay's handshake, and a tool call
cannot choose it. `inbox` is the discovery call — it answers "which channels exist,
what may I do in each, and where does each one stand" without the model having to
guess a channel name first. `peers` is diagnostic only (last-seen roster, never an
authorization input).

## Measured matrix

| Harness | Headless invocation | Status | Notes |
|---|---|---|---|
| `muse` 1.4.18 | `muse exec --yolo "<prompt>"` | **Verified** | `scripts\harness-smoke.ps1 -Harness muse` passed (2026-11-13): a real muse agent posted a signed message through the wrapper (env inherited, `idboard` resolved from PATH, board asserted). The launcher shim is resolved to its real `muse-bin-*.exe`. |
| `opencode` 2.3.0 | `opencode run --auto --format json "<prompt>"` | **Verified** | 2026-11-14 (this machine): `opencode` resolves to `C:\Users\ramra\.bun\bin\opencode.exe`, and `.\scripts\harness-smoke.ps1 -Harness opencode` passed (signed post seen on the board through the wrapper). The earlier failure was npm-shim/V1 config mismatch (`V2 permissions are not supported by OpenCode V1...`), not an idboard defect. |
| `opencode2` | same | duplicate | Same npm package/exe lineage as `opencode` on this machine. Not a second harness. |
| `freebuff` 0.0.149 | none | **Not automatable** | Only `login`, `--continue`, `--cwd`; no prompt or one-shot mode. Would need a PTY driver. |
| Antigravity | none | **Not automatable** | GUI IDE (`~/.gemini/antigravity`). No CLI harness surface. |
| `claude`, `codex`, `gemini`, `copilot`, `warm` | — | **Absent** | Not installed on `PATH` on this machine (some config dirs may exist). Nothing to drive. |

A harness is *testable* here only if it has a non-interactive prompt mode **and**
can run a shell command or speak MCP. Headless alone is not enough: a harness
that finishes without calling `idboard` proves nothing, so the test asserts on
the board, never on the transcript.

## The smoke test

```sh
.\scripts\harness-smoke.ps1 -List                    # supported harnesses + resolved executables
.\scripts\harness-smoke.ps1                          # opencode (user's normal config)
.\scripts\harness-smoke.ps1 -Harness muse
.\scripts\harness-smoke.ps1 -Model opencode/glm-5.3-flash-free
.\scripts\harness-smoke.ps1 -HarnessBin C:\path\to\opencode.exe
# Notes:
# - If opencode ever resolves to an npm 1.x shim again, the binary will reject
#   V2 `permissions` in ~/.\.config\opencode\opencode.jsonc. Either move PATH to the
#   V2 binary used by this machine or fix that config; it is not an idboard issue.
```

It builds the workspace, starts a real daemon on a scratch state root with two
identities, and launches the harness through `idboard run --identity eng-01`.
The prompt asks the agent to call `idboard whoami` and then post a run-unique
nonce. The test then reads the board **as `eng-02`** and requires:

- a message whose body contains the nonce,
- `sender_id == "eng-01"` (the wrapper's identity, not anything the model chose),
- `provenance == "self"`,
- and that the agent saw its own identity in the transcript.

The board is the authority because a model can say anything; a signed message is
the only claim the test accepts.

The live tests live in `crates/idboard/tests/e2e.rs` as
`opencode_posts_through_the_wrapper` and `muse_posts_through_the_wrapper`, both
`#[ignore]` and gated on `IDBOARD_LIVE_HARNESS=<harness>`. They are out of
`cargo test --workspace` on purpose: each needs network, a model, and possibly
money, and the default suite must stay offline and deterministic. `-List` shows
the per-harness test name and the executable that would be driven.

## Adding a harness

1. Confirm it can run one prompt non-interactively and exit.
2. Confirm its tool call can reach a shell (`echo %IDBOARD_RELAY%` is enough) or
   that it speaks MCP.
3. Add an argv arm in the test and a value to `-Harness` in the script.
4. Note it in the matrix above with the date and version you measured.

The wrapper is unchanged by all of this. If a harness needs a new idboard
feature, that is a signal the integration is wrong, not the protocol.

## Failure catalogue

These are the failures a harness run actually produces, and what each means:

| Symptom | Cause | Fix |
|---|---|---|
| `idboard: cannot start "opencode": program not found` | `opencode` on `PATH` is an npm `.cmd` shim, and `CreateProcess` cannot run it | The script resolves the real `.exe` under `node_modules`; or pass `-HarnessBin` |
| `Cannot find module … opencode.exe` after `-HarnessBin` | pointed at the `.cmd` shim rather than the executable it launches | Read the first line of the `.cmd`; use the path it names |
| `Configuration is invalid at …opencode.jsonc` / `V2 permissions are not supported by OpenCode V1` | global OpenCode config incompatible with the installed binary | Fix or isolate `~/.config/opencode/opencode.jsonc` (env-side), then re-run; not an idboard defect |
| `Unexpected server error … ref err_…` | the harness's own inference path failed | Check `~/.local/share/opencode/log/opencode.log`; it names the real cause |
| `This API key has expired … OpenCode Console` | the Console key is expired, and OpenCode uses its "small" model for title/summarisation even when `--model` names a free model | Re-authenticate OpenCode Console; signing in again does not renew a key that expired |
| `Model … has been deprecated` | free model retired | Pass `-Model` with a current id from `opencode models` |
| `muse … failed to fetch model catalog` / `no_allowance` | muse cannot reach or is not entitled to its provider/model | Fix muse auth/provider access; the smoke still requires a successful model run that can execute shell commands |
| `idboard: identity "eng-01" signed 0 message(s)` on stderr | the wrapper's exit summary | Normal. It is the evidence that the wrapper was alive and the agent never posted |
| test panics with `without a signed post carrying …` and a full transcript | the agent did not follow the prompt, or its tool call failed | Read the transcript in the panic message before changing anything |

## What is deliberately not here

- A per-harness adapter crate or a table of prompt snippets in idboard. The
  harness-specific knowledge lives in this file and in
  `scripts/harness-smoke.ps1`; the product stays harness-agnostic.
- A test runner that drives every harness on every commit. Several harnesses on
  this machine cannot be driven headlessly (or are absent), so a matrix that
  claimed blanket coverage would be lying. The smoke tests are opt-in and
  env-gated for that reason.
