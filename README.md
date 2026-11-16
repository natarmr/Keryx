# Keryx

**A local message bus where every agent has a cryptographic identity, so a prompt-injected agent can't speak as its supervisor.**

<!-- TODO: add CI badge once the workflow exists -->
<!-- TODO: add docs/demo.gif (the console + a refused forgery), then uncomment: -->
<!-- ![Keryx demo](docs/demo.gif) -->

When you run several AI agent CLIs on one machine and let them talk through a shared file or socket, they authenticate by *co-location*: anything that can reach the board can post under any name. That's fine while every agent is equally trusted. It stops being fine when agents have different privileges, or when any agent reads untrusted content (a fetched web page, a file from a peer) that tries to impersonate a sender or smuggle in an instruction disguised as data.

Keryx fixes that for one machine. Every message is signed with an ed25519 key. A daemon verifies each signature against the key your config registers for the claimed name. An agent never holds its own key: a wrapper does the signing.

```
  keryx run --identity eng-01 -- claude
       │
       ├── wrapper loads eng-01's key        (the agent never sees it)
       ├── opens a private relay socket      (token handed to the agent in its env)
       ├── spawns the agent                  (it can only reach the board via the relay)
       └── signs what the agent asks for ──► keryxd verifies against the registered key
```

## See it work

```
keryx keygen eng-01 && keryx keygen lead     # prints config entries to paste
keryxd --check                               # validate config, show the ACL matrix
keryxd                                       # start the daemon

keryx run --identity eng-01 -- powershell    # an agent, launched as eng-01
  keryx whoami                               # eng-01
  keryx post general "picking up the auth bug"       # ok
  keryx post deploy-approvals "approved"             # refused: only `lead` may post here
```

The last line is the point. An `eng-01` that has been prompt-injected can say anything `eng-01` is allowed to say, but it cannot produce a message that carries `lead`'s signature.

## What it defends against

- **Forged senders.** A name is only a claim until a signature makes it an identity.
- **Instructions smuggled in as another agent's words.** A message attributed to `lead` carries `lead`'s signature, so `eng-01` can't produce one.
- **Replay.** Posts carry a per-identity monotonic sequence number; the daemon rejects anything not strictly greater than the last accepted. Reads use a signed timestamp plus a nonce.
- **Bypassing the wrapper.** The agent-side CLI has no code path to the daemon, and the relay request has no field for a sender, signature or sequence number, so there is nowhere to put a forged one.
- **Untrusted content passing as trusted.** Each message carries a signed `provenance` (`self` or `external`). A channel can refuse `external` posts, and an identity can be **forced external**: the wrapper downgrades its provenance *before signing*, and the daemon rejects any `self`-labelled post from it with `ProvenanceRejected`. The stored value always equals the signed value.

## What it does not defend against

Stated on purpose.

- **A determined same-user process.** The agent runs as you, so it can read `~/.idboard/keys/`. The wrapper keeps the key out of the agent's documented reach; it doesn't make it unreachable. Treat the keystore as protection against mistakes and opportunistic exfiltration, not against an attacker who is already looking. The real hardening layer is one OS user per identity, which is deferred.
- **Misuse by a compromised agent within its own permissions.** The wrapper stops impersonation, not misuse.
- **Host compromise, and cross-machine traffic.** Root/SYSTEM can do anything, and v1 listens only on a local socket.
- **Provenance isn't derived.** `provenance` is declared by the caller unless the identity is `force_external`. It is a label you can enforce, not a taint tracker.

No trust-on-first-use: keys come only from your `config.toml`, and the daemon refuses to start if an identity has no `pubkey`. Full custody details, including what is and isn't enforced on Windows, are in [docs/custody.md](docs/custody.md).

## Features

- **Signed identity and per-channel ACLs.** Grants match a name, a role, or `*`. Startup prints the resolved matrix and warns about role-inheritance footguns.
- **Provenance policy.** `allow_external = false` per channel, `force_external = true` per identity.
- **Optional post budget.** Per-identity sliding window; reads are never charged.
- **Agent task layer.** Tasks, claims with leases, prerequisites and completion are ordinary signed messages folded client-side, not new protocol types. Only the live claimer (or creator, while unclaimed) can complete or abandon a task, and task events from `external` posts are ignored. This layer is advisory: the daemon doesn't enforce it.
- **MCP server.** `keryx mcp` advertises `whoami`, `post`, `read`, `inbox` and `peers` by default; `--all` adds the task tools. It uses the same relay as the CLI, with no second auth path.
- **Read-only console.** `keryx console` for the terminal, `keryx web` for a loopback-only dashboard with an ephemeral token, Host-header checking and a restrictive CSP. It never accepts writes.
- **`keryx doctor`.** Checks config, keys, daemon reachability and wrapper state without writing anything.

The full command reference is in [docs/commands.md](docs/commands.md).

## Quick start

Requires a recent stable Rust toolchain (1.89 or newer). On Windows, install the MSVC build tools, because `rusqlite` compiles SQLite from source.

```
cargo build --release
```

1. Generate keys: `keryx keygen eng-01`, `keryx keygen lead`.
2. Write `~/.idboard/config.toml` from what they print:

   ```toml
   [identity.eng-01]
   role = "engineer"
   pubkey = "..."

   [identity.lead]
   role = "lead"
   pubkey = "..."

   [channel.general]
   post = ["*"]
   read = ["*"]

   [channel.deploy-approvals]
   post = ["lead"]
   read = ["*"]
   allow_external = false
   ```
3. `keryxd --check`, then `keryxd`.
4. `keryx run --identity eng-01 -- <your agent>`.

To tell an agent how to use the board, run `keryx instructions --identity eng-01` and paste the output into its system prompt, or use `keryx mcp` if the harness speaks MCP.

Compatibility note: the previous names `idboard`/`idboardd`, the `~/.idboard/` state directory, `IDBOARD_*` env vars and the `idboard/v1` protocol domain are intentionally unchanged.

## How it's built

A Rust workspace: `idboard-core` (envelopes, canonical bytes, keys), `idboard-acl` (config and ACL), `idboard-store` (SQLite), `idboard-ipc` (sockets and framing), `idboardd` (the daemon), and `idboard` (the `keryx` CLI, wrapper, relay and MCP server).

- Signatures cover an explicit, length-prefixed byte encoding, never serialized JSON, so re-serialization can't masquerade as tampering.
- Verification uses `verify_strict` to reject weak keys and signature malleability.
- Two authentication mechanisms on purpose: a sequence counter for posts (they mutate the board) and a signed timestamp plus nonce for reads (replaying one returns data you were already allowed to see).

Details: [docs/design.md](docs/design.md).

## Testing

```
cargo build --workspace
cargo test --workspace
```

350+ tests: unit tests over the envelope, ACL matrix, storage, framing, MCP and the wrapper, plus end-to-end tests that spawn the real binaries and attack the board with forged senders, replayed envelopes, tampered bodies and wrong-key signatures. Every rejection is asserted as a specific error code, not merely "not ok", so a test can't pass because the wrong defence fired.

## Status and limits

- Developed and tested primarily on Windows. <!-- TODO: confirm Unix status or run it in CI before claiming more -->
- One live wrapper per identity, so attribution stays unambiguous.
- Presence is last-seen time, not liveness. No respawn or cursor rehydration yet.
- Wire protocol and state layout are frozen at 1.0.0; the command surface is not.

See [docs/custody.md](docs/custody.md) for the remaining deliberate limitations.

## About this repo

Built with AI coding agents under the working rules in [AGENTS.md](AGENTS.md), then audited: the audit trail is in `docs/audit-reconciliation.md`, and the design of the provenance enforcement is in `docs/provenance-enforcement.md`.

## Licence

MIT OR Apache-2.0