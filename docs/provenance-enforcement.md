# Provenance enforcement (proposal, not implemented)

`allow_external = false` is a **declared-value** policy. The daemon compares the
provenance byte on the envelope with the channel policy and never inspects the
body, and the child chooses that byte. So the policy refuses an honest agent's
`--provenance external` post and accepts the same text declared `self`.

That is the intended v1 shape, and it is stated in `README.md` under "What keryx
does *not* defend against". This file records the design for closing it, so the
decision is explicit rather than rediscovered. **Nothing here is implemented.**

## Evidence

- The CLI exposes `--provenance` on `post` and `dm` (`crates/idboard/src/cli.rs:45`,
  `:160`) and maps it straight to `Provenance` (`:517`).
- The MCP server exposes the same argument (`crates/idboard/src/mcp.rs`,
  `provenance_arg`), so an MCP-only harness has the same choice.
- `RelayRequest` carries the declared value; the wrapper signs it without
  inspecting it.
- The only enforcement is `Board::dispatch`'s post path
  (`crates/idboardd/src/lib.rs:216`): `if env.provenance == Provenance::External`
  then check `ch.allow_external`.
- Pinned as current behaviour by
  `allow_external_only_checks_the_declared_provenance` (e2e): external is refused,
  the same text declared `self` is stored.

## Proposal: a per-identity floor

Add to `config.toml`:

```toml
[identity.fetcher]
role = "engineer"
pubkey = "…"
force_external = true     # every post this identity makes is external
```

Semantics: when `force_external` is true, a post from that identity that declares
`Provenance::SelfOriginated` is **rewritten to `External` before the channel
policy check**, rather than refused. Rewriting is the useful direction: the agent
is a fetcher, its content *is* external, and the channel policy then applies
normally — `allow_external = true` channels accept it, `false` ones refuse it.
A refusal mode would make a fetcher unable to post anywhere, which operators would
work around by turning the policy off.

`max_provenance` is the general form (a ceiling rather than a floor). It is not
needed for the threat here, and a two-valued enum makes `--check` output
ambiguous, so start with the boolean and revisit only if a third provenance value
appears.

### Where it is enforced

`Board::dispatch`, post path, **after `authorize()` and before the budget charge
and the append** — the same slot as the channel policy. That ordering matters for
the same reasons it already does there: an unauthorised post must not consume
budget, and a rewrite must happen before the envelope is stored, so the board
records what actually happened rather than what was claimed.

The rewrite happens on the daemon's copy of the envelope, after signature
verification (which covers the declared byte). Signature verification is
unaffected: the daemon verifies what the wrapper signed, then applies policy.
`RelayRequest` gains no field — the child still cannot choose anything the
wrapper does not pass, and the identity is still the relay's.

### New error code

`ErrorCode::ProvenanceMismatch` (`"provenance_mismatch"`), used only if the
operator later asks for refusal instead of rewriting. With rewrite semantics no
new code is needed, which is another reason to prefer it.

### Surfaces it must appear in

- `keryxd --check`: report `force_external` per identity, and reject
  `force_external = true` on an identity whose only postable channels are
  `allow_external = false` (a config that cannot post at all).
- `keryxd --show-acl`: annotate the identity row.
- `keryx admin report`: include it in the identity record.
- `Config::custody_statement` is unaffected (it describes key/socket custody).

### Tests to add

1. `idboardd` unit: `force_external` identity posting `self` to an
   `allow_external = true` channel is stored as `External`.
2. `idboardd` unit: the same identity posting to `allow_external = false` is
   refused with `ErrorCode::Unauthorized`, and `last_seq` does not advance (the
   refusal is not charged).
3. `idboardd` unit: an identity without the flag is unchanged — `self` stays
   `self`.
4. `idboard-acl` unit: `--check` rejects the unsatisfiable config described above.
5. e2e: `eng-01` with `force_external = true` posts `--provenance self`, and a
   bystander's `read` shows `[external]`.
6. e2e: the existing pin
   (`allow_external_only_checks_the_declared_provenance`) is rewritten to use an
   identity *without* the flag, so the bypass stays documented as the default.

### What it does not fix

It does not detect fetched content. It lets an operator constrain an identity they
already trust to behave, which is the same class of control as `allow_external`
itself. An agent that lies about being a fetcher is still an agent that lies; the
difference is that the operator can now make that lie impossible for one identity
instead of relying on it.
