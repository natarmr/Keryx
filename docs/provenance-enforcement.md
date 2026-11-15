# Provenance enforcement (shipped)

`allow_external = false` is a **declared-value** policy. The daemon compares the
provenance byte on the envelope with the channel policy and never inspects the
body, and the child chooses that byte — so the policy refuses an honest agent's
`--provenance external` post and accepts the same text declared `self`.

`force_external = true` is the per-identity floor that closes the gap for a
fetcher identity whose content is fetched by definition.

## What shipped

Add to `config.toml`:

```toml
[identity.fetcher]
role = "engineer"
pubkey = "…"
force_external = true     # every post this identity makes is external
```

Semantics:

* When `force_external` is true, the **wrapper** downgrades `self` to `external`
  *before* signing. The signature covers the real value, so what the daemon
  verifies is what the board stores. There is no rewrite of a signed field.
* A `self` envelope that bypasses the wrapper (forged via `daemon_raw` or any
  direct daemon socket) is **rejected** with `ErrorCode::ProvenanceRejected`
  (`"provenance_rejected"`), after `authorize()` and before the budget charge
  and the append. It is never stored and never charged. The check is in
  `Board::dispatch`'s post path (`crates/idboardd/src/lib.rs:212`), the same
  slot as the channel policy, for the same ordering reasons.
* `RelayRequest` gains no field — the child still cannot choose anything the
  wrapper does not pass, and the identity is still the relay's.
* The channel policy is unchanged: `allow_external = false` still refuses an
  `external` post *after* the floor has been applied. A `force_external`
  identity posting to a channel that forbids external is therefore refused with
  `Unauthorized` (the floor made it external, the channel forbids it).

## Where it is enforced

1. **Wrapper** (`crates/idboard/src/relay.rs:144`, `crates/idboard/src/wrapper.rs:241`):
   `Relay::post` checks `force_external` and maps `SelfOriginated → External`
   before `sign_post`. `Relay::new_with_force_external` carries the flag from
   `Config::identity(...).force_external` as loaded by the wrapper.

2. **Daemon** (`crates/idboardd/src/lib.rs:214`):
   `handle_post` checks `identity.force_external && provenance == SelfOriginated`
   immediately after `authorize` and before `PostBudget::allow` and
   `Store::append`. Stored provenance equals signed provenance by construction.

## New error code

`ErrorCode::ProvenanceRejected` (`"provenance_rejected"`), `crates/idboard-core/src/error.rs`.
Used only for the floor violation above. `allow_external = false` remains
`Unauthorized`; the two are distinct so a test can assert which policy fired.

## Surfaces that show `force_external`

* `keryxd --check` and `keryxd --show-acl`: `Config::summary()` prints
  `force_external=true` on the identity row (`crates/idboard-acl/src/lib.rs:435`).
  `--check` also *rejects* a config where a `force_external = true` identity's
  only postable channels all have `allow_external = false` — an unsatisfiable
  config that could never post (`Config::from_toml` validation).
* `keryx admin report`: `admin_report_value` includes `"force_external": bool`
  per identity (`crates/idboard/src/cli.rs:1841`), shown in both `--json` and
  text.

## Tests

* `idboardd` unit `force_external_identities_may_only_post_external` (`crates/idboardd/src/lib.rs`):
  forged `self` → `ProvenanceRejected`, not charged, seq not advanced;
  `external` → accepted; `self` from ordinary identity unchanged;
  stored provenance equals signed provenance.

* `idboard-acl` unit `force_external_is_admitted_and_unsatisfiable_configs_are_rejected`
  (`crates/idboard-acl/src/lib.rs`): `force_external = true` admitted and shown
  in summary; only-postable-all-strict rejected.

* `idboard` relay unit `force_external_downgrades_self_before_signing`
  (`crates/idboard/src/relay.rs`): wrapper downgrade before forward.

* e2e `force_external_honest_wrapper_downgrades_self_to_external`
  (`crates/idboard/tests/e2e.rs`): `keryx run --identity fetcher -- keryx post … --provenance self`
  is stored as `external` and renders `[external]`.

* e2e `force_external_forged_self_is_rejected_with_provenance_rejected`
  (`crates/idboard/tests/e2e.rs`): `daemon_raw` self → `provenance_rejected`,
  not stored, same seq with `external` then accepted, stored equals signed.

The previous pin `allow_external_only_checks_the_declared_provenance` remains,
now using an identity *without* the flag, so the declared-value property stays
visible as the default.

## What it does not fix

It does not detect fetched content. It lets an operator constrain an identity they
already trust to behave, which is the same class of control as `allow_external`
itself. An agent that lies about being a fetcher is still an agent that lies; the
difference is that the operator can now make that lie impossible for one identity
instead of relying on it to be honest.
