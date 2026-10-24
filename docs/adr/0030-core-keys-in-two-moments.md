# ADR-0030: Core keys in two moments: transport at boot, head keys at activation

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The Core created all its keys at first boot: one Ed25519 key that was both
its QUIC/TLS identity and the classical half of the signed heads, plus the
ML-DSA-65 key (ADR-0019). A Core sitting dormant in a box already held the
keys that will sign its record, before any owner existed, and the owner's
pairing signature covered only the Ed25519 identity, not the post-quantum
key the app then pinned.

The head keys are what the whole record rests on; they should exist only
once an owner activates the Core, and the owner should sign for both.

## Options considered

### Option 1: keep generating everything at first boot

- Benefits: simplest.
- Drawbacks: head keys exist before an owner; the ML-DSA-65 key is pinned
  without the owner's signature covering it.

### Option 2: two moments

The transport identity at first boot (it must exist to be discovered and to
speak QUIC); the head keys when the app's wizard starts the activation,
covered by the owner's pairing signature and written only once it verifies.

- Benefits: a dormant Core holds no signing keys for a record; the owner
  signs for exactly the keys the app pins; transport and head keys are
  separate.
- Drawbacks: a pairing protocol change (`guardian.pair.v2`).

## Decision

Option 2.

### Key points

- **First boot:** `transport.json` (Ed25519 seed). This is the identity in
  the TLS certificate (ADR-0023), in the mDNS announcement and in every pin.
- **Activation:** `PairOffer`, which the wizard sends when the owner starts
  pairing, makes the Core generate the head keys (Ed25519 and ML-DSA-65) in
  memory, once per boot, and return their public half with the nonce.
- **The owner signs both:** `pair_message` = `guardian.pair.v2 || nonce ||
  transport id || head_keys_digest || app id`, where `head_keys_digest` =
  `SHA-256("guardian.head-keys.v1" || len || Ed25519 || len || ML-DSA-65)`.
  The six-digit code covers the head keys too (`guardian.confirm.v2`).
- **Written last:** only when the signature verifies does the Core write
  `keys.json` (head seeds), then `pairing.json`. A Core is never paired
  without the keys the owner signed for; a restart before that discards the
  pending keys.
- **Dormant until then:** an unpaired Core has no head keys (`Hello`
  reports none), signs nothing and denies every decision (ADR-0017).
- **Older Cores** (one `keys.json` from first boot) keep working: its
  Ed25519 seed becomes the transport identity and the same keys stay the
  head keys the app pinned.

## Dependencies and licences

None.

## Consequences

### Positive

- The record's signing keys are born with the owner, and the owner's
  signature covers the post-quantum key.
- Transport and signing keys are separate.

### Tradeoffs

- Apps and stress tools must speak `guardian.pair.v2`; an older app cannot
  pair a new Core.

## Implementation

### Where it lives

- `guardian-core/src/pairing.rs`: `head_keys_digest`, `pair_message`,
  `confirmation_code`.
- `guardian/src/core.rs`: `transport.json`, pending head keys, `keys.json`
  at pairing.
- `witness/src/commands.rs`, `eval/src/bin/stress.rs`: the app side.

## Related decisions

- ADR-0017: pairing and the owner key.
- ADR-0019: the hybrid heads these keys sign.
- ADR-0023: the transport identity.
- ADR-0029: pins name the transport identity.

## History

- v1.0 (2026-10-24): Initial decision.
