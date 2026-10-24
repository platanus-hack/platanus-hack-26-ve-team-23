# ADR-0025: A Merkle tree per batch, its root inside every signed head

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The hash chain (ADR-0006) proves that nothing was changed or removed, but to
prove that one event exists an auditor must replay the chain from the
beginning and see every event before it. With an off-site archive
(ADR-0026), an auditor should be able to check one event from one archived
batch without the rest of the record.

## Options considered

### Option 1: chain only

- Benefits: already built.
- Drawbacks: proving one event exposes the whole history before it.

### Option 2: a Merkle tree over each batch, root in the signed head

- Benefits: an inclusion proof is a few hashes; the head's signatures
  (Ed25519 + ML-DSA-65) cover the root, so the proof is as strong as the
  head; works offline and needs no chain.
- Drawbacks: one more structure to encode and test.

## Decision

A **batch** is the set of events between two signed heads
(`first_seq..=seq`). The Core builds a Merkle tree over the batch and signs
its root inside the head.

- **Leaves:** `SHA-256("guardian.leaf.v1" || encode(event))`.
- **Nodes:** `SHA-256("guardian.node.v1" || left || right)`; the tree splits
  at the largest power of two smaller than the size, as in RFC 6962, so no
  leaf is duplicated.
- **Signed head v2:** the signed bytes become
  `"guardian.head.v2" || first_seq || seq || timestamp_ms || chain head ||
  merkle root`. Both signatures still have to verify.
- **Inclusion proof:** the leaf index and the sibling hashes from the leaf to
  the root; `guardian-core` builds and verifies it.

Domain tags keep leaves and nodes from being confused, so a node can never
be presented as a leaf.

## Dependencies and licences

None: SHA-256 from `sha2`, already in use.

## Consequences

### Positive

- One event can be proven to an auditor with its batch entry and a short
  proof, without the rest of the record.

### Tradeoffs

- The head format changes to v2. Heads written before the change verify only
  with v1 code; there are no production records yet.

## Implementation

### Where it lives

- `guardian-core/src/merkle.rs`, `guardian-core/src/head.rs`.
- `guardian/src/core.rs`: collects the batch and fills the root.

## Related decisions

- ADR-0006 (chain), ADR-0019 (amended: the signed bytes now carry the
  Merkle root and the first sequence number), ADR-0026 (archive).

## References

- RFC 6962, Certificate Transparency, section 2.1.

## History

- v1.0 (2026-10-24): Initial decision.
