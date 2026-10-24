# ADR-0019: Hybrid post-quantum signatures on chain heads

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The record is evidence that may be needed years later. A signature that a
future quantum computer can forge lets someone fabricate signed heads after
the fact. The hash chain itself (SHA-256) keeps a large security margin
against quantum attacks; the weak point is the signature on each head
(Ed25519 in ADR-0014).

## Options considered

### Option 1: Ed25519 only

- Benefits: small, fast, mature.
- Drawbacks: forgeable by a large quantum computer.

### Option 2: ML-DSA (FIPS 204, lattice-based) only

- Benefits: standardised post-quantum signature; signatures of about 3 KB;
  fast on a Raspberry Pi.
- Drawbacks: young implementations; if a flaw is found, nothing else
  protects the heads.

### Option 3: SLH-DSA (FIPS 205, SPHINCS+, hash-based)

- Benefits: security rests only on hash functions; the most conservative
  assumption.
- Drawbacks: signatures of 8 to 30 KB and slow signing; heavy for frequent
  heads.

### Option 4: hybrid Ed25519 + ML-DSA

- Benefits: a forgery must break both; post-quantum protection without
  betting everything on a young implementation.
- Drawbacks: two signatures per head (about 3.3 KB).

## Decision

Every signed head carries two signatures over the same bytes: Ed25519 and
ML-DSA-65. A head is valid only if both verify. SLH-DSA is reserved for
optional daily checkpoints, where size and speed do not matter.

### Key points

- **Domain separation:** the signed bytes start with a fixed tag, so a head
  signature can never be confused with another message.
- **Owner keys stay P-256:** passkeys (ADR-0017) are not post-quantum; the
  platforms do not offer it. Declared in SECURITY.md.
- **No claim beyond what holds:** the implementation is not audited; the
  pitch says "hybrid post-quantum signatures", not "quantum-proof".

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| ml-dsa (RustCrypto) | 0.1 | Apache-2.0 OR MIT |
| slh-dsa (RustCrypto, checkpoints only) | 0.2 | Apache-2.0 OR MIT |
| ed25519-dalek | 2 | BSD-3-Clause |

## Consequences

### Positive

- Heads cannot be forged later even with a quantum computer, as long as
  either scheme holds.

### Tradeoffs

- Larger heads on the wire to the phone; still small.
- RustCrypto's ML-DSA is pre-1.0 and unaudited.

## Implementation

### Next steps

1. Signed head type in `guardian-core` with both signatures and golden
   tests.
2. Verification in `witness`.

## Related decisions

- ADR-0006: the heads being signed.
- ADR-0014: amends the signature choice.

## References

- NIST FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA).

## History

- v1.0 (2026-10-24): Initial decision.
