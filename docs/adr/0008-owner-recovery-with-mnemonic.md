# ADR-0008: Owner recovery with a mnemonic; weekly keys are not recoverable

- **Status:** Superseded by ADR-0017
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

In the personal edition both keys live on one phone (ADR-0007). A lost phone
must not mean losing control of the Guardian. Keys in phone secure hardware
cannot be derived from a seed or exported.

## Options considered

### Option 1: no recovery

- Benefits: simplest and strongest.
- Drawbacks: a lost phone means re-enrolling everything from scratch.

### Option 2: mnemonic recovers everything, including epoch keys

- Benefits: nothing is ever lost.
- Drawbacks: weekly erasure stops being real; anyone with the mnemonic could
  regenerate past epoch keys and read what is left on storage.

### Option 3: mnemonic recovers the owner identity only

- Benefits: control is recovered; erasure stays real.
- Drawbacks: the current week becomes unreadable after a loss.

## Decision

- At setup, the phone generates a BIP-39 mnemonic and shows it once, to be
  written on paper.
- The owner keys are derived from it (SLIP-0010, which supports P-256). For
  daily use they are wrapped by a key in the phone secure hardware, so every
  use still asks for biometrics.
- On a new phone, entering the mnemonic recovers the owner identity:
  enrolments, policies and the executor pseudonym key.
- Weekly epoch keys are random, not derived from the mnemonic, and not
  recoverable. A lost phone loses at most the reading of the current week.

### Key points

- **The paper is the identity:** whoever holds the mnemonic is the owner.
  The setup screen says so.

## Dependencies and licences

None decided yet; BIP-39 and SLIP-0010 libraries must satisfy ADR-0011.

## Consequences

### Positive

- Losing the phone does not lose the Guardian.
- Weekly erasure keeps its meaning.

### Tradeoffs

- The owner keys exist outside secure hardware at derivation time.
- Not part of the demo; revisit when the phone app is built.

## Related decisions

- ADR-0007: the keys being recovered.

## References

- BIP-39, SLIP-0010.

## History

- v1.0 (2026-10-24): Initial decision.
