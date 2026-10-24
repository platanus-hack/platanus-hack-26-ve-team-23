# ADR-0007: Two-key log access; personal and enterprise editions

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The log contains everything the agent attempted, including prompts and file
contents. Reading it must require more than one secret, so that a leaked
request or a compromised Guardian alone does not expose it. The product has
two kinds of owner: one person, and a company with several administrators.

## Options considered

### Option 1: one key opens and decrypts

- Benefits: simple.
- Drawbacks: a single compromise exposes the whole log.

### Option 2: an opening key and a decryption key

- Benefits: a partial compromise is not enough.
- Drawbacks: two keys to manage; in the personal edition both live on the
  same phone.

## Decision

- **Opening key:** the owner's signing key. The Guardian hands out encrypted
  batches only for a request signed with it. Requests expire after a short
  time so they cannot be replayed, and every opening is recorded as an event
  in the chain.
- **Decryption key:** the key of the weekly epoch. Useless without the
  opening key, because there is no other way to obtain the batches.

### Personal edition

One owner. Both keys live on the same phone, separate and non-exportable.
The opening key asks for biometrics once per session; the decryption key on
every use. This protects against partial compromises (a leaked request, a
compromised Guardian) but not against someone holding the unlocked phone.

### Enterprise edition

k of n administrators are needed to open and also to decrypt. Opening uses
k signatures. The decryption mechanism is left to a later ADR, because phone
secure hardware does not support threshold cryptography natively. The
personal edition does not depend on anything from the enterprise edition.

## Dependencies and licences

None decided yet; libraries must satisfy ADR-0011.

## Consequences

### Positive

- Reading the log leaves a trace in the log itself.
- Partial compromises do not expose content.

### Tradeoffs

- In the personal edition, the phone is a single point of failure for
  reading; recovery is covered in ADR-0008.
- Open question Q21: whether the opening key alone may show the index
  (date, severity, rule) without decrypting the content.

## Implementation

### Next steps

1. Signed, expiring open request and its handler on the Guardian.
2. Weekly epoch keys on the phone, rotation and destruction.

## Related decisions

- ADR-0006: the chain records openings; batches are encrypted with epoch keys.
- ADR-0008: recovery of the owner identity.

## History

- v1.0 (2026-10-24): Initial decision.
