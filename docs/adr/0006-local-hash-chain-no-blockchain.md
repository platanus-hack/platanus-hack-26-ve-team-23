# ADR-0006: A local hash chain with a phone witness; no blockchain

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The record of what the agent attempted is only useful if nobody can rewrite
it without being detected. Two adversaries matter:

| Adversary | What is enough |
|---|---|
| The agent or the PC tries to erase its traces (the central case) | A hash chain on the Guardian, with its head signed and sent to the phone. The PC controls neither. |
| An external auditor does not trust the company that runs the system | A witness independent of the company. |

A blockchain only adds integrity if its validators are independent of whoever
might want to alter the logs. A chain run by the same company, or by peers
that all belong to it, proves nothing the company could not rewrite.

## Options considered

### Option 1: our own chain (validators, finality, genesis authority)

- Benefits: easy to market.
- Drawbacks: no independence if we run the validators; most of the
  hackathon time would go into consensus instead of detection; does not fit
  on the Pi.

### Option 2: a peer-to-peer chain between users

- Benefits: some decentralisation.
- Drawbacks: needs many independent participants we do not have; consensus
  is not needed, attestation is.

### Option 3: anchoring in a public chain (OpenTimestamps on Bitcoin, Solana memo)

- Benefits: truly independent validators without operating a chain.
- Drawbacks: requires explaining blockchain to judges and sponsors who do
  not work with it, for no gain against the central adversary.

### Option 4: local hash chain and phone witness

- Benefits: covers the central adversary; simple; demonstrable in seconds.
- Drawbacks: does not protect against a company that controls both the
  Guardian and the phone.

## Decision

Every event (proxy request and response, hook request, decision, alert,
log opening) is appended to a hash chain on the Guardian. At regular
intervals and after every high-severity event, the Guardian signs the chain
head and sends it to the phone, which stores it. A rewritten chain no longer
matches the heads on the phone.

No chain of our own is operated, and none is part of the demo. Anchoring
heads in a public chain is recorded as a future option for the enterprise
edition, not implemented.

### Key points

- **Integrity is not truth.** A chain, local or public, only proves that
  what was sealed was not changed afterwards. If the component that seals
  runs on the infected machine, the attacker decides what gets sealed:
  omitted actions, invented events and signatures with stolen keys are
  anchored as faithfully as real ones. That is why capture and sealing run
  on the Core, a separate device, and why public anchoring adds nothing
  against the central adversary.
- **Events are encrypted in batches** with the weekly epoch key (ADR-0007);
  the chain covers the ciphertext, so integrity can be checked without
  reading the content.
- **Weekly erasure:** destroying an epoch key makes that week unreadable;
  the hashes keep proving that it existed and was not altered.

## Dependencies and licences

None decided yet; the hash and signature libraries must satisfy ADR-0011.

## Consequences

### Positive

- Time goes to detection and measurement, which is what the track evaluates.
- The integrity argument holds up without blockchain vocabulary.

### Tradeoffs

- No protection against a company that controls every device; revisit with
  public anchoring if the enterprise edition needs third-party audits.

## Implementation

### Next steps

1. Event format and hash chain on the Pi.
2. Signed head delivery to the phone.
3. Verifier: recompute the chain and compare with the heads on the phone.

## Related decisions

- ADR-0003: where the chain lives.
- ADR-0007: keys that sign heads and encrypt batches.

## References

- RFC 6962, Certificate Transparency (signed tree heads and witnesses).
- OpenTimestamps.

## History

- v1.0 (2026-10-24): Initial decision.
