# ADR-0001: Record architecture decisions

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The project is built in a few days by a small team, with design decisions
taken in conversations with people and with coding agents. Without a record,
the reasons behind the threat model, the topology and the cuts made for the
demo are lost, and judges or new contributors cannot tell deliberate
trade-offs from accidents.

## Options considered

### Option 1: keep the reasons in the README and the whitepaper

- Benefits: no new process.
- Drawbacks: those documents describe the system as it is; rejected options
  disappear.

### Option 2: Architecture Decision Records in the repository

- Benefits: versioned and reviewed with the code; rejected options are kept.
- Drawbacks: one more file for each significant change.

## Decision

Significant decisions are recorded as ADRs in `docs/adr`, following the
[index](README.md) and the [template](0000-template.md). Proposals that need
discussion first start as RFCs in `docs/rfcs`. The repository is written in
English.

### Key points

- **One decision per record**, small enough to review and to supersede.
- **Immutable once accepted**; a changed decision gets a new ADR.
- **Rejected options are part of the record**: the cuts made for the demo
  (for example, no blockchain in ADR-0006) are as important as what is built.

## Dependencies and licences

None.

## Consequences

### Positive

- The reasoning behind the demo is reviewable, including what was cut.

### Tradeoffs

- Writing an ADR slows a change down a little; that is intended.

## Implementation

### Where it lives

- `docs/adr/README.md`, `docs/adr/0000-template.md`, `docs/rfcs/README.md`.

## Related decisions

- All later ADRs follow this process.

## References

- Michael Nygard, "Documenting Architecture Decisions" (2011).
- Format adapted from the Nepheral ADRs.

## History

- v1.0 (2026-10-24): Initial decision.
