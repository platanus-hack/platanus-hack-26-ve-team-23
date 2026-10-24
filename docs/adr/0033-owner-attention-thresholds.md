# ADR-0033: Attention thresholds the owner sets from the app

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23 (approval pending)

## Context

ADR-0022 fixes how a finding's severity becomes an outcome: critical denies
and quarantines, high denies, medium asks the owner, low allows. The table
lives in code (`detect/src/policy.rs`); nobody can tune it. Owners differ:
a lab wants HAWK to ask about almost everything, a team in production wants
fewer interruptions but never to let a high finding through unseen.

Two further gaps: no rule in the catalogue was medium, so "ask" never
fired in practice, and the configuration the owner signs (ADR-0024,
ADR-0027) had no place for policy.

## Options considered

### Option 1: keep the fixed table

- Benefits: nothing to build.
- Drawbacks: one policy for every owner; the app cannot change it.

### Option 2: an outcome per severity, chosen freely

- Benefits: maximum control.
- Drawbacks: lets an owner allow critical findings by mistake; many
  combinations to explain.

### Option 3: two thresholds with floors, inside the signed configuration

The owner chooses from which severity HAWK asks and from which it denies.
Critical always denies and quarantines; a high finding is never allowed
without at least asking.

- Benefits: one idea ("from here it asks, from here it denies"), easy to
  show on a phone; the floors keep the worst cases closed.
- Drawbacks: less freedom than option 2.

## Decision

Option 3.

### Key points

- **`Thresholds { ask_from, deny_from }`** in `CoreConfig`, each a
  `Severity`. Defaults `medium` and `high` reproduce ADR-0022 exactly.
- **Floors:** a critical finding always denies and quarantines; `ask_from`
  may not be above `high`, so a high finding at least asks; `ask_from` may
  not be above `deny_from`. The Core refuses a configuration that breaks a
  floor, and the policy clamps `ask_from` to `high` in case one slips
  through (fail closed).
- **Same chain as the rest of the configuration** (ADR-0027): the owner
  signs the thresholds with the name and the firewall, the next version
  names the previous hash, and the change is recorded in the main chain.
  An enterprise signer the owner authorised can set them too.
- **Hashes stay stable:** default thresholds are left out of the JSON, so
  configurations signed before this ADR keep their hash and signature.
- **The app** shows the active thresholds in Settings and edits them in the
  configuration form, with the floors explained; the Core reports them in
  `Status`.
- **Medium rules exist:** the catalogue gains medium rules (force push,
  recursive deletes) so that "ask" happens in real use.

## Dependencies and licences

None.

## Consequences

### Positive

- Each owner tunes how often HAWK interrupts, from the phone, signed and
  recorded.
- "Ask" is reachable with the shipped rules.

### Tradeoffs

- Changing thresholds goes through the full configuration form, so a
  router password has to be typed again (the Core never returns it).
  Revisit when router secrets are sealed to the Core.
- Per-rule overrides are out of scope; revisit after the evaluation.

## Implementation

### Where it lives

- `guardian-core/src/wire.rs`: `Thresholds`, `CoreConfig.thresholds`,
  `ConfigSummary.thresholds`.
- `detect/src/policy.rs`: `apply_with`; `Detector::decide_with`.
- `guardian/src/core.rs`: validation in `apply_config`;
  `guardian/src/api.rs`: `decide` reads the active thresholds, `Status`
  reports them.
- `witness/src/commands.rs` (`configure_core`), `witness/ui`: the form and
  the Settings card.
- `detect/rules/default.json`: medium rules.

## Related decisions

- ADR-0022: the table this makes configurable; its defaults stay.
- ADR-0024, ADR-0027: the signed configuration chain.
- ADR-0031: the app's design.

## History

- v1.0 (2026-10-24): Initial proposal.
