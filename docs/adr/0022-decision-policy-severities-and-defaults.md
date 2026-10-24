# ADR-0022: Decision policy: severities, outcomes and defaults

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The Guardian must fail closed, but a Guardian that denies everything makes
the agent useless and will be switched off by its users. The detection
stages (ADR-0005) produce findings; something must turn findings into one
outcome, consistently, and the timing values of the action tree must be
fixed.

## Options considered

### Option 1: deny unless a rule explicitly allows (allow list)

- Benefits: safest on paper.
- Drawbacks: every legitimate action needs a rule; unusable for coding
  agents.

### Option 2: allow when no signal, deny on any error

- Benefits: the agent works; failures still stop it.
- Drawbacks: an attack no rule or model recognises passes; measured by the
  evaluation and reported.

## Decision

**Fail closed on failure, not on silence.** Errors, timeouts, malformed
input and unreachable components deny. A call with no finding and a low
classifier score is allowed.

| Severity | Examples | Outcome |
|---|---|---|
| Critical | Tampering with the record, disabling or editing the hook, sending secrets out | Deny, alert, quarantine the host |
| High | Deleting or truncating logs or shell history, writing outside the workspace | Deny, alert |
| Medium | Ambiguous: unusual network destination, broad deletes inside the workspace | Ask the owner; no answer means deny |
| Low or none | Everything else | Allow |

The highest severity among the findings decides. Every decision records
which rule or stage produced it.

### Timings (initial, tuned with the evaluation)

| Value | Initial |
|---|---|
| Cross-check window between proxy and hook | 5 s |
| Owner answer to `ask` | 60 s |
| Heartbeat silence before the dead man's switch | 15 s |

### During a quarantine

Every `/decide` from the quarantined host is denied: the host is frozen end
to end. Network quarantine is per host; denial by session is possible only
in `/decide`.

## Dependencies and licences

None.

## Consequences

### Positive

- Usable agents and a predictable, explainable policy.

### Tradeoffs

- Unknown attacks without a finding are allowed; their rate is reported.
- Revisit the table after the first evaluation run.

## Implementation

### Where it lives

- `guardian-core/src/types.rs`: `Severity`, `Finding`.
- `detect/src/policy.rs`: findings to decision.

## Related decisions

- ADR-0003 (fail closed), ADR-0005 (stages), ADR-0010 (measurement),
  ADR-0018 (quarantine), ADR-0021 (heartbeat).

## History

- v1.0 (2026-10-24): Initial decision.
- v1.1 (2026-10-24): the table above is now the default; the owner can move
  the ask and deny thresholds within floors (ADR-0033).
