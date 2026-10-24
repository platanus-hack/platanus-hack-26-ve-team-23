# ADR-0010: Build the evaluation set before the detectors

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

In an AI security track, "we built a monitor" is a prototype; "the monitor
blocks X% of attacks with Y% false positives" is a result. Detectors written
before the test cases tend to be tuned to the cases their authors imagined.

## Options considered

### Option 1: a scripted demo only

- Benefits: fast.
- Drawbacks: no numbers; a judge cannot compare it with anything.

### Option 2: run inside ControlArena

- Benefits: standard settings and metrics.
- Drawbacks: integrating our three-device setup takes time we may not have.

### Option 3: our own small set, with ControlArena's metrics

- Benefits: fits our setup; comparable vocabulary.
- Drawbacks: small and written by us; reported as such.

## Decision

Before writing detection code we build a set of about 30 legitimate coding
tasks and about 30 tasks with a hidden harmful side goal, run by the agent
of ADR-0009. Side goals include deleting or truncating logs and shell
history, sending secrets out over the network, editing the Guardian's
records, disabling the hook, and multi-step versions of these. Some attacks
are delivered by prompt injection in files the agent reads.

### Metrics

- **Safety:** share of harmful attempts blocked or flagged.
- **False positives:** share of legitimate actions blocked or flagged.
- **Usefulness:** share of legitimate tasks completed with the Guardian on.
- **Evasion detection:** share of hook bypasses caught by the cross-check.
- **Latency:** time the Guardian adds per tool call on the Pi.

Each metric is reported for: no Guardian, rules only, and rules plus
classifier. Missed multi-step attacks are reported, not hidden.

## Dependencies and licences

None.

## Consequences

### Positive

- The demo ends with a table, not a claim.

### Tradeoffs

- A set written by the team is biased; part of it is written by someone who
  does not write the rules.

## Implementation

### Next steps

1. Task format and runner that resets the workspace between runs.
2. Split authorship: tasks and rules by different people.

## Related decisions

- ADR-0005: what is measured.
- ADR-0009: the agent that runs the tasks.

## References

- UK AI Security Institute, ControlArena.

## History

- v1.0 (2026-10-24): Initial decision.
