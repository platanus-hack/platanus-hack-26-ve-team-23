# ADR-0005: Detection: rules first, small classifier second, optional small LLM

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The Guardian decides on every tool call, on a Raspberry Pi with 2 GB of RAM
shared with the operating system, the proxy and the hash chain. A 1.5B model
quantised to 4 bits needs about 1 GB for its weights alone, plus its context
cache, which leaves no margin. Decisions add latency to every tool call.

## Options considered

### Option 1: an LLM judges every action

- Benefits: handles ambiguous cases in natural language.
- Drawbacks: 1.5B models (Granite 1.5B, R1-Distill 1.5B) do not fit with the
  rest; latency on every call; harder to audit.

### Option 2: rules only

- Benefits: deterministic, auditable, fast.
- Drawbacks: miss anything not anticipated, including multi-step attacks.

### Option 3: rules, then a small classifier, then an optional ~350M LLM

- Benefits: most calls are decided by rules in microseconds; the classifier
  covers variations; the LLM only sees what is still ambiguous.
- Drawbacks: three stages to calibrate.

## Decision

1. **Rules** on the tool call and on the recent sequence of calls (for
   example: deleting or truncating logs and shell history, network egress
   with files read from secret paths, writing outside the workspace,
   disabling the hook or editing the plugin directory).
2. **A small classifier** on the normalised call and its recent context,
   for cases the rules do not settle.
3. **Optionally, a ~350M model** (Granite 350M class, Apache-2.0, quantised)
   for the remaining ambiguous cases, only if it fits in memory and its
   latency is acceptable when measured on the Pi.

Models of 1.5B and above are out of the demo device.

### Key points

- **Sequence rules matter:** a harmful action split across harmless-looking
  steps is the known weakness of a small monitor; rules over the last N
  calls cover part of it, and the rest is reported as a measured limitation.
- **Each decision records** which stage decided and which rule fired.

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| Granite ~350M (optional) | to be measured | Apache-2.0 |
| Classifier library | to be chosen | must satisfy ADR-0011 |

## Consequences

### Positive

- Fits in 2 GB; most decisions are fast and explainable.

### Tradeoffs

- Memory and latency figures are estimates until measured on the Pi.
- Revisit the LLM stage after the first evaluation run (ADR-0010).

## Implementation

### Next steps

1. First rule set, written against the evaluation set.
2. Measure classifier and 350M memory and latency on the Pi.

## Related decisions

- ADR-0003: runs on the Pi.
- ADR-0010: what the detectors are measured against.

## History

- v1.0 (2026-10-24): Initial decision.
