# ADR-0002: Control the agent, not the model

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The hackathon track is AI Security. Its sub-tracks are AI control,
guardrails and adversarial robustness, cyber evals, pragmatic
interpretability and defensive acceleration. We have consumer hardware: a PC
with an RTX 4070 (12 GB) and a Raspberry Pi with 2 GB of RAM. We have no
access to the weights or the runtime of frontier models.

Provider guardrails (content classifiers, refusal training) act on what a
model says. They do not see what an agent does with its tools, and they keep
their logs where neither the owner nor an auditor can check them
independently.

## Options considered

### Option 1: guardrails against jailbreaks and injections

- Benefits: a well-known problem with public benchmarks.
- Drawbacks: we would compete with Llama Guard and provider classifiers on
  their ground, with far less compute.

### Option 2: cyber evals or interpretability

- Benefits: open research areas.
- Drawbacks: need many model runs or access to activations; not feasible on
  our hardware in the time available.

### Option 3: AI control of agents

A monitor outside the agent's reach that sees every action, can block it,
and keeps a record the agent cannot rewrite.

- Benefits: matches the AI control sub-track directly; does not need large
  models; works the same for local and API models because it watches the
  agent, not the model.
- Drawbacks: does not make the model itself safer; only covers the actions
  that pass through the points we intercept.

## Decision

We build an AI control monitor for coding agents. It works at the layer of
actions and evidence: which tool calls the agent attempts, which are
blocked, and a tamper-evident record of both. We do not claim to make models
more robust, and we do not compete with content guardrails; we complement
them in the layer they do not cover.

### Key points

- **Threat model:** the agent may be misaligned or prompt-injected, and may
  know it is monitored and try to evade the monitor. The PC that runs it is
  untrusted. The agent runs as an unprivileged user; an agent with root on
  the PC is out of scope for prevention, but what was recorded before that
  point survives off the PC (ADR-0006).
- **A weaker monitor is acceptable** because it is trusted (small, without
  the capacity to collude), its task is narrow (classify one action, not
  solve the task), and its effectiveness is measured against attacks
  designed to evade it (ADR-0010). We do not rely on the agent being unaware
  of the monitor; we assume it is aware.
- **Out of scope:** jailbreak robustness, content filtering, cyber uplift
  evaluation, interpretability.

## Dependencies and licences

None.

## Consequences

### Positive

- A clear position that holds up to technical questions from judges.
- The same Guardian covers Ollama and remote APIs such as Claude by changing
  one base URL.

### Tradeoffs

- Reasoning that the model never turns into an action is invisible to us.
- Revisit if we gain access to a model runtime whose internal signals can
  be read.

## Implementation

### Next steps

1. Write the threat model, with the actors above, into the whitepaper.

## Related decisions

- ADR-0003: where the monitor runs.
- ADR-0004: where actions are intercepted.
- ADR-0010: how the monitor is measured.

## References

- Greenblatt et al., "AI Control: Improving Safety Despite Intentional
  Subversion" (2023).
- Redwood Research, "The Case for AI Control".
- UK AI Security Institute, ControlArena.

## History

- v1.0 (2026-10-24): Initial decision.
