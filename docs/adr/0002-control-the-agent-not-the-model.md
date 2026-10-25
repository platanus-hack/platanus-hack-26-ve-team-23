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

## Related work

The large labs converge on the same layer: controls outside the model,
applied before a tool runs.

| Work | What it says | In HAWK |
|---|---|---|
| Díaz, Kern, Olive, *Google's Approach for Secure AI Agents: An Introduction* (Google, 2025) | Hybrid defence in depth: deterministic runtime policy enforcement plus reasoning-based defences; a clearly identified human controller, limited agent powers, observable actions and planning | Rules before the classifier; the owner approves from the phone; deny and quarantine limit the agent; the signed record makes actions observable |
| Debenedetti, Shumailov et al., *Defeating Prompt Injections by Design* (CaMeL; Google, Google DeepMind, ETH Zurich; arXiv 2503.18813, 2025) | A protective layer around the model, with no change to the model, that enforces policies when tools are called | The hook asks the Core before every tool; the model is never modified |
| Shah et al., *An Approach to Technical AGI Safety and Security* (Google DeepMind; arXiv 2504.01849, 2025) | System-level monitoring and access control as the second line of defence, limiting harm even if the model is misaligned | The Core monitors every call and the firewall restricts the host, whatever the model intends |
| Meta, *Agents Rule of Two* (2025) | In one session an agent should combine at most two of: untrusted input, sensitive data, changing state or communicating externally; otherwise it needs supervision such as human approval | The `ask` outcome: the owner approves on the phone (ADR-0022) |

All of them assume the monitor runs on trusted infrastructure: the lab's or
the provider's. On a developer's machine that place does not exist, because
the agent runs with the same permissions as everything else. HAWK provides
it on a separate device (ADR-0003).

## Related decisions

- ADR-0003: where the monitor runs.
- ADR-0004: where actions are intercepted.
- ADR-0010: how the monitor is measured.

## References

- Greenblatt et al., "AI Control: Improving Safety Despite Intentional
  Subversion" (2023).
- Redwood Research, "The Case for AI Control".
- UK AI Security Institute, ControlArena.
- Díaz, Kern, Olive, "Google's Approach for Secure AI Agents: An
  Introduction" (2025):
  https://research.google/pubs/an-introduction-to-googles-approach-for-secure-ai-agents/
- Debenedetti, Shumailov et al., "Defeating Prompt Injections by Design"
  (2025): https://arxiv.org/abs/2503.18813
- Shah et al., "An Approach to Technical AGI Safety and Security" (2025):
  https://arxiv.org/abs/2504.01849
- Meta, "Agents Rule of Two" (2025):
  https://ai.meta.com/blog/practical-ai-agent-security/

## History

- v1.0 (2026-10-24): Initial decision.
- v1.1 (2026-10-25): Related work: Google's approach for secure AI agents,
  CaMeL, DeepMind's AGI safety approach and Meta's Agents Rule of Two, each
  mapped to HAWK; they assume trusted infrastructure, which HAWK provides on
  a separate device.
