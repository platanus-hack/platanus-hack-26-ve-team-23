# ADR-0009: Agent under test: OpenCode with Ollama on the PC

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The demo and the evaluation need a real coding agent that runs tools, uses a
model we can run many times without API costs, and can be intercepted at
both points of ADR-0004. The PC has an RTX 4070 with 12 GB of VRAM.

## Options considered

### Option 1: Claude Code or another agent on a remote API

- Benefits: the most capable agents.
- Drawbacks: every evaluation run costs money; not reproducible offline.

### Option 2: OpenCode with a local model through Ollama

- Benefits: open source (MIT), plugin hooks before tool execution, accepts
  any OpenAI-compatible base URL; runs offline and repeatedly.
- Drawbacks: smaller models fail more at tool use, which can look like the
  monitor's fault.

## Decision

The agent under test is OpenCode, using a model served by Ollama on the PC.
The starting model is a 7B to 8B coder model with tool support, such as
`qwen2.5-coder:7b` or `qwen3:8b`, quantised to Q4, with a context window of
about 32k. A 14B model fits only with a much smaller context and is not the
default.

### Key points

- **Context window:** Ollama's default context is too small for OpenCode's
  system prompt and tool definitions, and OpenCode fails silently with it;
  `num_ctx` is raised in a Modelfile.
- **Model choice is measured:** five tool-use tasks run before fixing the
  model; we record VRAM use and the tool-call success rate.
- **Remote models:** the same setup points at the Claude API through the
  proxy to show the Guardian does not depend on the model.

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| OpenCode | latest | MIT |
| Ollama | latest | MIT |
| Qwen2.5-Coder 7B or Qwen3 8B | latest | Apache-2.0 |

## Consequences

### Positive

- Cheap, reproducible runs for the evaluation set.

### Tradeoffs

- Results with a 7B agent may not transfer to frontier agents; the remote
  run shows the mechanism, not the detection rate, for those.

## Related decisions

- ADR-0003, ADR-0004, ADR-0010.

## History

- v1.0 (2026-10-24): Initial decision. Closes question Q12 (which agent the
  demo starts with).
