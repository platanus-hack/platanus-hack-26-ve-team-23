# ADR-0004: Enforce with an agent hook, record with an LLM proxy, cross-check both

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The Guardian must see what the agent attempts and stop it before it acts.
There are two places to intercept a coding agent:

- **Between the agent and the model:** an HTTP proxy sees every prompt and
  every tool call the model proposes, but execution happens later, inside
  the agent.
- **Inside the agent, before a tool runs:** OpenCode plugins can run code in
  `tool.execute.before` and abort the call. This runs on the untrusted PC.

## Options considered

### Option 1: proxy only

- Benefits: independent of the agent; works with any client that accepts a
  base URL, including remote APIs.
- Drawbacks: blocking means rewriting model responses, which is fragile with
  streaming; it cannot see what the agent runs without asking the model.

### Option 2: hook only

- Benefits: blocks exactly at execution; native to OpenCode.
- Drawbacks: runs inside the process it monitors; if that process is
  tampered with, the hook stops asking and nobody notices.

### Option 3: both, cross-checked on the Pi

- Benefits: the hook enforces, the proxy records independently, and each one
  exposes the other's gaps.
- Drawbacks: two components to build and keep in sync.

## Decision

- **The hook enforces.** An OpenCode plugin sends every tool call (name,
  arguments, working directory, session) to the Guardian on the Pi and runs
  it only if the Guardian answers "allow". No answer within the timeout means
  deny.
- **The proxy records.** OpenCode's model base URL points to a proxy on the
  Pi, which forwards to Ollama on the PC and appends every request and
  response to the hash chain.
- **The Guardian cross-checks.** Every tool call the model proposed through
  the proxy must be matched by a hook request for the same call. A proposed
  call that never reached the hook, or a hook request with no matching model
  output, raises an evasion alert to the phone.

### Key points

- **Remote models:** the same proxy can front the Anthropic or OpenAI APIs,
  so the Guardian covers API agents without changes to the agent.
- **What the Guardian decides:** allow, deny, or ask the owner on the phone
  (for actions above a severity threshold).

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| OpenCode (agent under test, not shipped) | latest | MIT |

## Consequences

### Positive

- An agent that disables its hook is detected, not just undetected.
- Enforcement does not depend on parsing streamed responses.

### Tradeoffs

- The matching rule must tolerate retries and partial streams without false
  evasion alerts; measure it.
- Actions the agent takes without a tool call (for example, a process
  started earlier) are invisible to both points.

## Implementation

### Next steps

1. Guardian API: `POST /decide` for the hook, the proxy on the OpenAI-
   compatible paths Ollama serves.
2. OpenCode plugin with `tool.execute.before`, fail closed.
3. Cross-check job with alert to the phone.

## Related decisions

- ADR-0003: the Pi hosts the proxy and the decision endpoint.
- ADR-0005: how decisions are made.
- ADR-0006: what is recorded.

## References

- OpenCode plugin documentation (`tool.execute.before`).

## History

- v1.0 (2026-10-24): Initial decision.
