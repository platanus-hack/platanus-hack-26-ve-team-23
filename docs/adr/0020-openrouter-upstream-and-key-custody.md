# ADR-0020: OpenRouter as a remote upstream; provider keys live only on the Core

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The proxy (ADR-0004) fronts Ollama on the PC. Teams also run agents on
remote models (Claude, GPT, open models) through API keys. If the API key
lives on the host, a compromised agent can call the provider directly and
skip the proxy, and the record never sees those calls.

## Options considered

### Option 1: keys on the host, proxy optional

- Benefits: no change for users.
- Drawbacks: the agent can bypass the proxy with the key it already has.

### Option 2: one adapter per provider

- Benefits: native APIs.
- Drawbacks: several APIs to implement and keep up to date.

### Option 3: OpenRouter behind the proxy, key only on the Core

- Benefits: one OpenAI-compatible API for many models; the host never holds
  a provider key, so the only way to reach a model is through the Core.
- Drawbacks: depends on OpenRouter's availability; prompts pass through a
  third party.

## Decision

The proxy has two upstreams: Ollama (local) and OpenRouter (remote). The
OpenRouter key is stored on the Core and added by the proxy to forwarded
requests. Agents on the host are configured with the Core's proxy as their
base URL and receive no provider key.

### Key points

- **Key custody is enforcement:** without a key on the host, bypassing the
  proxy means losing access to the model.
- **Per-host model allow list** on the Core.
- **Spend limit** on the OpenRouter key, so a runaway agent cannot run up
  costs.

## Dependencies and licences

None beyond ADR-0016 and ADR-0018 (HTTPS client).

## Consequences

### Positive

- Remote agents are covered as fully as local ones.
- The demo can show the same Guardian with a local model and a frontier
  model.

### Tradeoffs

- OpenRouter becomes part of the trust model for remote prompts.

## Related decisions

- ADR-0004: the proxy.
- ADR-0009: the local upstream.

## History

- v1.0 (2026-10-24): Initial decision.
