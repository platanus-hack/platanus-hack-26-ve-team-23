# ADR-0014: Our own implementation of the monitor, established crates for primitives

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

Agent monitoring tools already exist (guardrail frameworks, MCP gateways,
observability platforms). Wrapping one would be faster, but the project's
contribution is exactly the parts those tools do not have: a monitor on
separate hardware, the hook and proxy cross-check, and a record the agent
cannot rewrite. Judges evaluate what we built. At the same time, writing our
own cryptography or HTTP stack would be slower and less safe.

## Options considered

### Option 1: build on an existing guardrail or gateway framework

- Benefits: less code.
- Drawbacks: our contribution becomes configuration; their architecture
  (monitor on the same host, logs in their store) contradicts ours; many are
  Python and do not fit the Pi.

### Option 2: write everything, including cryptography

- Benefits: no dependencies.
- Drawbacks: home-made cryptography is the classic way to break a security
  product; no time for it.

### Option 3: our own monitor, established crates for primitives

- Benefits: every part that carries the idea is ours and explainable;
  primitives are audited and widely used.
- Drawbacks: more code to write than option 1.

## Decision

**We implement ourselves:**

- the event format, canonical encoding and the hash chain (`guardian-core`);
- the rules engine and sequence rules (`detect`);
- the classifier: hashed features over the normalised tool call and its
  recent context, with a linear model trained offline by `eval` and shipped
  as a weights file. Pure Rust, no ML runtime;
- the OpenAI-compatible proxy logic, streaming handling and tool-call
  extraction (`llm-proxy`);
- the cross-check, the decision API and the open-request protocol
  (`guardian`);
- the evaluation runner and metrics (`eval`).

**We take from established crates:**

- cryptographic primitives, never implemented by us;
- async runtime, HTTP server and client, serialisation, logging;
- the inference engine for the optional small-LLM stage.

**We may copy from Nepheral**, which the team owns: patterns and code for
the workspace layout, axum services, OpenAI-compatible endpoints, Tauri
shell, Keystore access, `just` and `cargo deny` setup. Copied code is
adapted, not vendored as a dependency.

### Key points

- **No third-party guardrail, gateway or observability framework** in the
  decision or recording path.
- **The small-LLM stage** uses `llama-cpp-2` behind a Cargo feature, as in
  Nepheral ADR-0014; the default build does not include it.

## Dependencies and licences

| Dependency | Version | Licence | Used for |
|---|---|---|---|
| sha2 | 0.10 | MIT OR Apache-2.0 | Chain hashes |
| ed25519-dalek | 2 | BSD-3-Clause | Guardian signature on heads |
| p256 | 0.13 | MIT OR Apache-2.0 | Owner signatures (phone hardware keys are P-256) |
| chacha20poly1305 | 0.10 | MIT OR Apache-2.0 | Batch encryption with epoch keys |
| zeroize | 1 | MIT OR Apache-2.0 | Wiping key material |
| rand | 0.8 | MIT OR Apache-2.0 | Key and nonce generation |
| bip39 | 2 | CC0-1.0 | Owner mnemonic (ADR-0008) |
| hyper, hyper-util | 1, 0.1 | MIT | HTTP server for the decision API and proxy (ADR-0016) |
| reqwest | 0.12 | MIT OR Apache-2.0 | Proxy forwarding to Ollama |
| llama-cpp-2 (optional feature) | latest | MIT OR Apache-2.0 | Optional ~350M stage |

## Consequences

### Positive

- The demo and the code show our idea, not someone else's configuration.
- Security-critical primitives are not ours to get wrong.

### Tradeoffs

- More code in a short time; the classifier starts simple and is measured
  against rules only (ADR-0010).
- Revisit the classifier if a linear model is clearly too weak in the
  evaluation.

## Related decisions

- ADR-0005: the detection stages implemented here.
- ADR-0011: licence list.
- ADR-0012: crate layout.

## References

- Nepheral-core: ADR-0002, ADR-0014, `nepheral-api`, `nepheral-desktop`.

## History

- v1.0 (2026-10-24): Initial decision.
