# ADR-0016: hyper directly on tokio for HTTP; our own framed protocol between edges

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

Three kinds of connection exist:

| Connection | Client | Constraint |
|---|---|---|
| Hook to host daemon (loopback) | OpenCode plugin in TypeScript | Must be HTTP and JSON |
| OpenCode to the proxy on the Core | OpenCode | Must be OpenAI-compatible HTTP, with SSE streaming |
| Host daemon to Core, Core to mobile app | Our own code on both sides | Free to choose |

The Guardian must control each connection: how long it waits for headers,
how many bytes it reads before parsing, how streams are passed through and
cancelled. A web framework hides most of that behind routing and extractors
we do not need for three routes.

## Options considered

### Option 1: axum

- Benefits: fast to write; used in Nepheral.
- Drawbacks: routing, extractors and tower layers we do not need; less
  direct control over connections and streaming bodies.

### Option 2: hyper 1 directly on tokio

- Benefits: we own the accept loop, the per-connection task, timeouts and
  body limits; streaming bodies are plain `Body` values; fewer
  dependencies.
- Drawbacks: routing and JSON handling written by hand (small for three
  routes).

### Option 3: raw tokio sockets with our own HTTP parser

- Benefits: total control.
- Drawbacks: HTTP parsing is a primitive with a history of security bugs
  (request smuggling, header injection); against ADR-0014.

## Decision

- **HTTP** (hook to daemon, OpenCode to proxy) uses hyper 1 with
  `hyper-util` on tokio, through a small shared crate, `edge-net`: accept
  loop with one task per connection, header read timeout, body size cap
  before parsing, JSON helpers. No web framework.
- **Between our own edges** (daemon to Core, Core to mobile app) we use our
  own framed protocol over `tokio::net` streams: length-prefixed frames with
  a size cap checked before reading, explicit timeouts and cancellation, and
  messages defined in `guardian-core`. Authentication and encryption of
  these links are decided in a later ADR, using an established TLS or Noise
  implementation, never our own.

### Key points

- **Every read is bounded** in time and size before any parsing.
- **Errors in the decision path become deny** (ADR-0003).
- **Streaming in the proxy** passes chunks through as they arrive while a
  copy is recorded; the agent never waits for the whole response.

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| hyper | 1 | MIT |
| hyper-util | 0.1 | MIT |
| http-body-util | 0.1 | MIT |
| bytes | 1 | MIT |

Removes axum, tower and tower-http from ADR-0014's list.

## Consequences

### Positive

- Full control of connections and streams on a 2 GB device.
- The protocol between edges is ours and small.

### Tradeoffs

- Routing and request handling written by hand.
- The framed protocol needs its own golden tests, like the event encoding.

## Implementation

### Where it lives

- `edge-net/`: HTTP server helpers; later the framed protocol.

### Next steps

1. Framed protocol codec with size caps and golden tests.
2. Choose the authenticated transport for daemon to Core (TLS or Noise).

## Related decisions

- ADR-0004, ADR-0015: the connections.
- ADR-0014: amended dependency list.

## History

- v1.1 (2026-10-24): The links between edges move to QUIC with mutual TLS
  (ADR-0023); hyper remains only for the host daemon's loopback endpoint.

- v1.0 (2026-10-24): Initial decision.
