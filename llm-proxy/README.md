# llm-proxy

OpenAI-compatible proxy between OpenCode and Ollama (ADR-0004). It forwards
each request upstream, streams the answer back unchanged, and produces a
`ProxyRecord` (request, response and the tool calls the model proposed) for
the Core's cross-check against hook requests.

- **Status:** forwarding (streaming and non-streaming), SSE pass-through and
  tool-call extraction (with ids) are implemented; the proxy runs inside the
  host daemon on loopback, which relays each `ProxyRecord` to the Core over
  QUIC.

## What it must never do

- Change the model's answer; it records, the hook enforces.
- Drop a request from the record because it failed to parse.

## Tests

`cargo test -p llm-proxy`. Streaming and non-streaming responses with and
without tool calls, against a local stand-in upstream.
