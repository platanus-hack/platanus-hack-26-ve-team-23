# llm-proxy

OpenAI-compatible proxy between OpenCode and Ollama (ADR-0004). Records every
request and response and extracts the tool calls the model proposes, for the
cross-check against hook requests.

- **Status:** skeleton (configuration type only).

## What it must never do

- Change the model's answer; it records, the hook enforces.
- Drop a request from the record because it failed to parse.

## Tests

`cargo test -p llm-proxy`. Streaming and non-streaming responses with and
without tool calls.
