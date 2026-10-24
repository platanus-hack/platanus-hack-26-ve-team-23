# guardian

The daemon on the Raspberry Pi. Wires `detect`, `llm-proxy` and
`guardian-core` together.

- **Runs on:** Raspberry Pi, 2 GB of RAM, Linux (arm64). In Docker, limited
  to 2 GB to match.
- **Status:** `GET /health` and `POST /decide` implemented; `/decide` always
  denies until the rules exist. Proxy, cross-check, chain store and delivery
  to the witness planned.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness, returns `ok` |
| `POST /decide` | Body: `ToolCall` JSON. Answer: `{"decision":"allow"}`, `{"decision":"deny","reason":...}` or `{"decision":"ask","reason":...}` |

Configuration: `GUARDIAN_ADDR` (default `0.0.0.0:8080`), `RUST_LOG`.

## What it must never do

- Allow an action when a detector fails, the body is malformed or too large
  (256 KiB cap), or a lock is poisoned.
- Run any model of 1.5B parameters or above.
- Store decryption keys for past epochs.
- Accept connections from the PC other than the decision and proxy
  endpoints.

## Tests

`cargo test -p guardian`, and against a running instance
`docker compose run --rm smoke`.
