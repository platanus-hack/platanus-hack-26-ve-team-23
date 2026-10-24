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
| `GET /identity` | The Core's public keys (Ed25519 and ML-DSA-65) |
| `GET /pair`, `POST /pair` | Pairing offer and pairing (only while unpaired) |
| `GET /status`, `/heads`, `/events` | State, signed heads and event metadata for the witness (`?since=N`) |
| `POST /decide` | Body: `ToolCall` JSON. Answer: `{"decision":"allow"}`, `{"decision":"deny","reason":...}` or `{"decision":"ask","reason":...}` |

Configuration: `GUARDIAN_ADDR` (default `0.0.0.0:8080`), `GUARDIAN_DATA_DIR`,
`GUARDIAN_FIREWALL` (+ the router variables of `integrations`), `KAFKA_BROKERS`,
`GUARDIAN_WEBHOOK_URL`, `RUST_LOG`.

A critical finding quarantines the TCP peer of the request on the firewall
(never a host the client declares), records a `containment` event and
publishes to the sinks.

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
