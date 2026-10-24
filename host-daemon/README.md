# host-daemon

The daemon on every machine that runs agents (ADR-0015). Relays hook
requests to the Core on the Pi, watches protected paths, and sends a
heartbeat.

- **Runs on:** every host that runs agents (Linux, Windows). Untrusted, so
  it is a sensor and a relay, never a decider. Runs as its own system user.
- **Status:** skeleton. `GET /health` and `POST /decide` on
  `127.0.0.1:7070`; `/decide` denies until forwarding to the Core exists.

## Configuration

`HOST_DAEMON_ADDR` (default `127.0.0.1:7070`), `RUST_LOG`. Planned:
`GUARDIAN_URL`, the enrolled host key, the list of protected paths.

## What it must never do

- Allow an action on its own, or when the Core does not answer.
- Listen on anything other than loopback for hook requests.
- Run as the same user as the agents.

## Tests

`cargo test -p host-daemon`.
