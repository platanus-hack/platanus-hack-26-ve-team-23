# host-daemon

Runs on every monitored machine (ADR-0015). It relays the agent hook to the
Core and has no user interface except the identification notice.

- **Status:** loopback HTTP for the OpenCode plugin on `HOST_DAEMON_ADDR`
  (default `127.0.0.1:7070`, loopback enforced); QUIC with mutual TLS to the
  Core with its own Ed25519 identity (`host.key`); Core discovery by mDNS or
  `GUARDIAN_CORE`; Core identity pinned (`GUARDIAN_CORE_ID`, or the first
  Core it talks to, stored in `core.pin`); identification notice.
  Pending: heartbeat, attestation, owner enrolment (see `PENDIENTES.md`).

## Identification notice

When the owner presses "Identify" for this machine in the app, the Core asks
the daemon over the existing QUIC connection to show itself. The daemon shows
a notice with the Core's name, the hostname and this machine's fingerprint
(`msg` on Windows, `notify-send` or `wall` on Linux, a notification on macOS)
and logs it. Values from the network are sanitised and passed as one
argument, never through a shell.

## Configuration

`HOST_DAEMON_ADDR`, `HOST_DAEMON_DATA_DIR` (default `./host-daemon-data`),
`GUARDIAN_CORE`, `GUARDIAN_CORE_ID`, `RUST_LOG`. At start it logs
`host identity fingerprint=… hostname=…`.

## What it must never do

- Decide on its own, or allow when the Core cannot be reached.
- Listen on anything other than loopback.
- Talk to a Core whose identity is not the pinned one.
- Run as the same user as the agents.

## Tests

`cargo test -p host-daemon` (relay against a QUIC stand-in Core, wrong
identity refused, no Core, malformed calls, notice sanitising).
