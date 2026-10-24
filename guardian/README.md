# guardian

The Core: decides, records, contains and serves the owner's app. Runs on the
Raspberry Pi (2 GB, Linux, arm64); in Docker it is limited to 2 GB to match.

- **Status:** QUIC with mutual TLS on `GUARDIAN_ADDR` (UDP, default
  `0.0.0.0:7443`), mDNS announcement, pairing bound to the app identity,
  owner-signed configuration, sealed and chained record with hybrid signed
  heads, containment on the firewall, sinks, host registry and identify.
  Pending: rule catalogue (team), host heartbeats and enrolment (team), LLM
  proxy cross-check, opening the record, releasing a quarantine. See
  `PENDIENTES.md`.

## Messages (`guardian_core::wire`)

| Request | Who may send it | Answer |
|---|---|---|
| `hello` | anyone | identity, paired, configuration summary |
| `pair_offer`, `pair` | anyone, while unpaired | offer; then the confirmation code |
| `configure` | the paired app, with the owner's signature | configuration summary |
| `status`, `events`, `heads`, `hosts`, `identify` | the paired app only | state, event metadata, signed heads, hosts, ack |
| `decide` | host daemons | decision |
| `host_hello` | host daemons | ack |

The Core has no HTTP endpoint (ADR-0023). `guardian probe ADDR` sends a QUIC
hello from a throwaway identity and prints the answer.

Configuration: `GUARDIAN_ADDR`, `GUARDIAN_DATA_DIR` (default
`./guardian-data`), `GUARDIAN_FIREWALL` and the router variables of
`integrations` (used until the owner configures the Core from the app),
`KAFKA_BROKERS`, `GUARDIAN_WEBHOOK_URL`, `RUST_LOG`.

At start the Core logs `core identity fingerprint=…`: the owner compares it
in the activation wizard.

## What it must never do

- Allow an action when a detector fails, the request is malformed, the Core
  is unpaired, or the decision cannot be recorded.
- Serve its record or accept configuration from anyone but the app bound at
  pairing.
- Quarantine an address a client declares; only the authenticated peer's.
- Run any model of 1.5B parameters or above.
- Hold a key that decrypts the record.

## Tests

`cargo test -p guardian`, and against a running Core `just probe`.
