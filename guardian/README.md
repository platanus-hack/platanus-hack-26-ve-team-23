# guardian

The Core: decides, records, contains and serves the owner's app. Runs on the
Raspberry Pi (2 GB, Linux, arm64); in Docker it is limited to 2 GB to match.

- **Status:** QUIC with mutual TLS on `GUARDIAN_ADDR` (UDP, default
  `0.0.0.0:7443`), mDNS announcement, pairing bound to the app identity,
  owner-signed configuration, sealed and chained record with hybrid signed
  heads, containment on the firewall, sinks, host registry and identify, the
  hook-proxy cross-check (ADR-0004), releasing a quarantine with the owner's
  signature (ADR-0018), opening the sealed record (ADR-0007), holding and
  answering `ask` decisions (ADR-0022), the data-driven rule catalogue
  (ADR-0005), host enrolment (ADR-0021) and the heartbeat with the dead man's
  switch (ADR-0021). Pending: TPM-sealed daemon key and measured boot
  (hardware). See `PENDIENTES.md`.

## Messages (`guardian_core::wire`)

| Request | Who may send it | Answer |
|---|---|---|
| `hello` | anyone | identity, paired, configuration summary |
| `pair_offer`, `pair` | anyone, while unpaired | offer; then the confirmation code |
| `configure` | the paired app, with the owner's signature | configuration summary |
| `release` | the paired app, with the owner's signature | ack (calls `Firewall::release`, recorded) |
| `open_record` | the paired app, with the owner's signature | the sealed events of the range (recorded) |
| `pending_asks`, `answer` | the paired app; `answer` with the owner's signature | the waiting asks; ack |
| `approve_host` | the paired app, with the owner's signature | ack (enrols a host) |
| `status`, `events`, `heads`, `hosts`, `identify` | the paired app only | state, event metadata, signed heads, hosts, ack |
| `decide` | enrolled host daemons | decision |
| `proxy_record` | enrolled host daemons | ack (recorded sealed; tool calls cross-checked) |
| `host_hello` | host daemons | ack |

The Core sends `heartbeat_challenge` to each enrolled host over its own
connection and verifies the signed `heartbeat` answer (ADR-0021).

The Core has no HTTP endpoint (ADR-0023). `guardian probe ADDR` sends a QUIC
hello from a throwaway identity and prints the answer.

Configuration: `GUARDIAN_ADDR`, `GUARDIAN_DATA_DIR` (default
`./guardian-data`), `HAWK_CLASSIFIER=1` (adds the familiarity stage of
ADR-0036 after the rules; off by default), `GUARDIAN_FIREWALL` and the router variables of
`integrations` (used until the owner configures the Core from the app),
`KAFKA_BROKERS`, `GUARDIAN_WEBHOOK_URL`, `RUST_LOG`, and the off-site
archive (ADR-0026, optional): `ARCHIVE_ENDPOINT`, `ARCHIVE_REGION`,
`ARCHIVE_BUCKET`, `ARCHIVE_PREFIX`, `ARCHIVE_ACCESS_KEY`,
`ARCHIVE_SECRET_KEY` (see `infra/README.md`).

Each signed head covers one batch (`first_seq..=seq`) and carries its
Merkle root (ADR-0025); with the archive enabled, the batch and its head
are uploaded in the background after signing.

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
