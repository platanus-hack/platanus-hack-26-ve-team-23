# host-daemon

Runs on every monitored machine (ADR-0015). It relays the agent hook to the
Core, serves the OpenAI-compatible proxy for OpenCode on loopback, and has no
user interface except the identification notice.

- **Status:** loopback HTTP for the OpenCode plugin on `HOST_DAEMON_ADDR`
  (default `127.0.0.1:7070`, loopback enforced); QUIC with mutual TLS to the
  Core with its own Ed25519 identity (`host.key`); Core discovery by mDNS or
  `GUARDIAN_CORE`; Core identity pinned (`GUARDIAN_CORE_ID`, or the first
  Core it talks to, stored in `core.pin`); identification notice; the
  OpenAI-compatible LLM proxy that forwards to Ollama and relays a copy of
  each exchange to the Core; the signed heartbeat answering the Core's
  challenge. Pending: TPM-sealed key and measured boot (see
  `PENDIENTES.md`).

## The heartbeat (ADR-0021)

The Core challenges the daemon (`HeartbeatChallenge { nonce }`) and the daemon
answers with a signed `Heartbeat { nonce, counter, digest, signature, boot }`:
a monotonic counter (persisted in `heartbeat.counter`), the digest of the tool
calls it relayed since the previous heartbeat, and its boot measurement. On
Linux the boot measurement is the SHA-256 digest of the first PCRs read from
the TPM driver (`tpm.rs`); without a TPM it is absent. The key is the daemon's
Ed25519 identity.

## The LLM proxy (ADR-0004)

OpenCode points its model base URL at this daemon (`/v1/…` and `/api/…` are
proxied). The daemon forwards to Ollama (`OLLAMA_URL`, default
`http://127.0.0.1:11434`), streams the answer back unchanged, and after each
response sends a `ProxyRecord` to the Core over QUIC. The plugin must send the
model's tool-call id as `call_id` (from `input.callID`) so the Core can
cross-check the two.

## Identification notice

When the owner presses "Identify" for this machine in the app, the Core asks
the daemon over the existing QUIC connection to show itself. The daemon shows
a notice with the Core's name, the hostname and this machine's fingerprint
(`msg` on Windows, `notify-send` or `wall` on Linux, a notification on macOS)
and logs it. Values from the network are sanitised and passed as one
argument, never through a shell.

## Configuration

`HOST_DAEMON_ADDR`, `HOST_DAEMON_DATA_DIR` (default `./host-daemon-data`),
`GUARDIAN_CORE`, `GUARDIAN_CORE_ID`, `OLLAMA_URL`, `RUST_LOG`. At start it
logs `host identity fingerprint=… hostname=…`.

## What it must never do

- Decide on its own, or allow when the Core cannot be reached.
- Listen on anything other than loopback.
- Talk to a Core whose identity is not the pinned one.
- Run as the same user as the agents.

## Tests

`cargo test -p host-daemon` (relay against a QUIC stand-in Core, wrong
identity refused, no Core, malformed calls, notice sanitising).
