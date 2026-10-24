# edge-net

Networking for the edges.

- **QUIC** (`quic.rs`, ADR-0023, adapted from Nepheral): mutual TLS 1.3 where
  each self-standing certificate carries one Ed25519 key, which is the
  identity; Ed25519 handshakes only; ALPN `hawk/1`; one bidirectional stream
  per request with length-prefixed JSON (4 MiB cap checked before reading);
  either side can open requests on an established connection
  (`serve_connection`); `fingerprint` for human comparison.
- **Discovery** (`discovery.rs`, ADR-0024): announce and browse
  `_hawk-core._udp.local.` with mdns-sd.
- **Loopback HTTP** (`http.rs`): hyper server for the host daemon's socket
  that the OpenCode plugin uses.

## What it must never do

- Accept a certificate with zero or several Ed25519 keys, or TLS 1.2.
- Parse a message before its size is checked.
- Implement a cryptographic primitive or a protocol parser itself.

## Tests

`cargo test -p edge-net` (round trip with both identities, wrong server
identity refused, certificate key extraction, body limits, fingerprints).
