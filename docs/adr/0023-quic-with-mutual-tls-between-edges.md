# ADR-0023: QUIC with mutual TLS bound to identities between our edges

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

ADR-0016 put HTTP on hyper between the host daemon and the Core, and the
witness reached the Core over HTTP too. Plain HTTP on the local network can
be read and rewritten by anything on the path, and it identifies nobody: the
Core cannot tell which device is asking, and the witness cannot tell which
Core is answering except by trusting an address. Nepheral already solved this
in production: QUIC with mutual TLS 1.3 where each certificate carries one
Ed25519 key and that key is the identity (Nepheral ADR-0003).

## Options considered

### Option 1: keep HTTP, add TLS with pinned certificates

- Benefits: small change.
- Drawbacks: one connection per request, head-of-line blocking, and client
  identity still needs a separate mechanism.

### Option 2: QUIC with mutual TLS bound to Ed25519 identities

- Benefits: every link is encrypted and both ends are identified by their
  key; streams multiplex requests on one connection; proven in Nepheral.
- Drawbacks: UDP may be blocked on some networks; more code than HTTP.

## Decision

Every link between our own components uses QUIC (quinn) with TLS 1.3 and
mutual authentication. Each component has an Ed25519 identity key; its
certificate is self-standing and carries exactly that key, which is the
identity. Only Ed25519 handshakes are accepted. ALPN is `hawk/1`.

| Link | Transport |
|---|---|
| Host daemon to Core | QUIC, mutual TLS |
| Witness app to Core | QUIC, mutual TLS |
| OpenCode plugin to host daemon | HTTP on loopback only (OpenCode cannot speak QUIC; nothing leaves the machine) |
| Core to routers, Kafka | Their own protocols (HTTPS with a pinned certificate, Kafka over TCP) |

The Core exposes no HTTP endpoint.

### Wire format

One bidirectional stream per request. Each message is a 4-byte big-endian
length followed by JSON; the length is checked against a 4 MiB cap before
reading. Requests and responses are the `Request` and `Response` enums in
`guardian-core::wire`.

### Authorisation by identity

- Before pairing, anyone may ask for the Core's identity and pairing offer,
  and pair.
- Pairing binds the witness's identity key (taken from the TLS handshake,
  never from the message) to the owner key.
- After pairing, status, events, heads and configuration are served only to
  that witness identity. Configuration also needs the owner's signature.
- Decisions are accepted only from hosts the owner has enrolled
  (`Request::ApproveHost`, ADR-0021); an unenrolled host is denied.

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| quinn | 0.11 | MIT OR Apache-2.0 |
| rcgen | 0.12 | MIT OR Apache-2.0 |

## Consequences

### Positive

- Nothing between our devices travels in clear text, and every request is
  attributed to a key.
- A swapped Core fails the handshake against the pinned identity.

### Tradeoffs

- Networks that block UDP break the link; revisit with a TCP fallback if the
  demo network does.
- Supersedes the HTTP-between-edges part of ADR-0016; hyper stays only for
  the loopback endpoint of the host daemon.

## Implementation

### Where it lives

- `edge-net/src/quic.rs`: identities, TLS configs, endpoints, framing.
- `guardian-core/src/wire.rs`: messages.

## Related decisions

- ADR-0016 (partly superseded), ADR-0024 (discovery and activation),
  ADR-0017 (pairing).

## References

- Nepheral ADR-0003 and `mesh-network/src/tls.rs`.

## History

- v1.1 (2026-10-24): decisions are accepted only from hosts the owner has
  enrolled (ADR-0021), no longer from any authenticated peer.
- v1.0 (2026-10-24): Initial decision.
