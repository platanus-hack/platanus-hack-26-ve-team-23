# guardian-core

The record format: event encoding, the hash chain and the types the hook and
the Guardian exchange. Every other crate depends on it; it depends on none of
them (ADR-0012).

- **Status:** event encoding and decoding, hash chain and verification,
  hybrid signed heads (Ed25519 + ML-DSA-65), sealing to the epoch key,
  pairing helpers and the QUIC wire messages, all with tests.

## Modules

- `wire`: requests and responses between the edges over QUIC (ADR-0023).
- `pairing`: the pairing message (Core, nonce, app identity) and the
  confirmation code.
- `keys`, `head`, `seal`: Core signing keys, hybrid signed heads, sealing to
  the epoch key.

## Main types

- `ToolCall`, `Decision`: the hook's request and the Guardian's answer.
- `Event`, `EventKind`: one entry of the record; `Event::encode` is the
  fixed canonical encoding.
- `HashChain`: append-only chain; `verify` recomputes it against a head the
  witness holds.

## What it must never do

- Any I/O, networking or async code.
- Change the encoding without updating the golden test deliberately.

## Tests

`cargo test -p guardian-core`. Includes a frozen encoding, an edited event
and a deleted event, both of which must fail verification.
