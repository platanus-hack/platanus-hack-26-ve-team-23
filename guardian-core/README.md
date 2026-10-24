# guardian-core

The record format: event encoding, the hash chain and the types the hook and
the Guardian exchange. Every other crate depends on it; it depends on none of
them (ADR-0012).

- **Status:** event encoding, hash chain and verification implemented with
  tests. Signed heads and epoch encryption planned (ADR-0006, ADR-0007).

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
