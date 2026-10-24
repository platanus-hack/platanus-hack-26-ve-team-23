# ADR-0012: One Rust workspace with the record format at the bottom

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The Guardian runs on a Raspberry Pi with 2 GB of RAM, next to a classifier.
The witness runs on a phone and on a desktop. The verifier, the Guardian and
the evaluation runner must agree byte for byte on the event format, the hash
chain and the signatures: a verifier that hashes an event differently from
the Guardian reports tampering that never happened, or misses tampering that
did.

## Options considered

### Option 1: one Rust workspace, layered crates

- Benefits: every binary links the same record and chain code; one lockfile;
  memory safety without a garbage collector on a 2 GB board; cross-compiles
  to `aarch64-unknown-linux-gnu` for the Pi; the same crates build into the
  Tauri witness (ADR-0013).
- Drawbacks: longer compile times; slower to prototype than a scripting
  language.

### Option 2: Python for the Guardian

- Benefits: fastest to prototype; rich ML tooling.
- Drawbacks: interpreter and ML libraries eat a large share of 2 GB; the
  chain format would exist twice (Guardian in Python, witness in another
  language) and drift.

### Option 3: Go or TypeScript

- Benefits: simple concurrency, fast builds.
- Drawbacks: a second language for the witness; garbage-collected memory on
  the Pi; no reuse of the Nepheral code the team already owns.

## Decision

The back end is one Cargo workspace, stable Rust, edition 2021. Crates
depend only downwards:

| Crate | Role | Depends on |
|---|---|---|
| `guardian-core` | Event types, canonical encoding, hash chain, signed heads, epoch encryption, open-request verification. No I/O, no async | none of the others |
| `detect` | Rules engine, sequence rules, classifier; optional small-LLM stage behind a feature | `guardian-core` |
| `llm-proxy` | OpenAI-compatible proxy: forwarding, streaming, tool-call extraction | `guardian-core` |
| `guardian` | The daemon on the Pi: `/decide`, the proxy, cross-check, chain store, delivery to the witness | all of the above |
| `witness` | Tauri 2 app: heads store, alerts, keys, verifier (ADR-0013) | `guardian-core` |
| `eval` | Task runner and metrics (ADR-0010); trains the classifier | `guardian-core`, `detect` |

The OpenCode plugin in `agent-hook/` is the only non-Rust code: OpenCode
loads plugins in JavaScript or TypeScript. It stays a thin shim that sends
the call to the Guardian and obeys the answer; it contains no logic.

### Key points

- **Record format at the bottom:** `guardian-core` has no dependency on the
  network or the runtime, so it can be tested and audited alone, and it is
  the only definition of how an event is hashed.
- **Features, not forks:** the optional small-LLM stage in `detect` is a
  Cargo feature, so the default Guardian builds without a C++ toolchain.
- **Targets:** `aarch64-unknown-linux-gnu` (Pi), `x86_64-unknown-linux-gnu`
  and `x86_64-pc-windows-msvc` (PC, development), Android (witness).

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| tokio | 1 | MIT |
| serde, serde_json | 1 | MIT OR Apache-2.0 |
| tracing, tracing-subscriber | 0.1, 0.3 | MIT |

Crate-specific dependencies are listed in ADR-0014.

## Consequences

### Positive

- One definition of every event and every hash, shared by the Guardian, the
  witness and the evaluation.
- Patterns and code can be taken from Nepheral, which the team owns.

### Tradeoffs

- Rust is slower to write under hackathon pressure; the scope in
  [ROADMAP](../ROADMAP.md) assumes it.
- Cross-compiling for the Pi needs a toolchain set up early (M1).

## Implementation

### Where it lives

- `Cargo.toml`: workspace members and shared dependency versions (to be
  created with the first crate).

### Next steps

1. Workspace skeleton with empty crates, `justfile` and `cargo deny` in CI.
2. Cross-compile a hello-world `guardian` and run it on the Pi.

## Related decisions

- ADR-0013: the witness front end.
- ADR-0014: what we implement ourselves and what we take from crates.
- ADR-0011: licences, enforced by `cargo deny`.

## References

- Nepheral ADR-0002, "One Rust workspace with consensus code at the bottom".

## History

- v1.0 (2026-10-24): Initial decision.
