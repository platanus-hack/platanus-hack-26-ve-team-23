# Code and testing

- **Status:** Proposed
- **Date:** 2026-10-24

## Languages

- **Back end:** Rust, one Cargo workspace (ADR-0012).
- **Front end:** Tauri 2 with plain HTML, CSS and JavaScript (ADR-0013).
- **Exception:** `agent-hook/` is TypeScript because OpenCode loads plugins
  in JavaScript or TypeScript. It stays a thin shim with no logic.

## Rust

- Format with `cargo fmt`; CI fails on any difference.
- `cargo clippy` with warnings as errors, for every target. Allow a lint
  locally only with a comment that says why.
- Stable toolchain, edition 2021.
- Crates depend only downwards (ADR-0012). `guardian-core` never depends on
  the network, the runtime or async code.
- What we implement ourselves and what we take from crates is ADR-0014.
  Never implement a cryptographic primitive.

## Errors and panics

- Return errors for anything that can fail in normal operation: requests
  from the PC, responses from Ollama, files on disk, configuration.
- Never `unwrap` or `expect` on data from the PC, the network or the disk.
  They are acceptable for invariants that hold by construction, with a short
  comment when that is not obvious.
- The agent must not be able to make the Guardian panic. Size caps are
  checked before parsing any request.
- **Fail closed:** in the decision path, every error becomes `deny`.

## Unsafe code

- Only where unavoidable: foreign functions (llama.cpp, JNI).
- Every `unsafe` block carries a `// SAFETY:` comment that says why it is
  sound.

## Front end

- The web view displays and forwards input; all logic is in Rust commands.
- Key material never crosses into the web view.

## Comments

- Explain why, not what.
- Module comments (`//!`) say what the module is for and which invariants
  it keeps.
- No commented-out code. English only.

## Record format changes

Anything that changes how an event is encoded or hashed changes
`guardian-core` and its golden tests deliberately: a verifier built before
the change must report the mismatch, not accept it silently.

## Tests

- Unit tests next to the code, in a `#[cfg(test)] mod tests` block at the
  end of the module.
- Tests across crates go in the crate's `tests/` directory.
- Every detection rule has one case that must fire and one that must not.
- The hash chain has golden tests for the encoding and a test that edits one
  event and checks that verification fails.
- Tests are deterministic: no live network, no model files. Tests that need
  a model or the Pi are `#[ignore]` with the reason.
- End-to-end behaviour is measured by `eval`, not by unit tests.
- A test that cannot fail is worse than no test.
