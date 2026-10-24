# ADR-0011: Only permissively licensed dependencies, enforced by cargo deny

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The project licence is not decided yet. Whatever it is, the code must stay
free to relicense, models must be usable in a commercial product later, and
code may be shared with Nepheral, whose dependency policy is Nepheral
ADR-0018. Rust links statically, so a copyleft dependency would impose its
terms on the whole binary.

## Options considered

### Option 1: review licences case by case in pull requests

- Benefits: no tooling.
- Drawbacks: transitive dependencies go unnoticed.

### Option 2: an allow list, recorded here and enforced in CI

- Benefits: every dependency, direct or transitive, is checked on every
  pull request.
- Drawbacks: a useful library under an excluded licence cannot be used.

## Decision

The same allow list as Nepheral ADR-0018, so code moves between the two
projects without a licence review:

| Licence | Notes |
|---|---|
| MIT, MIT-0, Apache-2.0, Apache-2.0 WITH LLVM-exception | Permissive |
| BSD-1-Clause, BSD-2-Clause, BSD-3-Clause, 0BSD, ISC, Zlib, BSL-1.0 | Permissive |
| Unlicense, CC0-1.0 | Public-domain dedications |
| Unicode-3.0, CDLA-Permissive-2.0 | Unicode tables and certificate data |
| MPL-2.0 | Only for crates used unmodified |
| OFL-1.1 | Only for font files, shipped with their licence text and never sold on their own |

Not allowed: GPL, LGPL, AGPL; source-available licences on a dependency;
non-commercial or no-derivatives licences; custom model licences (for
example some Llama and Gemma releases); anything without a clear licence.

Tools used only to run the demo and not shipped (OpenCode, Ollama) are
listed with their licence but do not constrain the product.

### Key points

- `cargo deny check` runs the list in `deny.toml` on every pull request.
- Every ADR and RFC lists the dependencies it adds, with their licences.

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| cargo-deny (tool) | latest | MIT OR Apache-2.0 |

## Consequences

### Positive

- The project licence can be chosen after the hackathon.
- Code can be shared with Nepheral in both directions.

### Tradeoffs

- Some models and libraries are excluded.

## Implementation

### Where it lives

- `deny.toml`.

## Related decisions

- Every ADR lists its dependencies against this list.

## References

- Nepheral ADR-0018.

## History

- v1.0 (2026-10-24): Initial decision.
- v1.1 (2026-10-24): Aligned with Nepheral ADR-0018 and enforced with
  `cargo deny`, before acceptance.
- v1.2 (2026-10-24): OFL-1.1 allowed for font files only (Saira and
  JetBrains Mono in the owner app, ADR-0031), as decided by the team. Fonts
  are not crates, so `cargo deny` does not see them; the ADR that ships a
  font lists it.
