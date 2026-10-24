# ADR-0011: Only permissively licensed dependencies

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The project licence is not decided yet. Whatever it is, the code must stay
free to relicense, and models must be usable in a commercial product later.

## Options considered

### Option 1: accept any licence

- Benefits: the widest choice.
- Drawbacks: copyleft or non-commercial terms could block the licence chosen
  later.

### Option 2: permissive licences only

- Benefits: keeps every licensing option open.
- Drawbacks: excludes some models and libraries.

## Decision

Libraries, models and datasets are accepted only under MIT, Apache-2.0,
BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0 or CC0-1.0. Anything else
needs a new ADR. Tools used only to run the demo and not shipped (OpenCode,
Ollama) are listed with their licence but do not constrain the product.

## Dependencies and licences

None.

## Consequences

### Positive

- The licence of the project can be chosen after the hackathon.

### Tradeoffs

- Models under custom licences (for example some Llama and Gemma releases)
  are excluded from the product.

## Related decisions

- Every ADR lists its dependencies against this list.

## History

- v1.0 (2026-10-24): Initial decision.
