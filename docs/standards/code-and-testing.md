# Code and testing

- **Status:** Proposed
- **Date:** 2026-10-24

## Languages

Not decided yet. Each component's language is recorded in an ADR before its
first code lands. Constraints that the choice must respect:

- `agent-hook`: OpenCode plugins are written in JavaScript or TypeScript.
- `guardian`: must run in well under 2 GB on a Raspberry Pi, next to the
  classifier.

## Conventions

- Handle the errors you expect; in the Guardian, an unexpected state denies
  the action rather than allowing it.
- Comments explain why, not what.
- No secrets, keys or mnemonics in code or tests; tests generate their own.

## Tests

- Unit tests next to the code of each component.
- The detection rules have a test for every rule, with one case that must
  fire and one that must not.
- The hash chain has a test that edits one event and checks that
  verification fails.
- End-to-end behaviour is measured by [eval](../../eval/README.md), not by
  unit tests.
