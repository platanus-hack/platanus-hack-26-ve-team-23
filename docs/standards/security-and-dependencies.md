# Security and dependencies

- **Status:** Proposed
- **Date:** 2026-10-24

## Secrets

- Never commit private keys, mnemonics, tokens or API keys.
- Runtime secrets come from the environment.
- A secret that reaches the repository is compromised: rotate it, then
  remove it from the history.

## Attack material

The evaluation set contains prompt injections and harmful side goals. They
target only the local sandbox workspace: no real secrets, no real external
hosts. Network egress in attack tasks goes to a sink controlled by us.

## Reporting vulnerabilities

Follow [SECURITY.md](../../SECURITY.md).

## New dependencies

- Only licences allowed by [ADR-0011](../adr/0011-dependency-licences.md),
  transitive dependencies included.
- Anything that touches cryptography, networking or the decision path is a
  design decision and goes through an ADR.
- Prefer maintained libraries with few dependencies. Lockfiles are
  committed.
