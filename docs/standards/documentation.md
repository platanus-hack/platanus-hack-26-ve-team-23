# Documentation

- **Status:** Proposed
- **Date:** 2026-10-24

## Where things are written

| What | Where |
|---|---|
| What the project is | `README.md` |
| Instructions for coding agents | `AGENTS.md` |
| How to contribute | `CONTRIBUTING.md`, `docs/standards/` |
| How the system works | `docs/WHITEPAPER.md` |
| Demo | `docs/DEMO.md` |
| Milestones | `docs/ROADMAP.md` |
| Why it works that way | `docs/adr/` |
| Proposals under discussion | `docs/rfcs/` |
| What changed | `CHANGELOG.md` |
| Each component | its `README.md` |
| Hackathon submission | `platanus-hack-project.jsonc`, `project-description.md` (Spanish) |

## Rules

- English everywhere except the hackathon submission files, which are in
  Spanish.
- No emojis.
- Update the documentation in the same pull request as the change.
- Every user-visible change gets a line under `Unreleased` in
  `CHANGELOG.md`.

## README of a component

Each component README says:

- what it is for and what it must never do;
- its main entry points;
- its status and the ADRs it implements;
- how to run its tests.
