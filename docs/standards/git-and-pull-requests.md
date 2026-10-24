# Git and pull requests

- **Status:** Proposed
- **Date:** 2026-10-24

## Branches

- `main` is the default branch; every change reaches it through a pull
  request.
- Names: `<type>/<short-description>`, lower case, hyphens:
  `feat/hook-fail-closed`.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```
<type>(<scope>): <short description, imperative, 50 characters at most>

Why the change was needed, wrapped at 72 characters.
```

- Types: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`,
  `chore`.
- Scopes: `guardian`, `proxy`, `hook`, `chain`, `witness`, `eval`, `docs`.
- No emojis.

## Pull requests

- One concern per pull request; link the ADR it implements.
- The description says what changed, why, and how it was tested.
- Read your own diff before asking for review. You own every line you
  submit, whatever tool produced it.

## Reviewers

- Does the change do what the ADR says, and only that?
- Does it keep the Guardian fail-closed and off the PC?
- Is every new dependency allowed by ADR-0011?
