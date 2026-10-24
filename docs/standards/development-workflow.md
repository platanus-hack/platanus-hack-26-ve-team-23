# Development workflow

- **Status:** Proposed
- **Date:** 2026-10-24

## Task runner

To be defined when the first component is implemented. Every component
exposes the same verbs (format, lint, test) so everyone runs the same
commands.

## Before every commit

1. Format and run the checks of the component you changed.
2. Update the component README, the documentation and the changelog if
   behaviour changed.

## Branch lifecycle

1. Branch from `main`: `git switch -c feat/guardian-decide-endpoint`.
2. Commit small and often.
3. Push the branch and open a pull request.
4. The pull request is squash-merged and the branch is deleted.

## Push policy

- Push freely to your own branches.
- Never push directly to `main`.
- Force-push only your own branches, with `--force-with-lease`.
- Automated tools, including AI assistants, never push, force-push, publish
  or deploy without the explicit approval of the person running them.

## Remotes

The organisation repository is used for judging; personal forks are used
for deploys. See the submission section of the [README](../../README.md).
