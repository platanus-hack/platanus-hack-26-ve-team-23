# Development workflow

- **Status:** Proposed
- **Date:** 2026-10-24

## Task runner

Common tasks go through [`just`](https://github.com/casey/just), so everyone
and CI run the same commands. The `justfile` lands with the workspace
skeleton (ADR-0012).

| Command | What it runs |
|---|---|
| `just fmt` | `cargo fmt --all` |
| `just fmt-check` | `cargo fmt --all -- --check` |
| `just lint` | `cargo clippy --workspace --all-targets -- -D warnings` |
| `just test` | `cargo test --workspace` |
| `just check` | `fmt-check`, `lint` and `test` together |
| `just audit` | `cargo deny check`: advisories, licences, sources |
| `just build-pi` | `guardian` cross-compiled for `aarch64-unknown-linux-gnu` |
| `just witness` | The Tauri witness in development mode |

## Before every commit

1. `just fmt`
2. `just check`
3. Update the component README, the documentation and the changelog if
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
