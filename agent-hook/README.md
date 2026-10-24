# agent-hook

OpenCode plugin that asks the Guardian before every tool call. The only
non-Rust code in the repository: OpenCode loads plugins in JavaScript or
TypeScript (ADR-0012), so this stays a thin shim with no logic.

- **Runs on:** the PC (untrusted).
- **Status:** first version in `guardian.ts`. Implements ADR-0004.

## Install

Copy `guardian.ts` to `.opencode/plugin/` in the project (or to
`~/.config/opencode/plugin/`), start the host daemon, and set
`HOST_DAEMON_URL` if it does not listen on `http://127.0.0.1:7070`.

## What it does

- In `tool.execute.before`, sends the tool name, arguments, working
  directory, session id and the model's tool-call id (`call_id`, from
  `input.callID`) to `POST /decide` on the Guardian. The call id lets the
  Core cross-check the hook against the proxy (ADR-0004).
- Runs the tool only if the answer is `allow`. On `deny`, aborts with the
  reason. On `ask`, waits for the owner's answer from the phone.
- On timeout or connection error, denies.

## What it must never do

- Decide on its own, cache decisions, or allow on error.
- Keep the record; the record lives on the Guardian.

## Why it is not enough alone

It runs inside the process it monitors. The proxy on the Guardian records
the model's proposed tool calls independently, and the cross-check detects a
hook that stopped asking.
