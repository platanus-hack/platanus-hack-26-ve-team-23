# agent-hook

OpenCode plugin that asks the Guardian before every tool call.

- **Runs on:** the PC (untrusted).
- **Status:** planned. Implements ADR-0004.

## What it does

- In `tool.execute.before`, sends the tool name, arguments, working
  directory and session id to `POST /decide` on the Guardian.
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
