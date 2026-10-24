# ADR-0034: Every agent and every model on the host, as far as each allows

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23 (approval pending)

## Context

ADR-0004 enforces with an OpenCode plugin and records with an
OpenAI-compatible proxy in front of Ollama (ADR-0009). Owners run more than
that on the same machine: Claude Code, Codex, other agents, local model
servers (Ollama, LM Studio, llama.cpp, vLLM) and cloud APIs (OpenAI,
Anthropic). HAWK has to see all of it, or say plainly what it cannot see.

What each one allows decides how far HAWK can go:

- **Claude Code and Codex** run `PreToolUse` command hooks: the agent sends
  the tool call as JSON on stdin and the hook can deny it before it runs.
  Both fail open by default when the hook crashes or times out; Claude Code
  can be told to block instead (`"onFailure": "block"`), Codex cannot.
  Codex does not support "ask" from a hook.
- **Model servers** are reached over HTTP: a proxy sees requests and the tool
  calls the model proposes, but only when the agent is pointed at it.
- **Cloud APIs** travel over TLS. Reading them without the agent's
  cooperation would mean a root certificate on the machine to intercept
  TLS, which would weaken the host more than it protects it.

## Options considered

### Option 1: OpenCode only (today)

- Drawbacks: every other agent runs unseen.

### Option 2: intercept everything at the network (TLS interception)

- Benefits: sees any cloud call.
- Drawbacks: a root CA on the host; breaks pinned clients; a new, valuable
  target; against ADR-0002 (control the agent, not the model).

### Option 3: three layers, each as strong as the agent allows

## Decision

Option 3.

1. **Enforce through each agent's hook** (blocks before execution):
   OpenCode (plugin), Claude Code and Codex (`hawk-host-daemon hook`, one
   command for both). The hook normalises the call (`Bash`, `exec_command`,
   `shell` → `bash`; `Write`, `Edit`, `MultiEdit`, `apply_patch` → `write` or
   `edit` with `path`; `Read` → `read`; `WebFetch` → `webfetch` with `url`),
   tags the session with the agent (`claude:`, `codex:`), asks the daemon,
   and waits for the owner when the Core asks. Any failure denies (exit 2).
   `hawk-host-daemon hooks install` registers it in `~/.claude/settings.json`
   (with `"onFailure": "block"`) and `~/.codex/hooks.json`, keeping every
   other setting and a backup; `hooks uninstall` removes only our entry.
2. **Record every model through the proxy** (sees proposals, feeds the
   cross-check): `/v1` and `/api` go to local Ollama as before; `/openai/...`
   goes to the OpenAI API and `/anthropic/...` to the Anthropic API over
   HTTPS, with the agent's own credentials passed through and never stored
   in clear. Tool calls are extracted from OpenAI chat completions, the
   OpenAI Responses API and Anthropic Messages, streaming or not.
3. **Detect everything else** (no agent cooperation needed): the daemon
   lists AI agents and model servers running on the host (process names and
   known local ports) and reports them to the Core every minute. An agent
   running without HAWK's hook raises a high alert; a model server is
   recorded. The owner sees what HAWK watches and what it does not.

The cross-check "a decide the model never proposed" (ADR-0004) now applies
only to hosts whose agents use the proxy, so an agent outside the proxy
does not flood the owner with false alerts.

### What HAWK still cannot do

- Block an agent that has no hook (it is detected and reported, not
  stopped); Codex hooks fail open on a timeout.
- See a cloud API call from an agent not pointed at the proxy.

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| None for layer 1 | | |
| hyper-rustls (layer 2, already in the workspace) | 0.27 | Apache-2.0 OR ISC OR MIT |
| sysinfo (layer 3, process list; not added yet) | 0.33 | MIT |

## Consequences

### Positive

- Claude Code and Codex are enforced like OpenCode; cloud and local models
  are recorded when routed; nothing else runs unseen.

### Tradeoffs

- The owner must route cloud APIs through the proxy (environment variables
  the installer prints); without it, cloud calls are only detected.
- The daemon now makes outbound HTTPS calls to model APIs on the agent's
  behalf.

## Implementation

### Where it lives

Built (layer 1 and the cross-check scope):

- `host-daemon/src/agents.rs`: hook normalisation, the `hook` command and
  `hooks install|uninstall|status`.
- `guardian/src/crosscheck.rs`, `guardian/src/api.rs`: the cross-check
  applies only to hosts that sent a proxy record in the last 10 minutes.
- `misc/landing/install.sh`: registers the hooks for the agents it finds.

Not built yet (layers 2 and 3, for the team): the cloud routes and formats
of the proxy, and the host inventory with its alerts.

## Related decisions

- ADR-0002, ADR-0004 (refined here), ADR-0009, ADR-0015, ADR-0021, ADR-0022.

## History

- v1.0 (2026-10-24): Initial proposal.
- v1.1 (2026-10-24): layer 1 (Claude Code and Codex hooks) and the
  cross-check scope built; layers 2 and 3 left for the team.
