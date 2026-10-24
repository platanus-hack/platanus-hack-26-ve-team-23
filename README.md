# HAWK

**Hardware Autonomous Watcher & Keeper** (tentative name).

An AI control monitor for coding agents that lives on separate hardware. It
sees every tool call the agent attempts, blocks the dangerous ones, and keeps
a tamper-evident record that the agent cannot rewrite, witnessed by the
owner's phone and opened only with two keys.

Platanus Hack 26: Caracas. Track: AI Security (AI control). Team 23.

<img src="./project-logo.png" alt="Project logo" width="200" />

> Status: design phase. The decisions are recorded as ADRs in
> [`docs/adr`](docs/adr/README.md); no component is implemented yet. Coding
> agents start with [AGENTS.md](AGENTS.md).

## The problem

Provider guardrails act on what a model says. They do not see what an agent
does with its tools (delete a log, send a secret over the network, disable
its own monitor), and their logs live where neither the owner nor an auditor
can check them independently. A monitor that runs on the same machine as the
agent can be switched off by that agent.

HAWK controls the agent, not the model
([ADR-0002](docs/adr/0002-control-the-agent-not-the-model.md)): it covers the
layer of actions and evidence that content guardrails do not.

## How a tool call flows

```
PC (untrusted host)                 Raspberry Pi (Guardian)            Phone
OpenCode --hook: may I run X?-----> policy: rules + classifier
   |      <---allow / deny---------
   |                                hash chain  ---signed head------> witness
   +--LLM requests to Pi proxy----> proxy logs prompts and tool calls  two keys
Ollama (RTX 4070) <---forwarded---- cross-check hook vs proxy ---alert-> alerts
```

1. The model proposes a tool call. The request and the response pass through
   the proxy on the Pi, which records them.
2. Before running the tool, the OpenCode hook asks the Guardian. Rules, then a
   small classifier, decide: allow, deny, or ask the owner. No answer means
   deny.
3. Every event is appended to a hash chain on the Pi. Signed chain heads go
   to the phone, so a rewritten record no longer matches.
4. If the proxy saw a tool call that never reached the hook, the agent
   bypassed its monitor, and the phone gets an alert.
5. Reading the record needs the opening key and the weekly decryption key,
   both on the phone.

## Components

| Layer | Directory | Runs on | Responsibility |
|---|---|---|---|
| Agent hook | [agent-hook](agent-hook/README.md) | PC | OpenCode plugin: asks the Guardian before every tool call, fails closed |
| Guardian | [guardian](guardian/README.md) | Raspberry Pi | Decision API, LLM proxy, detectors, cross-check, hash chain |
| Witness | [witness](witness/README.md) | Phone | Stores signed heads, receives alerts, holds the two keys |
| Evaluation | [eval](eval/README.md) | PC + Pi | Legitimate and attack tasks, runner, metrics |

The agent under test is OpenCode with a 7B to 8B model served by Ollama on
the PC ([ADR-0009](docs/adr/0009-agent-under-test-opencode-ollama.md)). The
same proxy can front the Claude or OpenAI APIs.

## What HAWK is not

- Not a jailbreak or content guardrail; it does not make the model safer.
- Not a blockchain; integrity comes from a local hash chain and an
  independent witness ([ADR-0006](docs/adr/0006-local-hash-chain-no-blockchain.md)).
- Not protection against an agent with root on the PC; what was recorded
  before that point survives off the PC.

## Documentation

| What | Where |
|---|---|
| Orientation for coding agents | [AGENTS.md](AGENTS.md) |
| Design and threat model | [docs/WHITEPAPER.md](docs/WHITEPAPER.md) |
| Demo script | [docs/DEMO.md](docs/DEMO.md) |
| Milestones | [docs/ROADMAP.md](docs/ROADMAP.md) |
| Why it works this way | [docs/adr](docs/adr/README.md) |
| Proposals under discussion | [docs/rfcs](docs/rfcs/README.md) |
| How work is done | [docs/standards](docs/standards/README.md), [CONTRIBUTING.md](CONTRIBUTING.md) |
| Reporting a vulnerability | [SECURITY.md](SECURITY.md) |
| What changed | [CHANGELOG.md](CHANGELOG.md) |

## Team

- Elisaul Velasquez ([@elisaul170408-ai](https://github.com/elisaul170408-ai))
- Adrián Guevara ([@adrianegb](https://github.com/adrianegb))
- Aaron Chacon Rincones ([@chaconjrincones-star](https://github.com/chaconjrincones-star))
- Samuel Hernández ([@unkn0wn-cs](https://github.com/unkn0wn-cs))

## Hackathon submission checklist

- [ ] Project metadata in `platanus-hack-project.jsonc` (name, one-liner and
      description in Spanish, deploy URL).
- [ ] `project-description.md` with the project description for the voting
      page.
- [ ] 1000x1000 PNG logo, at most 500 KB (`project-logo.png`).
- [ ] This README kept concise.

Deploy platforms cannot connect to the organisation repository. Mirror to a
personal repository by adding it as a second push URL of `origin`:

```bash
git remote set-url --add --push origin https://github.com/platanus-hack/platanus-hack-26-ve-team-23.git
git remote set-url --add --push origin https://github.com/<your-user>/<your-repo>.git
```
