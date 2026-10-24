# Instructions for coding agents

Read this first. It tells you what the project is, where everything is, and
the rules you must follow in this repository.

## What you are working on

HAWK (tentative name) is an AI control monitor for coding agents. The agent
runs on an untrusted PC; the monitor (the Guardian) runs on a Raspberry Pi;
the owner's phone is the witness and holds the keys. Read
[README.md](README.md) for the flow and
[docs/WHITEPAPER.md](docs/WHITEPAPER.md) for the threat model.

The project is in the design phase. The ADRs in [docs/adr](docs/adr/README.md)
are the source of truth for every decision. If your task contradicts an ADR,
stop and say so; do not silently change the design.

## Hard constraints

- **Raspberry Pi: 2 GB of RAM, Linux.** Nothing on the Pi may assume more.
  No model of 1.5B parameters or above runs on it (ADR-0005).
- **PC: RTX 4070, 12 GB of VRAM.** It runs OpenCode and Ollama and is
  untrusted. Nothing that decides or records runs on the PC (ADR-0003).
- **Fail closed.** If the Guardian does not answer, the hook denies.
- **No blockchain.** Integrity is a local hash chain plus signed heads on the
  phone (ADR-0006). Do not add chain, consensus or token code.
- **Weekly epoch keys are random and never derived from the mnemonic**
  (ADR-0008).
- **Evaluation before detection.** Detectors are written against the
  evaluation set in [eval](eval/README.md), not the other way round
  (ADR-0010).
- **Licences:** only those allowed by
  [ADR-0011](docs/adr/0011-dependency-licences.md).

## Where things are

| Path | What |
|---|---|
| `agent-hook/` | OpenCode plugin (PC) |
| `guardian/` | Decision API, LLM proxy, detectors, hash chain (Pi) |
| `witness/` | Phone side: heads, alerts, keys |
| `eval/` | Tasks, runner, metrics |
| `docs/adr/` | Decisions |
| `docs/rfcs/` | Proposals under discussion |
| `docs/standards/` | How work is done |
| `docs/ROADMAP.md` | Milestones and what comes next |

Each component directory has a README that says what it does, what it must
never do, and its status.

## Rules

- **Document first:** a change of behaviour or design needs an ADR before the
  code (see [CONTRIBUTING.md](CONTRIBUTING.md)).
- **Never push, force-push, deploy or publish without explicit approval** of
  the person running you. Commit locally and ask.
- **Do not edit `platanus-hack-project.jsonc`, `project-description.md` or
  `project-logo.png`** unless asked; they are the hackathon submission.
- **English** in the repository; no emojis.
- **Branches and commits** follow
  [docs/standards/git-and-pull-requests.md](docs/standards/git-and-pull-requests.md).
- **No secrets** in the repository: keys, mnemonics, tokens.
- Update the README of the component and `CHANGELOG.md` in the same change.

## Open questions

Listed at the end of the [ADR index](docs/adr/README.md). Do not decide them
on your own; propose an answer in an ADR or RFC.
