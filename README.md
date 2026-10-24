# HAWK

**Hardware Autonomous Watcher & Keeper** (tentative name).

An AI control monitor for coding agents that lives on separate hardware. It
sees every tool call the agent attempts, blocks the dangerous ones, and keeps
a tamper-evident record that the agent cannot rewrite, witnessed by the
owner's phone and opened only with two keys.

Platanus Hack 26: Caracas. Track: AI Security (AI control). Team 23.

<img src="./project-logo.png" alt="Project logo" width="200" />

> Status: workspace skeleton. The decisions are recorded as ADRs in
> [`docs/adr`](docs/adr/README.md). The hash chain and the Guardian's
> `/health` and `/decide` endpoints exist; detection denies everything until
> the rules are written. Coding agents start with [AGENTS.md](AGENTS.md).

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
5. Reading the record needs the owner passkey and the weekly decryption key,
   both on the phone.

6. On an evasion or an exfiltration attempt, the Core puts the host in the
   quarantine list of the network firewall (MikroTik, then Cisco), so even
   a host with root access is cut off
   ([ADR-0018](docs/adr/0018-network-containment-through-the-firewall.md)).

A new Core does nothing until it is paired with the owner's phone
([ADR-0017](docs/adr/0017-core-pairing-and-passkeys.md)). Chain heads carry
hybrid Ed25519 + ML-DSA signatures
([ADR-0019](docs/adr/0019-post-quantum-signatures-on-heads.md)). Remote
models go through OpenRouter with the key held only by the Core
([ADR-0020](docs/adr/0020-openrouter-upstream-and-key-custody.md)).

**Prevent, not just record.** A black box tells you why the plane crashed;
HAWK stops the action before it runs, and contains the host at the network
when the agent tries to get around it. A record sealed on the infected
machine only proves what the attacker let it seal; HAWK seals on a separate
device.

## Components

Back end in Rust, one Cargo workspace
([ADR-0012](docs/adr/0012-rust-workspace-and-crate-boundaries.md)); front end
in Tauri 2, one crate for desktop and APK
([ADR-0013](docs/adr/0013-tauri-front-end.md)); the monitor is our own
implementation on top of established primitives
([ADR-0014](docs/adr/0014-own-implementation-established-primitives.md)).

| Layer | Crate | Runs on | Responsibility |
|---|---|---|---|
| Record format | [guardian-core](guardian-core/README.md) | everywhere | Event encoding, hash chain, shared types. No I/O |
| Detection | [detect](detect/README.md) | Raspberry Pi | Rules, sequence rules, classifier |
| Proxy | [llm-proxy](llm-proxy/README.md) | Raspberry Pi | OpenAI-compatible proxy to Ollama, tool-call extraction |
| Networking | [edge-net](edge-net/README.md) | Core and hosts | HTTP on hyper and tokio; framed protocol between edges |
| Core | [guardian](guardian/README.md) | Raspberry Pi | Daemon: pairing, `/decide`, proxy, cross-check, chain store |
| Host daemon | [host-daemon](host-daemon/README.md) | Every machine running agents | Relays hooks to the Core, sensors, heartbeat; never decides |
| Witness | [witness](witness/README.md) | Phone (APK) and desktop | Tauri 2 app: heads, alerts, keys, verifier |
| Evaluation | [eval](eval/README.md) | PC + Pi | Tasks, runner, metrics, classifier training |
| Agent hook | [agent-hook](agent-hook/README.md) | PC | Thin TypeScript OpenCode plugin; asks the Guardian, fails closed |

## Build and test

```sh
just check          # fmt, clippy (warnings are errors) and tests
just guardian       # run the Guardian on :8080
just witness        # run the witness on the desktop
just witness-apk    # build the witness APK (Android SDK and NDK)
```

With Docker, no local toolchain is needed:

```sh
docker compose run --rm check     # fmt, clippy and tests in a container
docker compose up -d guardian     # Guardian limited to 2 GB, like the Pi
docker compose run --rm smoke     # it answers and fails closed
```

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

## Licence

Not chosen yet. Until it is, no licence is granted. Whatever it becomes,
every dependency must use a licence from the allow list in
[ADR-0011](docs/adr/0011-dependency-licences.md) (MIT, Apache-2.0, BSD,
ISC and similar; no GPL, LGPL or AGPL, no non-commercial licences), checked
by `just audit`.

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
