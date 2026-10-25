# HAWK

**Hardware Autonomous Watcher & Keeper** (tentative name).

An AI control monitor for coding agents that lives on separate hardware. It
stops dangerous agent actions before they run, contains the machine at the
network firewall when the agent tries to get around it, and keeps a record
the agent cannot rewrite, verified by the owner's phone.

Platanus Hack 26: Caracas. Track: AI Security (AI control). Team 23.

<img src="./project-logo.png" alt="Project logo" width="200" />

> **Status.** Working end to end: the OpenCode plugin asks the host daemon on
> loopback; the daemon relays over QUIC with mutual TLS to the Core; the Core
> decides, seals and chains every decision, signs heads (Ed25519 + ML-DSA-65)
> and contains hosts on the firewall. The owner's phone app finds the Core on
> the network, activates it with a wizard, shows the dashboard, verifies the
> heads and can make any monitored machine identify itself. Detection rules,
> host heartbeats and the LLM proxy are pending: see
> [`PENDIENTES.md`](PENDIENTES.md). Decisions: [`docs/adr`](docs/adr/README.md).
> Flow: [`docs/ACTION-TREE.md`](docs/ACTION-TREE.md). Coding agents:
> [`CLAUDE.md`](CLAUDE.md).

## The problem

Provider guardrails act on what a model says. They do not see what an agent
does with its tools (delete a log, send a secret over the network, disable
its own monitor), and their logs live where neither the owner nor an auditor
can check them independently. A monitor that runs on the same machine as the
agent can be switched off by that agent.

HAWK controls the agent, not the model
([ADR-0002](docs/adr/0002-control-the-agent-not-the-model.md)): it covers the
layer of actions and evidence that content guardrails do not.

## The three edges

```
 Monitored machine                    Core (Raspberry Pi)                 Owner's phone
 OpenCode --hook--> host daemon ==QUIC==> decide: rules + policy   <==QUIC== HAWK app
            loopback   | identity        seal + chain + sign heads           activate (wizard)
                       | pin             contain at the firewall             dashboard, verify heads
            notice <---+---- identify -- hosts by fingerprint  <--identify-- find a machine
```

- **Core** (`guardian`): decides, records, contains. Inactive until the
  owner's app pairs with it ([ADR-0017](docs/adr/0017-core-pairing-and-passkeys.md)).
- **Host daemon** (`host-daemon`): runs on every monitored machine. Relays the
  agent hook, has no UI except the identification notice.
- **Owner app** (`witness`): the phone app that controls everything (APK; a
  desktop build exists for development).

Every link between them is QUIC with mutual TLS 1.3, and each certificate's
Ed25519 key is the identity ([ADR-0023](docs/adr/0023-quic-with-mutual-tls-between-edges.md)).
The Core announces itself by mDNS and the app activates it with a wizard;
nobody types addresses ([ADR-0024](docs/adr/0024-discovery-and-activation-wizard.md)).

## How a tool call flows

1. Before running a tool, the OpenCode plugin asks the host daemon on
   loopback. If the daemon does not answer, the tool does not run.
2. The daemon relays the call to the Core over QUIC, pinned to the Core's
   identity. If the Core cannot be reached, the daemon denies.
3. The Core evaluates the call: rules and, later, a small classifier; the
   highest severity decides: allow, ask the owner, deny, or deny and contain
   ([ADR-0022](docs/adr/0022-decision-policy-severities-and-defaults.md)).
4. Every decision is sealed to the owner's weekly key, appended to a hash
   chain and covered by heads signed with Ed25519 and ML-DSA-65
   ([ADR-0019](docs/adr/0019-post-quantum-signatures-on-heads.md)). The Core
   can write the record but cannot read it.
5. On a critical finding the Core puts the machine in the quarantine list of
   the network firewall (OpenWrt, MikroTik; Cisco next), so even a machine
   with root access is cut off
   ([ADR-0018](docs/adr/0018-network-containment-through-the-firewall.md)).
6. Event metadata goes to Kafka or a webhook
   ([ADR-0020](docs/adr/0020-integrations-firewalls-and-event-sinks.md)).

**Prevent, not just record.** A black box tells you why the plane crashed;
HAWK stops the action before it runs. A record sealed on the infected
machine only proves what the attacker let it seal; HAWK seals on a separate
device.

## Components

Rust workspace ([ADR-0012](docs/adr/0012-rust-workspace-and-crate-boundaries.md)),
Tauri 2 app ([ADR-0013](docs/adr/0013-tauri-front-end.md)), our own monitor
on established primitives ([ADR-0014](docs/adr/0014-own-implementation-established-primitives.md)).

| Layer | Crate | Runs on | Responsibility |
|---|---|---|---|
| Record and wire | [guardian-core](guardian-core/README.md) | everywhere | Events, hash chain, signed heads, sealing, wire messages. No I/O |
| Detection | [detect](detect/README.md) | Core | Rule engine and policy (rule catalogue pending) |
| Networking | [edge-net](edge-net/README.md) | everywhere | QUIC with mutual TLS, mDNS discovery, loopback HTTP |
| Integrations | [integrations](integrations/README.md) | Core | Firewalls (dry run, MikroTik, OpenWrt), Kafka and webhook |
| Core | [guardian](guardian/README.md) | Raspberry Pi | Pairing, decisions, record, containment, hosts, identify |
| Host daemon | [host-daemon](host-daemon/README.md) | Monitored machines | Hook relay over QUIC, Core pinning, identification notice |
| Owner app | [witness](witness/README.md) | Phone (APK), desktop for dev | Activation wizard, dashboard, verification, identify |
| Agent hook | [agent-hook](agent-hook/README.md) | Monitored machines | Thin TypeScript OpenCode plugin; fails closed |
| LLM proxy | [llm-proxy](llm-proxy/README.md) | Host daemon | Planned |
| Evaluation | [eval](eval/README.md) | PC + Core | Planned |

## Build and run

```sh
just check                  # fmt, clippy (warnings are errors) and tests
just guardian               # the Core: QUIC on 0.0.0.0:7443, announced by mDNS
just probe 127.0.0.1:7443   # QUIC hello against a Core
just daemon                 # a host daemon (GUARDIAN_CORE=ip:7443 to skip discovery)
just witness                # the owner app on the desktop
just witness-apk            # the owner app as an APK (Android SDK and NDK)
```

To review the app's design without a Core, open `witness/ui/index.html` in a
browser (add `?wizard` to see the activation).

With Docker (not yet tested on this machine):

```sh
docker compose run --rm check   # fmt, clippy and tests in a container
just docker-smoke               # the Core limited to 2 GB, then a QUIC hello
```

The agent under test is OpenCode with a 7B to 8B model served by Ollama
([ADR-0009](docs/adr/0009-agent-under-test-opencode-ollama.md)).

## What HAWK is not

- Not a jailbreak or content guardrail; it does not make the model safer.
- Not a blockchain; integrity comes from a local hash chain and an
  independent witness ([ADR-0006](docs/adr/0006-local-hash-chain-no-blockchain.md)).
- Not protection against an agent with root on the PC; what was recorded
  before that point survives off the PC.

## Documentation

| What | Where |
|---|---|
| Instructions for coding agents | [CLAUDE.md](CLAUDE.md) |
| Design and threat model | [docs/WHITEPAPER.md](docs/WHITEPAPER.md) |
| Demo script | [docs/DEMO.md](docs/DEMO.md) |
| Router lab (Hyper-V VMs: MikroTik CHR, OpenWrt) | [docs/LAB.md](docs/LAB.md) |
| Optional cloud: archive and configuration as code (OpenTofu, Render, LocalStack) | [infra/README.md](infra/README.md) |
| Training the classifier (Granite) | [docs/ENTRENAMIENTO-GRANITE.md](docs/ENTRENAMIENTO-GRANITE.md) |
| Milestones and state | [docs/ROADMAP.md](docs/ROADMAP.md) |
| What is missing and why | [PENDIENTES.md](PENDIENTES.md) |
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

- Javier Hernández ([@JEHR037](https://github.com/JEHR037))
- Elisaul Velasquez ([@elisaul170408-ai](https://github.com/elisaul170408-ai))
- Adrián Guevara ([@adrianegb](https://github.com/adrianegb))
- Aaron Chacon Rincones ([@chaconjrincones-star](https://github.com/chaconjrincones-star))
- Samuel Hernández ([@unkn0wn-cs](https://github.com/unkn0wn-cs))

## Hackathon submission checklist

- [x] Project metadata in `platanus-hack-project.jsonc` (name, one-liner and
      description in Spanish, deploy URL).
- [x] `project-description.md` with the project description for the voting
      page.
- [x] 1000x1000 PNG logo, at most 500 KB (`project-logo.png`: the HAWK
      mark and wordmark).
- [ ] This README kept concise.

Deploy platforms cannot connect to the organisation repository. Mirror to a
personal repository by adding it as a second push URL of `origin`:

```bash
git remote set-url --add --push origin https://github.com/platanus-hack/platanus-hack-26-ve-team-23.git
git remote set-url --add --push origin https://github.com/<your-user>/<your-repo>.git
```
