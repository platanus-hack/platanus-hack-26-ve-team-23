# CLAUDE.md

Instructions for Claude Code and any other coding agent in this repository.
`AGENTS.md` points here. Read this before changing anything.

## What this is

HAWK (Hardware Autonomous Watcher & Keeper, tentative name) is an AI
control monitor for coding agents (Platanus Hack 26, AI Security track,
team 23). It stops dangerous agent actions before they run, contains the
host at the network firewall, and keeps a record the agent cannot rewrite.

| Edge | Crate | Runs on | Role |
|---|---|---|---|
| Core | `guardian` | Raspberry Pi (2 GB, Linux) | Decides, records, contains, serves the owner's app |
| Host daemon | `host-daemon` | Every monitored machine | Relays the agent hook to the Core; no UI except the identification notice |
| Owner app | `witness` | The owner's phone (APK); desktop build for development | Activates and controls the Core, shows the dashboard, verifies the record |

The phone app is the control surface. Monitored machines run only the
daemon; the only thing they ever show is a notice when the owner presses
"Identify" (to find one machine among dozens).

Shared crates: `guardian-core` (record format, chain, signatures, sealing,
wire messages; no I/O), `edge-net` (QUIC, discovery, loopback HTTP),
`detect` (rule engine and policy), `integrations` (firewalls, event sinks),
`llm-proxy` (tool-call extraction for the proxy that runs inside the
daemon), `eval` (evaluation set, runner, metrics, `stress`). Full flow:
`docs/ACTION-TREE.md`.

## How decisions are made here: ADRs first

The ADRs in `docs/adr/` are the source of truth. Code follows them, not the
other way round.

1. **Before changing behaviour, design, the threat model, the wire format,
   what is recorded, or adding a dependency:** find the ADR that covers it.
   - If one covers it, follow it.
   - If your change contradicts it, stop and say so. Do not change the
     design silently.
   - If none covers it, write one: copy `docs/adr/0000-template.md` to the
     next free number, status **Proposed**, and add it to the index in
     `docs/adr/README.md`.
2. **Proposed ADRs may be edited in place** (add a line to their History).
   **Accepted ADRs are never rewritten**: a changed decision gets a new ADR
   that supersedes it, and the old one only changes its status.
3. **Every ADR lists its new dependencies with their licence.** Only the
   licences of ADR-0011 are allowed (`just audit` checks them).
4. **Discussion first when unsure:** larger proposals start as an RFC in
   `docs/rfcs/`.
5. **Code, then docs, in the same change:** update the component README,
   `CHANGELOG.md` (under Unreleased), `docs/ROADMAP.md` and `PENDIENTES.md`.

Today every ADR is Proposed (0001 to 0030; 0008 superseded by 0017). The
team approves them.

## Hard rules

- **Nothing between our devices travels in clear text.** Links between the
  Core, the daemons and the app are QUIC with mutual TLS 1.3; the Ed25519 key
  in each certificate is the identity (ADR-0023). The Core has no HTTP
  endpoint. The only HTTP is the daemon's loopback socket for the OpenCode
  plugin, which cannot speak QUIC.
- **Identity, not addresses.** The app and the daemons pin the Core's key.
  The Core serves its record and configuration only to the app identity bound
  at pairing; the owner's signature covers the Core, the offer nonce and that
  app (ADR-0017, ADR-0023). Containment targets the socket address of the
  authenticated peer, never an address a client declares.
- **Fail closed on failure, not on silence** (ADR-0022): errors, timeouts,
  malformed input, an unpaired Core, a record that cannot be written: deny.
  No finding and a low score: allow.
- **The Core never runs on the monitored machine** and never loads a model of
  1.5B parameters or more (ADR-0003, ADR-0005).
- **Offline first** (ADR-0027): the Core, the daemons and the app work with
  no cloud and no internet. Every cloud feature (archive, remote
  configuration) is optional, available to any owner, and the Core keeps
  working if the cloud is unreachable.
- **Configuration is a chain**: the next configuration is exactly the active
  version plus one and names the active hash; never accept a rollback, a
  skip or a fork. Only the owner can change the enterprise signer.
- **No blockchain** (ADR-0006). Integrity is the local hash chain plus heads
  signed with Ed25519 and ML-DSA-65 (ADR-0019), verified by the app against
  the pinned identity.
- **The Core writes the record but cannot read it**: payloads are sealed to
  the app's weekly epoch key (ADR-0007). Epoch keys are never derived from
  anything recoverable (ADR-0008, ADR-0017).
- **Own implementation, established primitives** (ADR-0014): never write a
  cryptographic primitive or a protocol parser yourself.
- **Untrusted text** (hostnames, tool names, rules, anything from the
  network) goes into the web view with `textContent`, and into commands as
  separate arguments after sanitising, never through a shell.
- **Keys never reach the web view** of the app (ADR-0013).

## Stack and layout

Rust workspace (ADR-0012), Tauri 2 for the app with plain HTML/CSS/JS
(ADR-0013), hyper only for loopback, quinn for QUIC, mdns-sd for discovery.
Patterns may be copied from Nepheral-core, which the team owns and runs in
production (workspace, TLS identities, QUIC, mDNS, Tauri shell, Android
Keystore). Crates depend only downwards; `guardian-core` does no I/O.

## Working in the repository

| Task | Command |
|---|---|
| Format, lint (warnings are errors), test | `just check` |
| Licences and advisories | `just audit` |
| Run the Core (QUIC on `0.0.0.0:7443`) | `just guardian` |
| QUIC hello against a Core | `just probe 127.0.0.1:7443` |
| Run a host daemon | `just daemon` (set `GUARDIAN_CORE=ip:7443` to skip discovery) |
| Run the app on the desktop | `just witness` |
| Review the app design without a Core | open `witness/ui/index.html` in a browser (`?wizard` for the activation) |
| Docker | `docker compose run --rm check`, `just docker-smoke` |
| Router lab for containment | `docs/LAB.md` (MikroTik CHR 7.x and OpenWrt VMs in Hyper-V) |

- Clippy denies `unwrap`, `expect`, `panic` and `println!` outside tests;
  allow one only with a comment that says why.
- Every new behaviour comes with a test; a detection rule with one case that
  fires and one that does not.
- Look at UI changes before calling them done: render the page (a headless
  Chromium from Playwright is installed) and check the screenshot.

## Git and publishing

- Work happens on branches; Conventional Commits; English; no emojis.
- The code lives in the **private** repository `JEHR037/team23-private`
  (remote `origin`). **Never push to the public organisation repository**
  until the team decides what to submit. Push only with the user's approval.
- Do not edit `platanus-hack-project.jsonc`, `project-description.md` or the
  logo unless asked: they are the hackathon submission.
- No secrets in the repository: keys, mnemonics, router passwords, tokens.

## What is not built and why

`PENDIENTES.md` lists every open item, who should do it, and why;
`docs/EJECUCION-PENDIENTES.md` says how to execute each one, with acceptance
criteria and ready-to-use prompts. Some
items (the detection rule catalogue, the evaluation attacks, host heartbeats
and attestation) were stopped by the model's safety filter while being
written, so they are for the team to write by hand. Do not retry them in a
loop; build around them.
