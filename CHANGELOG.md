# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Every entry is written when the change is merged, under `Unreleased`.

## [Unreleased]

### Changed

- ADR-0003 v1.1 and ADR-0021 v1.3: validating off the host is set next to
  how the large platforms separate who executes from who decides (Apple
  Secure Enclave and Private Cloud Compute, TPM and Pluton, HSMs, AWS Nitro,
  SIEM and WORM storage, the reference monitor, AI control), with the limits
  of the analogy: the hook on the PC is cooperative, the network is HAWK's
  lever, and the TPM key closes the impersonation gap.

- Repository hygiene: `witness/gen/schemas/` is no longer tracked (tauri-build
  regenerates it); README, CLAUDE.md, ROADMAP and PENDIENTES now describe the
  12-rule catalogue, the Claude Code and Codex hooks, the proxy and `eval` as
  built, ADRs up to 0035 and the trained (not yet integrated) classifier.
  `docs/DEMO.md` uses the current setup (hooks, the HAWK app, optional
  router) and adds the dead man's switch step.

### Fixed

- The owner app is called HAWK on the launcher, the window and the
  installers (it showed as "Witness"), and the APK's launcher icon is the
  HAWK mark, generated at release time from `witness/icons/hawk-launcher.png`
  (it had Tauri's default icon). The identifier stays `org.team23.witness`,
  so installed apps keep their data. The hackathon logo is the HAWK mark and
  wordmark. Version 0.1.6.

- Claude Code's `PowerShell` tool on Windows (and `pwsh`, `cmd`) is judged as a
  command by the rules; before 0.1.5 it was recorded but no rule read it.
  The record keeps which shell it was. Version 0.1.5.

### Added

- Hackathon submission filled in: `platanus-hack-project.jsonc` (name,
  one-liner and description in Spanish, deploy URL `https://hawkeeper.xyz`)
  and `project-description.md` for the voting page, including what is real
  in the demo and what is not.

- ADR-0034 and Claude Code and Codex hooks: `hawk-host-daemon hook
  claude|codex` is their `PreToolUse` hook (normalises the call, asks the
  daemon, blocks on any failure), and `hooks install|uninstall|status` edits
  their configuration keeping everything else and a backup. `install.sh`
  registers it for the agents it finds (from 0.1.4). The Core now compares
  a `decide` with the model's proposals only on hosts that use the proxy,
  so an agent talking to its model directly raises no false alerts.

- ADR-0033: attention thresholds the owner sets from the app.
  `CoreConfig.thresholds { ask_from, deny_from }` travels in the signed
  configuration chain (left out of the JSON while default, so older
  configurations keep their hash); the Core refuses thresholds that would
  let a high finding through without asking, `decide` applies them, and
  `Status` reports them. The app edits them in the configuration form and
  shows them in Settings, next to a new "what HAWK does and does not do"
  card. Two medium rules (`hawk.git.force-push`,
  `hawk.fs.recursive-delete`) make "ask" happen with the shipped catalogue.

### Changed

- The OpenCode plugin is published as `hawk-opencode-plugin.ts` (was
  `guardian.ts`), and `install.sh` now checks it against `SHA256SUMS`
  before installing it: it runs inside OpenCode, and before it was copied
  unchecked. The downloads page groups the files (app, program for each
  computer, Core, plugin, verification) and says what each one is.
- The Android APK is a release build for arm64, zipaligned and signed (with
  `ANDROID_KEYSTORE_B64` when set, a test key otherwise): about 700 MB as a
  debug build for four ABIs before. Version 0.1.3 is the first with it.
- Landing: the hero spells out Hardware Autonomous Watcher & Keeper; the
  Core runs today on a dedicated device (a Raspberry Pi 4 or another 64-bit
  Linux machine) and the next step needs one able to run a Granite 4 class
  model (~800M, ADR-0005 v1.2); new sections for the optional off-site
  archive in S3-compatible storage with Object Lock and for the next steps;
  an answer on the thresholds. The phone frame shows the current app.
- Version 0.1.2: the attention thresholds and the cleaner app. Version 0.1.1: the first release built by `release.yml`. The v0.1.0
  release, built by hand from `887ae46`, stays as published.
- The landing, the installer and the release notes use
  `https://hawkeeper.xyz`.
- Landing checked against the code: the Core runs on any separate 64-bit
  Linux machine, not only a Pi (the release ships x86_64 and aarch64);
  containment needs an OpenWrt or MikroTik router; discovery can fall back
  to typing the address; the claim about testing with 7-8B models is gone
  (M2 is pending); a new answer lists what the rules detect today and that
  unrecognised actions are allowed and recorded.

- Documentation synced with the code: `CLAUDE.md` describes `llm-proxy` and
  `eval` as built, counts ADRs 0001 to 0030 and names the `origin` remote;
  the roadmap adds M12 (repository clean-up), M13 (landing page and app
  redesign, designs ready) and the critical path for the demo;
  `PENDIENTES.md` lists that path and the redesign after the clean-up.
- ADR-0011 v1.2: OFL-1.1 allowed for font files only, as the team decided.
- `webpki-roots` 1.0.11 (RUSTSEC-2026-0381, distrusted emSign roots).
  `deny.toml` records two exceptions with their reason and review:
  RUSTSEC-2026-0387 (crypto-bigint 0.5 via p256 0.13, until the p256 0.14
  migration) and RUSTSEC-2024-0370 (proc-macro-error via Tauri's GTK).
- Landing: simpler and more sober content; the interactive demo, the
  decision ticker and "Lo que no es" are gone; "Instalación" is a step by
  step guide (requirements, the Core on the Pi, activation, the daemon,
  approval); Javier Hernández added to the team.
- `witness/icons`: the HAWK mark replaces the icons copied from Nepheral.

### Added

- ADR-0031: the owner app's design, information structure and UI contract
  (grey and black identity, light and dark, five screens, one state per Core
  situation, status never by colour alone).
- `misc/landing`: the internal landing page (3D Raspberry Pi with three.js,
  part explorer, the real app in a phone frame, design tokens in
  `DESIGN.md`) and the host daemon installer `install.sh` (SHA-256 checked
  download, systemd service under its own user, OpenCode plugin).
- ADR-0032 and GitHub Actions: `ci.yml` (fmt, clippy as errors, tests,
  `cargo deny`, i18n audit on every push and pull request) and
  `release.yml` (on a `v*` tag: host daemon for Linux x86_64/aarch64,
  Windows and macOS (Apple Silicon and Intel), the Core for the Pi and
  x86_64, the app as `.deb`, AppImage, Windows installer and universal
  macOS `.dmg`, an experimental debug APK, `guardian.ts`,
  `SHA256SUMS` and an optional minisign signature, then a landing redeploy).
- `misc/landing/fetch_downloads.py`: the Render build copies the releases
  to `/downloads/`, checks every file against `SHA256SUMS`, and writes an
  index page; the landing links to it. `install.sh` downloads from there,
  says "suma" instead of "firma", and verifies a minisign signature once the
  key exists.
- `infra/render`: the landing page as the static site `hawk-landing`
  at `https://hawkeeper.xyz`, the URL in the install command, the
  installer and the release notes.
- `witness/ui`: the app screens rebuilt on the twelve commands of
  `commands.rs` (overview, machines, events, record, settings, activation),
  Spanish and English, an SVG chart with a table alternative, sheets for
  approving, releasing and event detail, and the stale, unreachable,
  identity-changed, heads-invalid, paired-elsewhere and dormant states.
- `witness/ui/preview.js` scenarios with data shaped exactly like the Rust
  structs, and `witness/tools/audit-i18n.js`, which fails on a missing or
  mismatched text key.
- Saira and JetBrains Mono (SIL OFL 1.1) as files in `witness/ui/fonts`.
- ADR-0025 and ADR-0026: a Merkle tree per batch with its root inside
  every signed head (head v2, inclusion proofs bound to the head), and an
  off-site archive of sealed batches and heads in S3 with Object Lock.
- `integrations::archive`: background uploader (SigV4 by `rusty-s3`,
  signed `Content-MD5`), enabled with `ARCHIVE_*`; never blocks decisions.
- `infra/aws` (OpenTofu) and `infra/localstack` for the demo's cloud PC.
- ADR-0027: offline by default, optional cloud features for any owner. The
  configuration becomes a chain (`version`, `prev`, signature over both):
  no rollback, no skipping, no forks; every change recorded in the main
  chain. Optional enterprise signer authorised only by the owner, remote
  configuration fetched from S3 with alerts on rollback or fork, and
  `guardian config-keygen` / `config-sign` for pipelines.
- `infra/aws` gains `target` (aws, localstack, s3) and publishes the signed
  configuration; `infra/render` deploys RustFS with Object Lock on Render.
- `docs/ENTRENAMIENTO-GRANITE.md`: how to build or fine-tune the classifier,
  with the reading list.

- ADR-0028: hosts are selected by more than their IP. The Core reads the
  peer's MAC in its neighbour table and contains it next to the IP (OpenWrt
  `ether_addr` set, MikroTik mangle to the address list); the daemon reports
  a HWID (OS machine id hashed with the Core identity). Quarantine is sticky
  by identity, MAC and HWID; conflicting identifiers raise alerts.
- ADR-0029: the daemon obeys one Core (build-time pin, environment, or a
  `core.pin` written when the owner approves it).
- ADR-0030: the Core's transport identity is created at first boot, its
  head keys (Ed25519 and ML-DSA-65) when the wizard activates it, covered by
  the owner's pairing signature (`guardian.pair.v2`).
- Witness: typed Core address when discovery cannot reach, host filter by
  name/IP/MAC/HWID/fingerprint, Approve and Release, Android safe areas.
- `eval` `stress` binary: load and abuse run against a live Core.
- ADR-0005/0022 detection catalogue: rules as data (JSON: id, severity,
  MITRE technique, tools, field, patterns, exceptions, fire/deny examples)
  with a loader and an embedded 10-rule catalogue (`detect/rules/default.json`,
  attributed to Falco in `detect/NOTICE`) plus a code rule for writes outside
  the workspace; the Core now runs the catalogue. A test walks every example.
- ADR-0021 enrolment, merged with ADR-0029: the owner approves each host
  from the app with a signature over Core, daemon key, HWID and time
  (`Request::ApproveHost { approval }`); the Core denies `decide` and proxy
  records from hosts that are not approved with the HWID they report.
- ADR-0021 heartbeat and dead man's switch: the Core challenges each enrolled
  host (`HeartbeatChallenge`) and verifies the signed `Heartbeat` (nonce,
  monotonic counter, digest of observed calls, boot measurement); a host
  silent for 15 s, or whose boot measurement changed, is quarantined. The
  daemon reads the PCRs on Linux (`host-daemon/src/tpm.rs`); sealing the key
  in the TPM and a TPM-signed quote are the hardware follow-up.
- ADR-0010 evaluation set: task format, validation, metrics (safety, false
  positives, usefulness, evasion detection, latency) and a runner in `eval/`
  with 15 legitimate and 15 harmful tasks (several by prompt injection).
- ADR-0022 `ask`: when the policy returns `Ask`, the Core holds the decision
  for up to 60 s; the app lists `PendingAsks` and answers with a signed
  `Answer { id, allow, signature }` (allow/deny buttons). No answer denies,
  and the answer is recorded. The dashboard shows pending asks and a notice
  for new alerts.
- ADR-0007 opening: the app opens the sealed record with a signed
  `Request::OpenRecord { from_seq, to_seq, timestamp_ms, signature }` (60 s
  max age, paired witness only); the Core records a sealed `LogOpened` and
  returns the events still sealed. The app verifies the chain against the
  last signed head and decrypts each payload with `epoch.key` in a "Record"
  view.
- ADR-0018 release: the owner lifts a quarantine from the app with a P-256
  signature over the host address and a timestamp (rejected after 60 s);
  the Core calls `Firewall::release`, records a sealed `Released` event and
  publishes it. Only the paired witness may send it.
- ADR-0004 implemented: the OpenAI-compatible LLM proxy runs in the host
  daemon on loopback, forwards to Ollama with SSE streaming, extracts the
  model's tool calls (with ids) from streaming and non-streaming responses,
  and relays a `ProxyRecord` to the Core. The Core records it sealed and
  cross-checks the tool calls against the hook's `decide` (`call_id`) in a
  5 s window: a proposal without a `decide` is a critical evasion alert that
  quarantines the host; a `decide` without a proposal is a high alert.
- ADR-0023 and ADR-0024: QUIC with mutual TLS between all our edges (the
  Core has no HTTP endpoint) and discovery with an activation wizard.
- Pairing binds the app's device identity; the Core serves its record and
  configuration only to that identity; owner-signed configuration applied
  live (name, firewall).
- Host registry by fingerprint and the identify signal: the app asks a
  monitored machine to show a notice on its screen.
- Host daemon over QUIC with its own identity, Core discovery and pinning.
- Owner app: activation wizard, hosts with Identify, Core identity in the
  header instead of an address field.
- `guardian probe` and a QUIC health check for Docker; `CLAUDE.md` with the
  ADR process and the hard rules.

- ADR-0001 to ADR-0011: scope, topology, interception, detection, hash
  chain, two-key access, recovery, agent under test, evaluation, licences.
- Repository structure, standards and agent instructions adapted from
  Nepheral.
- Tentative project name: HAWK (Hardware Autonomous Watcher & Keeper).
- ADR-0012 to ADR-0014: Rust workspace, Tauri 2 front end (desktop and APK
  from one crate), own implementation on established primitives.
- Cargo workspace: `guardian-core` (event encoding and hash chain with
  tests), `detect`, `llm-proxy`, `guardian` (`/health`, fail-closed
  `/decide`), `eval`, `witness` (Tauri 2).
- Clippy lints with warnings as errors, `justfile`, `cargo deny`
  configuration.
- ADR-0015 to ADR-0017: three edges (host daemon, Core, mobile app), hyper
  on tokio instead of axum with our own framed protocol between edges, and
  pairing with passkeys (supersedes ADR-0008 for recovery).
- ADR-0018 and ADR-0019: network containment through the firewall, and
  hybrid Ed25519 + ML-DSA signatures on heads. ADR-0006 now states why a
  chain sealed on the infected machine proves nothing.
- ADR-0020: `integrations` crate with firewall adapters (OpenWrt,
  MikroTik, Cisco) and event sinks (Kafka, webhook, CEF syslog); OpenWrt
  added to ADR-0018.
- Roadmap with full scope in parallel streams.
- ADR-0021 (daemon attestation, challenge-response heartbeat, dead man's
  switch, eBPF sensors) and ADR-0022 (severities and defaults: fail closed
  on failure, not on silence); `docs/ACTION-TREE.md`.
- Pairing helpers shared in `guardian-core`; Core endpoints `/identity`,
  `/pair`, `/status`, `/heads`, `/events`; containment of the request's TCP
  peer on a critical finding and publishing to the sinks.
- Witness app connected to the Core: pairing, dashboard and verification of
  signed heads against the pinned identity.
- First vertical slice: OpenCode plugin (`agent-hook/guardian.ts`) ->
  host daemon relay -> Core `/decide` with the rule engine and policy;
  denies when the daemon or the Core is unreachable.
- `host-daemon` and `edge-net` crates; Guardian and daemon on hyper.
- Docker: development container, Guardian image limited to 2 GB, smoke
  test, optional Ollama service on the GPU.

### Changed

- `witness/icons` are the HAWK mark on a dark rounded square (they were
  copied from Nepheral).
- `witness/README.md` describes the QUIC link (it still described HTTP).
