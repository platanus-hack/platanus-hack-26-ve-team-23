# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Every entry is written when the change is merged, under `Unreleased`.

## [Unreleased]

### Added

- ADR-0005/0022 detection catalogue: rules as data (JSON: id, severity,
  MITRE technique, tools, field, patterns, exceptions, fire/deny examples)
  with a loader and an embedded 10-rule catalogue (`detect/rules/default.json`,
  attributed to Falco in `detect/NOTICE`) plus a code rule for writes outside
  the workspace; the Core now runs the catalogue. A test walks every example.
- ADR-0021 enrolment: the Core stores approved host identities
  (`approved.json`), denies `decide` from unenrolled hosts, and the app shows
  pending hosts with an "Approve" button (owner-signed `Request::ApproveHost`).
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
