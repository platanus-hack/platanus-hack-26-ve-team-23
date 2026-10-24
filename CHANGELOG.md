# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Every entry is written when the change is merged, under `Unreleased`.

## [Unreleased]

### Changed

- Documentation synced with the code: `CLAUDE.md` describes `llm-proxy` and
  `eval` as built, counts ADRs 0001 to 0030 and names the `origin` remote;
  the roadmap adds M12 (repository clean-up), M13 (landing page and app
  redesign, designs ready) and the critical path for the demo;
  `PENDIENTES.md` lists that path and the redesign after the clean-up.

### Added

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
