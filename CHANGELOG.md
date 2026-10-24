# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Every entry is written when the change is merged, under `Unreleased`.

## [Unreleased]

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
