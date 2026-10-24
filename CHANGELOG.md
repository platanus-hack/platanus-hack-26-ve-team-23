# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Every entry is written when the change is merged, under `Unreleased`.

## [Unreleased]

### Added

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
- `host-daemon` and `edge-net` crates; Guardian and daemon on hyper.
- Docker: development container, Guardian image limited to 2 GB, smoke
  test, optional Ollama service on the GPU.
