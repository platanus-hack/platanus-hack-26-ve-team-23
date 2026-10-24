# Roadmap

Full scope. Deadline assumed 2026-10-25 10:00 (to be confirmed). Patterns and
code are taken from Nepheral where it already solved the problem (ADR-0014).
What is missing and why: `PENDIENTES.md`.

| # | Milestone | ADRs | State |
|---|---|---|---|
| M0 | Decisions recorded | 0001 to 0024 | Written; all Proposed, team approval pending |
| M1 | Workspace skeleton | 0012, 0013 | Done (clippy as errors, tests, `just`, `cargo deny`; Docker files untested) |
| M2 | Agent under test | 0009 | Pending: OpenCode + Ollama on the 4070 |
| M3 | Evaluation set | 0010 | Pending, for the team |
| M4 | Hook, daemon, decision | 0004, 0015, 0022 | Done: plugin -> daemon (loopback) -> Core over QUIC; engine and policy; concrete rules pending (team) |
| M4b | QUIC between edges, discovery | 0023, 0024 | Done: mutual TLS identities, mDNS, pinning; end-to-end run verified |
| M5 | Proxy and cross-check | 0004 | Pending |
| M6 | Network containment | 0018, 0020 | Done: a critical finding quarantines the QUIC peer (dry run, MikroTik, OpenWrt); release pending |
| M6b | Event sinks | 0020 | Done: Kafka and webhook behind a bounded queue |
| M7b | Merkle and off-site archive | 0025, 0026 | Built: Merkle root in head v2, inclusion proofs, S3 uploader, OpenTofu module, LocalStack and Render blueprint (infrastructure untested here) |
| M7c | Configuration chain and optional remote configuration | 0027 | Built: chained configurations without rollback, enterprise signer, S3 polling with alerts, signing CLI |
| M7 | Signed heads and record | 0006, 0007, 0019 | Done: sealed to the epoch key, chained, persisted, hybrid heads verified by the app |
| M8 | Owner app (phone) | 0013, 0024 | Done: activation wizard, dashboard, hosts with Identify; opening the record, `ask` answers and Android specifics pending |
| M9 | Pairing | 0017 | Done with a P-256 owner key bound to the Core, nonce and app identity; passkeys pending |
| M9b | Host identity and identify | 0015, 0021 | Done: fingerprint per host and identify notice; heartbeat, attestation and enrolment pending (team) |
| M10 | Classifier | 0005 | Pending |
| M11 | Results and demo | 0010 | Pending |

## After the hackathon

Cisco adapter, enterprise edition (k of n), SLH-DSA daily checkpoints,
optional public anchoring, Granite fine-tuning (needs a data-licence ADR).
