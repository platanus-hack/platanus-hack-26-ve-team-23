# Roadmap

Full scope. Deadline assumed 2026-10-25 10:00 (to be confirmed). Patterns and
code are taken from Nepheral where it already solved the problem (ADR-0014).
What is missing and why: `PENDIENTES.md`.

| # | Milestone | ADRs | State |
|---|---|---|---|
| M0 | Decisions recorded | 0001 to 0030 | Written; all Proposed (0008 superseded by 0017), team approval pending |
| M1 | Workspace skeleton | 0012, 0013 | Done (clippy as errors, tests, `just`, `cargo deny`; Docker files untested) |
| M2 | Agent under test | 0009 | Pending: OpenCode + Ollama on the 4070 |
| M3 | Evaluation set | 0010 | Done: task format, 15+15 tasks, runner and metrics in `eval/`; scale to 30/30 |
| M4 | Hook, daemon, decision | 0004, 0015, 0022 | Done: plugin -> daemon (loopback) -> Core over QUIC; engine and policy; data-driven rule catalogue with examples |
| M4b | QUIC between edges, discovery | 0023, 0024 | Done: mutual TLS identities, mDNS, pinning; end-to-end run verified |
| M5 | Proxy and cross-check | 0004 | Done: forwarding with SSE streaming and tool-call extraction in the host daemon; the Core records each `ProxyRecord` sealed and cross-checks proposals against hook `decide`s (5 s window, evasion alert + quarantine) |
| M6 | Network containment | 0018, 0020 | Done: a critical finding quarantines the QUIC peer (dry run, MikroTik, OpenWrt); release with the owner's signature |
| M6b | Event sinks | 0020 | Done: Kafka and webhook behind a bounded queue |
| M7b | Merkle and off-site archive | 0025, 0026 | Built: Merkle root in head v2, inclusion proofs, S3 uploader, OpenTofu module, LocalStack and Render blueprint (infrastructure untested here) |
| M7c | Configuration chain and optional remote configuration | 0027 | Built: chained configurations without rollback, enterprise signer, S3 polling with alerts, signing CLI |
| M7 | Signed heads and record | 0006, 0007, 0019 | Done: sealed to the epoch key, chained, persisted, hybrid heads verified by the app |
| M8 | Owner app (phone) | 0013, 0024, 0031 | Done: activation wizard, five screens (overview, machines, events, record, settings), Identify, Approve and Release, opening the sealed record, answering `ask` with alerts, Spanish and English, light and dark; reviewed in a browser against a mock shaped like the Rust structs; not yet run on a device; Android specifics pending |
| M9 | Pairing | 0017 | Done with a P-256 owner key bound to the Core, nonce and app identity; passkeys pending |
| M9b | Host identity and identify | 0015, 0021 | Done: fingerprint per host, identify notice, owner enrolment, heartbeat and dead man's switch; TPM key and boot quote pending (hardware) |
| M10 | Classifier | 0005 | Pending |
| M11 | Results and demo | 0010 | Pending: needs M2, a real `eval` run against the Core, the demo router and the Pi |
| M12 | Repository clean-up | – | In progress: documentation synced with the code |
| M13 | Landing page and app redesign | 0013, 0031 | Done in the browser preview: new `witness/ui`, HAWK icons, landing in `misc/landing`; pending the Tauri build on device, publishing the landing and a release for `install.sh` |
| M14 | CI, releases and downloads | 0032 | Built: CI and release workflows, downloads on the landing; pending the first CI run, the Render token and deploy hook, the first tag and the minisign key |

Critical path for the demo: M2, then M11 (router, Pi, `eval` metrics,
recorded-session fallback). M10, passkeys, the TPM key, the S3 archive and
remote configuration are not in the demo script and can wait.

## After the hackathon

Cisco adapter, enterprise edition (k of n), SLH-DSA daily checkpoints,
optional public anchoring, Granite fine-tuning (needs a data-licence ADR).
