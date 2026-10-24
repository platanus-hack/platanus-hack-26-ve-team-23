# Roadmap

Full scope, no cuts. Deadline assumed 2026-10-25 10:00 (to be confirmed).
Work runs in parallel streams; patterns and code are taken from Nepheral
(workspace, Tauri shell, Android Keystore, APK build) per ADR-0014.

| # | Milestone | ADRs | Done when |
|---|---|---|---|
| M0 | Decisions recorded | 0001 to 0020 | ADRs accepted by the team |
| M1 | Workspace skeleton | 0012, 0013 | `just check` green locally and in Docker (done locally) |
| M2 | Agent under test | 0009, 0020 | OpenCode + Ollama on the 4070, and OpenCode through OpenRouter, both via the Core proxy |
| M3 | Evaluation set | 0010 | ~30 legitimate and ~30 attack tasks with a runner that resets the workspace |
| M4 | Hook, daemon, decision | 0004, 0015 | Plugin -> daemon -> Core `/decide`; rules deny the attacks; fail closed end to end |
| M5 | Proxy and cross-check | 0004, 0016 | Proxy records streams; disabling the hook raises an evasion alert |
| M6 | Network containment | 0018 | Evasion or exfiltration puts the host in the MikroTik quarantine list; owner lifts it |
| M7 | Signed heads and witness | 0006, 0019 | Hybrid Ed25519 + ML-DSA heads verified by the witness; an edited record fails |
| M8 | Witness app | 0013 | Datadog-style dashboard on desktop and APK, from Nepheral's Tauri shell |
| M9 | Pairing and passkeys | 0017 | Core inactive until paired; opening the record with the passkey |
| M10 | Classifier | 0005 | Measured against rules only |
| M11 | Results and demo | 0010 | Metrics table; demo rehearsed per [DEMO.md](DEMO.md); backup video |

## Streams

| Stream | Milestones |
|---|---|
| Core and detection (Rust) | M4, M5, M10 |
| Agent and evaluation | M2, M3, M11 |
| Network and integrations | M6, M2 (OpenRouter) |
| Crypto and record | M7, M9 |
| App (Tauri, from Nepheral) | M8, M9 |

## After the hackathon

Cisco adapter, enterprise edition (k of n), SLH-DSA daily checkpoints,
optional public anchoring.
