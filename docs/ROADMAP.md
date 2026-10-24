# Roadmap

Ordered by impact on the demo and the evaluation. Each milestone lists the
ADRs it implements.

| # | Milestone | ADRs | Done when |
|---|---|---|---|
| M0 | Decisions recorded | 0001 to 0011 | ADRs accepted by the team |
| M1 | Agent under test | 0009 | OpenCode + Ollama complete 5 tool-use tasks; VRAM and success rate recorded |
| M2 | Evaluation set | 0010 | ~30 legitimate and ~30 attack tasks with a runner that resets the workspace |
| M3 | Proxy on the Pi | 0003, 0004 | OpenCode works through the proxy; latency measured |
| M4 | Hook and decision API | 0004 | Plugin asks `/decide`, fails closed; rules deny the basic attacks |
| M5 | Hash chain and witness | 0006, 0007 | Signed heads on the phone; verifier detects an edited record |
| M6 | Cross-check | 0004 | Disabling the hook raises an evasion alert |
| M7 | Classifier | 0005 | Classifier stage measured against rules only |
| M8 | Results and demo | 0010 | Metrics table; demo rehearsed per [DEMO.md](DEMO.md) |

After the hackathon: two-key opening with biometrics on a real phone app,
mnemonic recovery, enterprise edition, optional public anchoring.
