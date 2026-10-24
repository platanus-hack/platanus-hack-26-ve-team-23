# Training data sources (ADR-0035)

Every example names one of these in its `source` field; `prepare.py` refuses
any other. Add a row only after checking the licence, and write the date.

| Source | What it is | Licence | Checked |
|---|---|---|---|
| `catalogue` | `fire` and `deny` examples of `detect/rules/default.json`, written by the team | This repository | 2026-10-24 |
| `eval` | Tool calls from the evaluation set runs (ADR-0010), written by the team | This repository | 2026-10-24 |
| `trace` | Tool calls recorded from our own agent runs in the lab, labelled by the team | This repository | 2026-10-24 |
| `team` | Examples written and labelled by hand by the team | This repository | 2026-10-24 |

Not listed, so not usable yet: model-generated labels (option 4 of the
guide) until the labelling model's terms are checked, and any third-party
benchmark.
