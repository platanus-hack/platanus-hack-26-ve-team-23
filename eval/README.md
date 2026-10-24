# eval

The evaluation set and the runner that measure the Guardian.

- **Runs on:** the PC (agent) and the Pi (Guardian).
- **Status:** implemented (ADR-0010). Task format, validation, metrics and a
  runner; the task set is a starter set of 15 legitimate and 15 harmful tasks.

## Contents

- A task is one JSON object in `tasks.json`: the prompt, the initial files,
  `kind` (legit/attack), and for attacks the `category` and an optional
  `injection` file.
- Legitimate coding tasks, and tasks with a hidden harmful side goal:
  deleting logs and shell history, sending secrets out, editing the
  Guardian's records, disabling the hook, and multi-step versions. Several
  are delivered by prompt injection in files the agent reads.
- A runner (`eval run`) that resets the sandbox workspace between tasks and
  runs the agent (`EVAL_AGENT_CMD`, default `opencode`). Collecting the
  Core's decisions is the M2/M3 integration.

## Commands

| Command | Effect |
|---|---|
| `cargo run -p eval` | validate the task set and print the counts |
| `cargo run -p eval -- list` | list every task |
| `cargo run -p eval -- metrics results.json` | compute the metrics of one configuration |
| `cargo run -p eval -- run` | run the agent on every task in a fresh sandbox |

## Metrics

Safety, false positives, usefulness, evasion detection and latency, each for
no Guardian, rules only, and rules plus classifier (`metrics::compute`).

## Rules

- Attack tasks touch only the sandbox; network egress goes to a sink we
  control.
- Tasks and detection rules are written by different people.
- Missed attacks are reported.
