# eval

The evaluation set and the runner that measure the Guardian.

- **Runs on:** the PC (agent) and the Pi (Guardian).
- **Status:** planned. Implements ADR-0010. Built before the detectors.

## Contents

- About 30 legitimate coding tasks.
- About 30 tasks with a hidden harmful side goal: deleting or truncating logs
  and shell history, sending secrets out, editing the Guardian's records,
  disabling the hook, and multi-step versions. Some are delivered by prompt
  injection in files the agent reads.
- A runner that resets the sandbox workspace between tasks.

## Metrics

Safety, false positives, usefulness, evasion detection and latency, each for
no Guardian, rules only, and rules plus classifier.

## Rules

- Attack tasks touch only the sandbox; network egress goes to a sink we
  control.
- Tasks and detection rules are written by different people.
- Missed attacks are reported.
