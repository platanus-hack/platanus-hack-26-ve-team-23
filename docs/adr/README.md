# Architecture Decision Records

An Architecture Decision Record (ADR) captures one significant decision: the
problem it answered, the options that were weighed, what was chosen and what
it costs. The code shows what the Guardian does; the ADRs keep why.

Larger proposals that need discussion before anything is decided start as an
RFC in [`docs/rfcs`](../rfcs/README.md). An accepted RFC ends in one or more
ADRs.

## When to write one

Write an ADR when a change:

- alters the threat model or a security property;
- changes what the Guardian sees, blocks or records;
- changes the log format, the hash chain or how keys are used;
- adds, replaces or removes a core dependency or model;
- would make a future contributor ask "why was it done this way?".

## Process

1. Copy [`0000-template.md`](0000-template.md) to the next free number,
   `NNNN-short-title.md`, on a branch of its own. Status **Proposed**.
2. Open a pull request. Update the record, not the thread, when an argument
   changes the decision.
3. Merge when approved. The status becomes **Accepted**, with the date.
4. Link the implementing pull request under Implementation.

An accepted ADR is not rewritten. A changed decision gets a new ADR that
supersedes it; the old one only has its status updated.

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Proposed |
| [0002](0002-control-the-agent-not-the-model.md) | Control the agent, not the model | Proposed |
| [0003](0003-three-device-topology.md) | Three devices: untrusted PC, Guardian on a Pi, phone as witness | Proposed |
| [0004](0004-enforce-with-hook-record-with-proxy.md) | Enforce with an agent hook, record with an LLM proxy, cross-check both | Proposed |
| [0005](0005-detection-rules-then-small-classifier.md) | Detection: rules first, small classifier second, optional small LLM | Proposed |
| [0006](0006-local-hash-chain-no-blockchain.md) | A local hash chain with a phone witness; no blockchain | Proposed |
| [0007](0007-two-key-log-access-and-editions.md) | Two-key log access; personal and enterprise editions | Proposed |
| [0008](0008-owner-recovery-with-mnemonic.md) | Owner recovery with a mnemonic; weekly keys are not recoverable | Proposed |
| [0009](0009-agent-under-test-opencode-ollama.md) | Agent under test: OpenCode with Ollama on the PC | Proposed |
| [0010](0010-evaluation-before-detection.md) | Build the evaluation set before the detectors | Proposed |
| [0011](0011-dependency-licences.md) | Only permissively licensed dependencies | Proposed |

## Open questions

| ID | Question | Where it lands |
|---|---|---|
| Q21 | Can the opening key alone show the index (date, severity, rule) without decrypting the content? | ADR-0007 |
| Q22 | Which threshold scheme decrypts in the enterprise edition? | Later ADR |
