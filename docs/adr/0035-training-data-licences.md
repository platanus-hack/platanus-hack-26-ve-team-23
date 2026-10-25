# ADR-0035: Which data may train the classifier

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23 (approval pending)

## Context

The second detection stage (ADR-0005) is a classifier trained on labelled
tool calls (`docs/ENTRENAMIENTO-GRANITE.md`). ADR-0011 decides which code and
model licences are allowed; it says nothing about training data, and data
carries its own terms: share-alike licences can reach the trained weights,
some benchmarks ask not to train on them, some model providers forbid using
their outputs to train other models.

## Options considered

### Option 1: train on whatever public data helps

- Drawbacks: unknown obligations on the weights; contaminated measurements
  when a benchmark's test split ends up in training.

### Option 2: only our own data

- Benefits: no third-party terms.
- Drawbacks: few examples at the start.

### Option 3: our own data first, third-party data only with a recorded licence that allows training

## Decision

Option 3.

### Key points

- **Allowed without further review:** the evaluation set (ADR-0010) and the
  `fire`/`deny` examples of the rule catalogue (`detect/rules`), both written
  by the team in this repository; traces of our own agent runs in the lab
  (`training/data`), which contain no third-party content and no real
  secrets.
- **Allowed with a recorded check:** labels produced by a model whose terms
  allow using its outputs to train another model (Qwen and Granite are
  Apache-2.0; each API provider's terms are checked and recorded before use);
  third-party benchmarks whose licence allows training, never their test
  split.
- **Reference only, never training text:** CC-BY-SA material (for example
  OWASP), papers (each with its own licence), MITRE ATT&CK and ATLAS, whose
  identifiers are used as labels and cited.
- **Every example records its `source`**, and `training/data/SOURCES.md`
  lists each source with its licence and the date it was checked. The
  pipeline refuses examples whose source is not listed.
- **Training data stays in the private repository.** The weights and the
  LoRA adapters follow the base model's licence (Granite, Apache-2.0).

## Dependencies and licences

Python, used only to train; nothing is shipped in the Core from these.

| Dependency | Version | Licence |
|---|---|---|
| PyTorch | 2.4+ | BSD-3-Clause |
| transformers, peft, trl, datasets, accelerate | current | Apache-2.0 |
| scikit-learn | 1.5+ | BSD-3-Clause |
| IBM Granite 4, about 800M parameters | current | Apache-2.0 |

## Consequences

### Positive

- The weights carry no unknown obligation; the measurement is not inflated by
  benchmark leakage.

### Tradeoffs

- Fewer examples at first; option 4 of the guide (distillation) has to check
  the labelling model's terms first.
- Revisit when a benchmark with a training-friendly licence is found.

## Implementation

### Where it lives

- `training/`: pipeline, `data/SOURCES.md`, `data/` for the JSONL files.

## Related decisions

- ADR-0005 (stages), ADR-0010 (measurement), ADR-0011 (code and model
  licences), ADR-0014 (own implementation).

## History

- v1.0 (2026-10-24): Initial proposal.
- v1.1 (2026-10-24): First third-party source, tldr-pages (CC-BY 4.0, no
  share-alike, attribution in `training/data/SOURCES.md`): its command
  examples as everyday calls; labels are ours, never copied from the rules.
