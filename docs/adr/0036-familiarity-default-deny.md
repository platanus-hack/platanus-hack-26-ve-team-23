# ADR-0036: Familiarity default-deny for the classifier stage

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** team-23 (approval pending)

## Context

The classifier (ADR-0005) is the second stage: it decides the calls no rule
covered. The trained model (`training/`, ADR-0035) recognises legitimate
calls very well (near-zero false alarms on held-out legitimate traffic) but
does not recognise novel dangerous calls, because the only dangerous examples
are the handful in the rule catalogue and the split is by family, so the test
always holds out families the model never saw. A classifier that predicts a
severity therefore lets unseen attacks through as `low`.

This matters now for the demo and, after it, for any honest use of the stage:
a monitor that silently allows what it has not seen is not fail-closed
(ADR-0022). The model's strength is recognising the legitimate, not the
malicious, so the stage should lean on that.

## Options considered

### Option 1: the classifier predicts a severity, used directly

- Benefits: one number, simple.
- Drawbacks: the model has almost no dangerous examples; it answers `low` to
  unseen attacks. Measured miss rate 100% on the held-out `critical` families.

### Option 2: familiarity default-deny

The classifier answers one question — "is this call like the legitimate
traffic the model was trained on?" An unfamiliar call is never allowed on the
classifier's word: writing or network gets denied, reading gets asked. A
familiar call produces no finding, so the rules and the rest of the policy
decide as before.

- Benefits: fail-closed; plays to the model's actual strength; no dependence
  on dangerous training data; legible in the demo ("the agent tried something
  we have never seen that writes to disk → blocked").
- Drawbacks: false alarms on legitimate-but-novel calls; the breadth of
  "familiar" depends entirely on the training corpus.

## Decision

Option 2. The classifier stage is a **familiarity check**, not a severity
predictor, for the demo and until there is dangerous training data broad
enough to measure a severity model (ADR-0035).

### Key points

- **Rules first, unchanged.** The stage adds findings only; the existing
  policy (ADR-0022) still lets the highest severity decide, so a rule's
  `critical` always wins over the stage.
- **Unfamiliar is never allowed silently.** The per-tool severity of an
  unfamiliar call is data (`detect/model/familiarity.json`): `bash`, `write`
  and `edit` are `high` (deny), `read` and `webfetch` are `medium` (ask).
  The owner's thresholds (ADR-0033) still apply on top.
- **The shipped demo model is not Granite in the Core.** Running a GGUF model
  inside the Core is unbuilt and would add a runtime (a separate ADR). For the
  demo the stage embeds a compact familiarity artifact distilled from the
  training corpus, the same way the rule catalogue is embedded
  (`include_str!`). Granite fine-tuning stays on the training side; running it
  in the Core is the staged next step.
- **The artifact is built, never hand-written:** `training/export_familiarity.py`
  reads the `low` examples of the prepared dataset and writes the program
  allowlist. Its breadth follows the corpus: a broad corpus (tldr) makes the
  stage conservative (it fires only on genuinely obscure programs, and the
  rules carry the demo); a narrow corpus of real lab traces makes it the sharp
  "unknown command blocked" demo.

## Dependencies and licences

None. The artifact is data embedded in the existing binary; no new crate, no
model runtime in the Core.

| Dependency | Version | Licence |
|---|---|---|
| None | | |

## Consequences

### Positive

- The classifier stage is fail-closed and demo-ready without dangerous
  training data.
- The model carried by the install is a plain data file, versioned and
  reviewable like the rules.

### Tradeoffs

- "Familiar" is only as good as the corpus; a broad corpus makes the stage
  rarely fire on its own. Revisit once lab traces (narrow, high-signal) or a
  measured severity model exist.
- Running Granite in the Core (a GGUF runtime, memory and latency on the Pi)
  is deferred to its own ADR; this decision does not build it.

## Implementation

### Where it lives

- `training/export_familiarity.py`: distils `detect/model/familiarity.json`
  from the prepared dataset.
- `detect/model/familiarity.json`: the embedded artifact (program allowlist +
  per-tool unfamiliar severity).
- `detect/src/classifier.rs`: the familiarity stage; opt-in, embedded at
  compile time. Added to the demo Core's detector, not yet to `builtin()` for
  every build.

### Next steps

1. Enable the stage in the demo Core and show it with the scripted scenarios.
2. Label `training/out/tldr-review.jsonl` and real lab traces to tune breadth.
3. Separate ADR if a model runtime is ever to run inside the Core.

## Related decisions

- ADR-0005 (detection stages), ADR-0022 (fail-closed policy), ADR-0033
  (owner thresholds), ADR-0035 (training data).

## References

- `docs/ENTRENAMIENTO-GRANITE.md`; `training/README.md`.

## History

- v1.0 (2026-10-24): Initial proposal.
