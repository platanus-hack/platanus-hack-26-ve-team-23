# detect

Decides on tool calls: rules, sequence rules, then the classifier
(ADR-0005). Own implementation; the classifier is a linear model over hashed
features, trained by `eval` (ADR-0014).

- **Status:** skeleton. `Detector::decide` denies everything until the rules
  are written against the evaluation set (ADR-0010).

## What it must never do

- Allow by default, or allow when a stage fails.
- Load a model of 1.5B parameters or above.

## Tests

`cargo test -p detect`. Every rule gets one case that must fire and one that
must not.
