# detect

Decides on tool calls: rules, sequence rules, then the classifier
(ADR-0005). Own implementation; the classifier is a linear model over hashed
features, trained by `eval` (ADR-0014).

- **Status:** the engine (`Detector`) and the policy are implemented, with a
  data-driven rule catalogue (`rules/default.json`, loaded by
  `catalogue::builtin()` and `catalogue::load_dir`) plus a code rule for
  writes outside the workspace. The catalogue has high and critical rules
  and two medium ones (force push, recursive delete) so "ask" happens. The
  policy follows the owner's thresholds (`policy::apply_with`,
  `Detector::decide_with`, ADR-0033); a critical finding always denies and
  quarantines, a high one at least asks. The classifier is not built yet.

## Rule format

One JSON object per rule: `id`, `severity` (low/medium/high/critical),
`mitre` (ATT&CK technique), `tools` (empty = every tool), `field`
(command/path/url), `patterns` (regex), `exceptions` (regex), `reason`, and
`examples` with `fire` and `deny` strings. `cargo test -p detect` walks every
example of every rule.

## What it must never do

- Allow by default, or allow when a stage fails.
- Load a model of 1.5B parameters or above.

## Tests

`cargo test -p detect`. Every rule gets one case that must fire and one that
must not.
