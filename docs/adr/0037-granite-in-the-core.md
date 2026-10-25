# ADR-0037: Granite runs inside the Core

- **Status:** Proposed
- **Date:** 2026-10-25
- **Deciders:** Javier Hernandez, team-23 (approval pending)

## Context

ADR-0005 decided rules first, then a small classifier. The classifier stage
today is the familiarity check of ADR-0036: a program allowlist distilled from
the training corpus, embedded as data. The fine-tuned model itself (Granite 4
350M with a LoRA adapter, `training/`) runs only on the training machine; the
Core never loads it. ADR-0035's pipeline produces it, and
`docs/ENTRENAMIENTO-GRANITE.md` leaves "export to GGUF and measure on the Pi"
as the open step.

The team has decided the model ships with the product and decides inside the
Core. That needs decisions this repository has not made: which inference
runtime (ADR-0011 limits licences, ADR-0014 forbids writing primitives
ourselves), how a few hundred megabytes of weights travel, what the Core does
when the model is missing or slow (ADR-0022 is fail closed), and how the
model's answer combines with the rules without weakening them.

Measured facts this decision starts from (`training/bench_latency.py`):

| Path | p50 per decision |
|---|---|
| Rules only, Core in release | ~700 ns |
| Rules + familiarity, Core in release | ~900 ns |
| Our Granite 350M + LoRA, unquantised, development hardware | 100 – 200 ms |
| A cloud model API, network floor alone (TLS + first byte, no inference) | 0.54 – 1.34 s |

The full table and its caveats are in [`docs/BENCHMARKS.md`](../BENCHMARKS.md).

The rules are effectively free, and a remote model costs half a second before
it thinks. Between them sits the local model, which is what this ADR adds.

Those figures come from a Windows development laptop and are indicative only:
the Core's platform is Linux, which is faster for this work, and the board it
has to run on is slower than the laptop. The numbers that decide this ADR are
the ones from the acceptance criteria below, measured on Linux and on the
board itself.

## Options considered

### Option 1: keep the model outside the Core (today)

- Benefits: nothing new to ship; the Core stays a small, pure-Rust binary that
  cross-compiles for aarch64 with `cargo-zigbuild`.
- Drawbacks: the trained model never decides; only its distilled allowlist
  does. The ambiguous calls ADR-0005 wanted it for are still unresolved.

### Option 2: the Core asks a local model server (Ollama, llama-server)

- Benefits: no inference code in our binary.
- Drawbacks: a second process to install, supervise and version on the Pi; the
  Core would depend on a loopback HTTP service, which contradicts the hard rule
  that the Core has no HTTP surface and keeps its dependencies downwards.

### Option 3: the Core loads the model and runs it in-process

Quantized GGUF weights loaded by an inference library linked into the Core.

- Benefits: one binary, one lifecycle, offline, no IPC; the decision never
  leaves the process that records it.
- Drawbacks: a substantial new dependency; memory and latency on a 2 GB board;
  weights far larger than anything else we ship.

## Decision

Option 3, with the constraints below. The model is part of the Core, and the
Core is still useful without it.

### Key points

- **Runtime: llama.cpp, through its Rust bindings (`llama-cpp-2`, MIT).**
  ADR-0014 forbids writing an inference engine ourselves. llama.cpp is the
  reference implementation for quantized GGUF on small ARM boards: it is what
  the quantisations in `docs/ENTRENAMIENTO-GRANITE.md` are produced for, it
  has the NEON kernels a Raspberry Pi needs, and it supports the Granite
  architecture upstream rather than depending on a port of it.
  **The cost, accepted here:** it is C++, so the release build gains a C++
  cross-toolchain for aarch64 and x86_64 next to `cargo-zigbuild` (ADR-0032),
  and the Core is no longer a pure-Rust binary. A pure-Rust runtime
  (`candle`, Apache-2.0) was considered and rejected for this: it would keep
  the build simple but put us one architecture port away from not being able
  to load our own model.
- **The weights are a release asset, not a file in git history.** Granite 4
  350M quantized is 120 MB (Q4) to 250 MB (Q8) per variant: committing them
  would weigh on every clone of this repository for ever, and git history
  cannot be pruned after the fact. The repository carries what reproduces and
  verifies them, which is the part that matters: the LoRA adapter recipe
  (`training/`), the export and quantisation script, and **the SHA-256 of the
  exact file the Core accepts**, embedded in the binary. The weights ship as
  a `hawk-model-<version>-<quant>.gguf` asset next to the Core archive, listed
  in `SHA256SUMS` like everything else (ADR-0032), and `install.sh` places
  them in the Core's data directory. The Core refuses to load a file whose
  digest does not match (fail closed), so an attacker swapping the model on
  disk cannot change decisions.
- **The model judges only what is unfamiliar, and almost nothing is.** The
  gate is not "run the model when no rule fired": no rule firing is the
  ordinary case, so that would pay the model's cost on nearly every call.
  A call is resolved without the model when a rule decides it, **or** when it
  is familiar and no rule fired. Only the unfamiliar remainder reaches the
  model. Measured over the held-out split (1383 calls): 0.6% decided by
  rules, 99.3% familiar and allowed, **0.1% left for the model** — two calls.
  The model's latency is therefore paid on roughly one call in a thousand,
  while 99.9% are answered in under a microsecond.
- **The model may escalate a rule, never clear one.** It produces a `Finding`
  like any other stage and ADR-0022 still takes the highest severity, so it
  can raise a call the rules did not catch and can never lower or clear a
  rule's finding. The one thing it *may* resolve downwards is the familiarity
  stage's own "unfamiliar" default: that default exists precisely because no
  model had been consulted, so when the model is enabled its answer replaces
  it for those calls. A finding from a real rule is never touched. This
  follows ADR-0036's measurement: the model recognises legitimate traffic well
  and misses attack families it never saw, so its silence is not evidence of
  safety where a rule has spoken.
- **Fail closed, at the right moment.** If the stage is switched on and the
  model is missing, fails its digest, or fails to load, the Core **refuses to
  start** and says why: a Core that silently runs without the stage its owner
  enabled would be reporting a protection it is not giving. Once running, a
  per-call timeout (`MODEL_TIMEOUT_MS`, default 150 ms) or an inference error
  is an error, and errors deny (ADR-0022). Silence with no finding stays an
  allow.
- **Opt-in until measured on the hardware.** The stage stays behind the same
  switch as ADR-0036 until the acceptance criteria below are met on a real
  Raspberry Pi 4; it is not enabled by default on the strength of numbers from
  a laptop GPU.
- **The size ceiling of ADR-0005 holds:** under 1.5B parameters, and the
  resident set must leave the rest of the Core room on a 2 GB board.

### Acceptance criteria

Measured on a Raspberry Pi 4 (2 GB) with `training/bench_latency.py` and the
Core in release, before this stage is enabled by default:

| What | Budget |
|---|---|
| Added latency, p95, per call that reaches the stage | under 150 ms |
| Added latency, p95, on a call the rules already decided | zero: the gate skips the stage |
| End to end, what the agent waits (hook to daemon to Core and back) | measured with OpenCode, reported next to the above |
| Resident memory of the Core with the model loaded | under 1.2 GB |
| False alarms on legitimate calls, held out | no worse than the familiarity stage alone |
| Decisions on the rules' own attack examples | unchanged (the model cannot clear them) |

If the latency budget cannot be met at Q4, the answer is a smaller quantisation
or dropping back to Option 1, not raising the budget: a monitor that makes the
agent wait is a monitor people switch off.

Unquantised, through PyTorch, the stage lands at 100 – 200 ms on development
hardware. The budget is reachable, but only on the quantised GGUF path and
only with the gate: those are part of the implementation, not optimisations
for later.

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| `llama-cpp-2` (Rust bindings) | current | MIT |
| llama.cpp (vendored by the bindings) | current | MIT |
| IBM Granite 4 (about 350M), fine-tuned by us | current | Apache-2.0 |

All permitted by ADR-0011. The LoRA adapter and the merged weights inherit the
base model's Apache-2.0 licence, as ADR-0035 already records.

## Consequences

### Positive

- The trained model decides inside the Core, offline, with no cloud round-trip
  (~540 ms saved per ambiguous call) and without the tool call leaving the
  machine.
- One binary and one lifecycle; the weights are verified against a digest the
  binary carries.

### Tradeoffs

- The Core's binary gains an inference stack, and its releases gain a large
  asset. Clone size stays unchanged, but downloads do not.
- The release pipeline gains a C++ cross-toolchain and the Core stops being a
  pure-Rust binary, so a build failure can now come from llama.cpp rather than
  from our code. `just check` and the Docker build have to cover it.
- Memory and latency on the Pi become a real constraint, measured rather than
  assumed; the acceptance criteria may send us back to Option 1.
- The weights are not in git, so reproducing an old decision needs the release
  asset, not just a checkout. The digest in the binary and `SHA256SUMS` make
  that auditable.

## Implementation

### Where it lives

- `detect/src/model.rs`: the stage, behind the same switch as ADR-0036.
- `detect/src/lib.rs`: the gate. `Detector::decide_with` runs every stage
  today and lets the policy take the highest severity, which is right while
  every stage costs nanoseconds. A stage that costs ~10^8 times that cannot
  run unconditionally, so the detector has to short-circuit: rules and
  familiarity first, and the model only for the calls they leave unfamiliar.
  The latency budget below assumes this gate exists.
- `detect/model/digest.txt` (or a constant): the accepted SHA-256.
- `training/export_gguf.py`: merge the adapter, convert and quantise.
- `.github/workflows/release.yml`: publish the GGUF asset and its checksum.
- `misc/landing/install.sh`: place the model in the Core's data directory.

### Next steps

1. Export and quantise the current adapter; record its digest.
2. Build the stage against `llama-cpp-2` and verify it loads the quantised
   Granite 4 350M, first on Linux x86_64, then cross-built for aarch64.
3. Measure on the Pi against the acceptance criteria; record the table in
   `docs/ENTRENAMIENTO-GRANITE.md`.
4. Only then consider enabling it by default.

## Related decisions

- ADR-0005 (stages and the size ceiling), ADR-0011 (licences), ADR-0014 (no
  home-made primitives), ADR-0022 (fail closed), ADR-0032 (releases),
  ADR-0035 (training data), ADR-0036 (familiarity default-deny, which this
  stage sits beside and does not replace).

## History

- v1.0 (2026-10-25): Initial proposal.
- v1.1 (2026-10-25): Runtime decided as llama.cpp through `llama-cpp-2`
  instead of `candle` (team): the mini model has to run on the board, and
  llama.cpp is what its quantisations target. The C++ cross-toolchain in the
  release build is accepted as the cost.
