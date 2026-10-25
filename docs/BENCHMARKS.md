# Benchmarks: what one decision costs

Measured, not estimated. Everything here is produced by
[`training/bench_latency.py`](../training/bench_latency.py), which measures
each path automatically and writes `training/out/bench-*.json`, and by
[`detect/examples/latency.rs`](../detect/examples/latency.rs) for the Core's
own path. Re-run it instead of trusting this page:

```sh
python training/bench_latency.py --adapter training/out/bench-final/adapter
python training/bench_latency.py --device cpu --skip-rules --skip-api
python training/bench_latency.py --daemon            # end to end, needs a running daemon
```

## Latency per decision

Run of 2026-10-25. Workload: 8 normalised tool calls, mostly ordinary work
with a few dangerous ones.

| Path | p50 | p95 | Samples | Where |
|---|---|---|---|---|
| Rules only (Core, Rust, release) | **700 ns** | 1.1 µs | 240 000 | local, in process |
| Rules + familiarity stage (ADR-0036) | **900 ns** | 1.3 µs | 240 000 | local, in process |
| Granite 4 350M + our LoRA, unquantised | **100 – 200 ms** | | 64 | local, GPU and CPU |
| A model API, **network floor only** | **0.54 – 1.34 s** | up to 1.9 s | 8 per run | api.deepseek.com |

The rules are free: a decision costs less than a microsecond and never leaves
the process that records it. The local model costs five to six orders of
magnitude more, and a remote model costs more still, before it has thought
about anything.

## Almost every call is answered by the rules

The model's cost is the wrong number to look at on its own, because almost
nothing reaches it. A call needs the model only when it is **unfamiliar**: a
rule deciding it, or it being familiar with no rule firing, both end in the
sub-microsecond path.

Measured over the held-out split, 1383 real calls:

| Resolved by | Calls | Share | Cost |
|---|---|---|---|
| A rule decides | 8 | 0.6% | < 1 µs |
| Familiar, no rule fired → allow | 1373 | 99.3% | < 1 µs |
| **Unfamiliar → the model** | **2** | **0.1%** | 100 – 200 ms |

**99.9% of calls are answered in under a microsecond**, and the model is
consulted on roughly one call in a thousand. Spread over this traffic, the
model adds about 0.2 ms to the average decision, and nothing at all to the
999 calls that never touch it. A model API, by contrast, is paid on whichever
calls are sent to it and cannot be skipped by a gate.

Reproduce the share with the rules and the familiarity artifact:

```sh
python training/show_decisions.py        # per-call view of the same two stages
```

## What each number is, and is not

- **Rules and familiarity** are the real Core path, built in release. This is
  what HAWK decides with today.
- **Granite** is our fine-tuned adapter answering one severity per call,
  through PyTorch in **fp32, not quantised**. The GGUF Q4/Q8 build that
  ADR-0037 ships should be materially faster; this is the pessimistic end.
- **The API figure is only the network floor**: connect, TLS handshake and
  first byte of an *unauthenticated* request. No key, no inference, and no
  tool call sent to anyone. A real decision over an API is this plus the
  model's own time plus queueing. It also varies a lot with the network: two
  runs an hour apart gave 0.54 s and 1.34 s.
- **The hardware is not the target.** These come from a Windows development
  laptop. The Core runs on Linux, which is faster for this, and the board it
  has to run on is slower than this laptop. Treat the table as orders of
  magnitude, not as the Pi's numbers.

## What it means for ADR-0037

ADR-0037 budgets **under 150 ms p95** for the model stage on a Raspberry Pi 4.
Unquantised and through PyTorch, the stage lands at 100 – 200 ms on
development hardware, so the budget is reachable but not with this path. That
does not sink the decision, it directs it:

1. The quantised GGUF through llama.cpp is the only candidate, not PyTorch.
2. The gate matters more than the model's speed. `Detector::decide_with` runs
   every stage today; the model must not run when the rules already decided.
   With the gate, the 150 ms is paid only on the calls the rules leave open.
3. If Q4 on the board still misses the budget, ADR-0037 says to quantise
   further or drop back to the familiarity stage, not to raise the budget.

## Still to measure

- **On the board**: a Raspberry Pi 4 (2 GB), Linux, release build, with the
  quantised model. These are the numbers ADR-0037's acceptance criteria are
  written against.
- **End to end**: what the agent actually waits for, from the hook through the
  daemon's loopback socket and the QUIC hop to the Core and back, driven by a
  real OpenCode session. `bench_latency.py --daemon` measures it; it needs a
  running daemon and an activated Core.
- **The quantised model's quality**, not just its speed: Q4 and Q8 against the
  same held-out split, to see what accuracy each quantisation costs.

## A note on the model's answers

The adapter measured here is the `--final` one, trained on every split, which
is the model meant to ship. It answers correctly on all eight calls of the
workload, including `nc -e /bin/sh`. **That is not evidence it generalises**:
it saw those families in training, because `--final` holds nothing out. The
honest measurement is the held-out run, and there the model still lets 100% of
the unseen `critical` families through as `low`. This is the gap ADR-0036 is
built around and that only more labelled attack data closes
(`docs/ROADMAP.md`, M10).
