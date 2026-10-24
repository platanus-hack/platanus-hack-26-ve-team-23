# guardian

The monitor. Decides on tool calls, records everything, and reports to the
phone.

- **Runs on:** Raspberry Pi, 2 GB of RAM, Linux.
- **Status:** planned. Implements ADR-0003, ADR-0004, ADR-0005, ADR-0006,
  ADR-0007.

## Parts

| Part | Responsibility |
|---|---|
| Decision API | `POST /decide` for the hook: allow, deny or ask |
| Detectors | Rules on the call and the last N calls; small classifier; optional ~350M model |
| LLM proxy | OpenAI-compatible endpoint that forwards to Ollama on the PC and records requests and responses |
| Cross-check | Matches proposed tool calls (proxy) with hook requests; mismatch raises an evasion alert |
| Hash chain | Appends encrypted event batches; signs heads and sends them to the phone |
| Opening | Hands out encrypted batches only for a valid, unexpired request signed by the owner |

## What it must never do

- Allow an action when a detector fails or times out.
- Run any model of 1.5B parameters or above.
- Store decryption keys for past epochs.
- Accept connections from the PC other than the decision and proxy
  endpoints.
