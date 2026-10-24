# HAWK: an AI control monitor the agent cannot reach

**Design snapshot, before implementation.** This document describes the
system as decided in ADR-0001 to ADR-0011. When the design changes, this
document is updated and the decision is recorded in an ADR.

## 1. Scope of the claim

HAWK guarantees, within the threat model below:

- every tool call that a coding agent runs through its hook is decided by a
  monitor that the agent does not control;
- every model request and response that passes through the proxy, every
  decision and every opening of the record is in a hash chain whose signed
  heads are held by an independent device;
- a hook that is bypassed or disabled produces an alert, because the proxy
  and the hook no longer agree.

HAWK does not guarantee:

- that the model is robust against jailbreaks or injections;
- visibility of reasoning that never becomes an action;
- prevention against an agent with root on the PC;
- that a small monitor catches every multi-step attack. The rate is measured.

## 2. Actors and trust

| Actor | Trusted? | Notes |
|---|---|---|
| Agent (OpenCode + model) | No | May be misaligned or injected; may know it is monitored |
| PC | No | Runs the agent as an unprivileged user |
| Guardian (Raspberry Pi) | Yes, for decisions and recording | Separate hardware; no inbound access for the agent except the decision and proxy endpoints |
| Phone | Yes, as witness and key holder | Owner's device; biometrics on key use |
| Model provider (local or API) | Not relevant | HAWK watches the agent, not the model |

The monitor is weaker than the agent on purpose: it is trusted because it is
small, its task is narrow, and it is measured against attacks designed to
evade it (ADR-0002, ADR-0010).

## 3. Topology

PC runs OpenCode and Ollama on an RTX 4070. The Pi runs the Guardian. Ollama
listens only towards the Pi; OpenCode's model base URL is the proxy on the
Pi. The phone receives heads and alerts (ADR-0003).

## 4. Interception

- **Hook (enforcement):** an OpenCode plugin in `tool.execute.before` sends
  each call to `POST /decide` on the Guardian and runs it only on "allow".
  Timeout means deny.
- **Proxy (recording):** OpenAI-compatible proxy on the Pi that forwards to
  Ollama and records requests and responses.
- **Cross-check:** every tool call proposed in a model response must be
  matched by a hook request, and vice versa; a mismatch is an evasion alert
  (ADR-0004).

## 5. Detection

1. Rules on the call and on the last N calls.
2. A small classifier for what rules do not settle.
3. Optionally a ~350M model for remaining ambiguous cases, if it fits and is
   fast enough on the Pi.

Decisions: allow, deny, or ask the owner on the phone (ADR-0005).

## 6. Record integrity

Events are encrypted in batches with the weekly epoch key and appended to a
hash chain over the ciphertext. Signed heads go to the phone periodically and
after every high-severity event. Verification recomputes the chain and
compares it with the heads on the phone. Destroying an epoch key erases that
week's content while the hashes keep proving it existed (ADR-0006).

## 7. Access to the record

Two keys: the owner's signing key opens (short-lived signed request,
recorded in the chain); the weekly epoch key decrypts. Personal edition:
both on one phone, non-exportable. Enterprise edition: k of n administrators
to open and to decrypt; the decryption scheme is open (ADR-0007). Owner
identity is recoverable from a BIP-39 mnemonic; epoch keys are not
(ADR-0008).

## 8. Evaluation

About 30 legitimate and 30 attack tasks run by the agent under test.
Metrics: safety, false positives, usefulness, evasion detection and latency,
for no Guardian, rules only, and rules plus classifier (ADR-0010).

## 9. Not in this design

Own blockchain or consensus; content guardrails; interpretability; public
anchoring (future option for the enterprise edition).
