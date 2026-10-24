# ADR-0003: Three devices: untrusted PC, Guardian on a Pi, phone as witness

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

A monitor that runs on the same machine as the agent can be disabled,
bypassed or have its logs edited by that agent. ADR-0002 assumes the PC that
runs the agent is untrusted. We have three devices available: a PC with an
RTX 4070 (12 GB of VRAM), a Raspberry Pi with 2 GB of RAM running Linux, and
the owner's phone.

## Options considered

### Option 1: everything on the PC

- Benefits: the most compute for the monitor; one machine to set up.
- Drawbacks: the agent shares the host with its monitor and its log; this
  contradicts the threat model.

### Option 2: agent and monitor on the Pi

- Benefits: a single small device.
- Drawbacks: 2 GB cannot hold a model that uses tools reliably, plus the
  agent, plus the monitor; and the agent would again share the host.

### Option 3: PC runs the agent, Pi runs the Guardian, phone witnesses

- Benefits: the separation is physical and visible in the demo; each device
  does what its hardware allows.
- Drawbacks: three devices to configure; network latency between PC and Pi
  on every tool call.

## Decision

```
PC (untrusted host)                 Raspberry Pi (Guardian)            Phone
OpenCode --hook: may I run X?-----> policy: rules + classifier
   |                                hash chain  ---signed head------> witness
   +--LLM requests to Pi proxy----> proxy logs prompts and tool calls  two keys
Ollama (RTX 4070) <---forwarded---- forwards to Ollama on the PC       alerts
```

- **PC:** runs OpenCode and Ollama. Treated as untrusted.
- **Raspberry Pi:** runs the Guardian: the policy and detectors (ADR-0005),
  the LLM proxy (ADR-0004) and the hash chain (ADR-0006). Nothing that
  decides or records runs on the PC.
- **Phone:** receives signed chain heads and alerts, and holds the keys that
  open the log (ADR-0007).

### Key points

- **The classifier stays on the Pi** even though the GPU is faster. A
  monitor on the PC is within the agent's reach.
- **Network:** Ollama listens only on the interface towards the Pi, and the
  PC firewall accepts connections to it only from the Pi. OpenCode runs as
  an unprivileged user that cannot change the firewall.
- **Fail closed:** if the Pi does not answer, the hook denies the action.

## Dependencies and licences

None.

## Consequences

### Positive

- The thesis of the project (the monitor is out of the agent's reach) can
  be seen on the table during the demo.

### Tradeoffs

- Every tool call waits for a round trip to the Pi; this latency is measured
  in ADR-0010.
- A root compromise of the PC can change the firewall and talk to Ollama
  directly; the cross-check in ADR-0004 detects that the proxy was skipped.

## Implementation

### Next steps

1. Fix IP addresses and firewall rules for the demo network.
2. Measure the round-trip latency of a hook call to the Pi.

## Related decisions

- ADR-0002: threat model.
- ADR-0004, ADR-0005, ADR-0006, ADR-0007.

## History

- v1.0 (2026-10-24): Initial decision.
