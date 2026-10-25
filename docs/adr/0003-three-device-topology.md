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

### Precedents: who executes is not who decides

Validating outside the PC follows a pattern the industry already relies on
wherever the environment that executes cannot be trusted with its own
checks:

| Precedent | What executes (may be compromised) | What decides or keeps the secret | In HAWK |
|---|---|---|---|
| Apple Secure Enclave | The application processor and its OS | A separate subsystem with its own secure boot, reached only through a mailbox; it releases keys after its own checks | The PC and the agent; the Core, reached only through fixed QUIC messages |
| Apple Private Cloud Compute | The node that serves a request | Software images that are attested and published in a transparency log, verified by the client before it sends anything | The app verifies every signed head against the identity pinned at pairing |
| TPM, Microsoft Pluton | The host OS | A chip that measures the boot and signs attestations with a key the OS cannot read | ADR-0021: the daemon key in the TPM and a boot quote (pending) |
| HSMs in banking and PKI | The applications that ask for signatures | A device that keeps the key and applies its own policy | The Core keeps the head keys; the PC never holds them |
| AWS Nitro | The customer's instance | Networking, storage and management moved to dedicated cards outside the instance's reach | The firewall decision and the record live outside the PC |
| SIEM and WORM storage | The host that writes the logs | Logs shipped off the host as they are written, kept where it cannot delete them | The sealed record on the Core; the optional S3 Object Lock archive (ADR-0026) |

The principle is older than any of them: a reference monitor must be
tamper-proof, always invoked and small enough to verify (Anderson, *Computer
Security Technology Planning Study*, 1972). In AI control, a trusted monitor
can watch an untrusted model only while the model cannot subvert it
(Greenblatt et al., *AI Control: Improving Safety Despite Intentional
Subversion*, 2023). Another device is the most direct way to meet that
condition. Three devices also separate duties: the agent acts, the Core
authorises, the owner's phone audits.

The control evaluations that followed test this setting directly:

- **Ctrl-Z** (Bhatt, Shlegeris et al., Redwood Research, arXiv 2504.10374,
  2025) is the first control evaluation in an agent environment: BashBench,
  257 multi-step system administration tasks, against an agent that tries to
  download and run malicious code. Its best protocol, resampling suspicious
  actions, cut attack success from 58% to 7% at about 5% cost to a
  well-behaved agent. It is close to HAWK's own scenario: a shell agent and
  a monitor that blocks before execution.
- **SHADE-Arena** (Anthropic, arXiv 2506.15740, 2025) measures whether an
  agent can complete a hidden harmful side task without an LLM monitor
  noticing. The best monitor reached an AUC of 0.87, and sabotage depended
  heavily on a scratchpad hidden from the monitor: a model-only monitor is
  not enough (ADR-0005).

### Where the analogy stops

- The Secure Enclave holds something the application processor needs, so
  skipping it gains nothing. The hook on the PC can be skipped by an agent
  with root. HAWK's lever is the network: the router obeys the Core, not the
  PC. A daemon that stops answering its heartbeat (ADR-0021), or tool calls
  the proxy saw and the hook never asked about (ADR-0004), end in quarantine
  (ADR-0018).
- So the guarantee has three parts: the decision and the record are out of
  the agent's reach; enforcement on the PC is cooperative and fails closed;
  enforcement on the network does not depend on the PC.
- Damage done on the PC before detection is not undone: it is cut off and
  recorded.
- Until the daemon key lives in a TPM (ADR-0021), a PC compromised with root
  can copy that key and impersonate its daemon. The Secure Enclave avoids
  this with a key fused into the chip; the TPM is our equivalent.

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
- v1.1 (2026-10-25): Precedents for validating off the host (Secure Enclave,
  Private Cloud Compute, TPM, HSM, Nitro, SIEM/WORM, the reference monitor,
  AI control) and where the analogy stops.
- v1.2 (2026-10-25): The control evaluations Ctrl-Z (Redwood) and
  SHADE-Arena (Anthropic) next to Greenblatt et al.
