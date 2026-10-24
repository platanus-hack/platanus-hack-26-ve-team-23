# ADR-0015: Three edges: a daemon on every host, the Core on the Pi, the mobile app

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

ADR-0003 places the agent on the PC, the Guardian on the Pi and the witness
on the phone, and ADR-0004 lets the OpenCode plugin call the Guardian
directly. The product will be used on several machines that run agents, each
with possibly more than one agent, and the hook alone only sees what the
agent chooses to route through OpenCode's tool system. Each machine needs a
component of its own that identifies it to the Core and observes what the
hook cannot.

## Options considered

### Option 1: hook talks to the Core directly (ADR-0004 as written)

- Benefits: nothing installed on the host beyond the plugin.
- Drawbacks: no host identity; one plugin per agent to secure; nothing
  watches the host outside the agent's tool calls.

### Option 2: a daemon on every host between the hook and the Core

- Benefits: one enrolled identity per machine; one place for every agent's
  hook to call; independent sensors (protected files, the plugin directory,
  process launches) that report even when the hook is bypassed.
- Drawbacks: runs on the untrusted host, so it is a sensor and a relay,
  never a decider; one more program to install.

## Decision

The system has three edges:

| Edge | Crate | Runs on | Role |
|---|---|---|---|
| Host daemon | `host-daemon` | Every machine that runs agents | Relay for hooks, sensors, host identity, heartbeat |
| Core | `guardian` | Raspberry Pi (2 GB, Linux) | Decides, records, cross-checks, delivers heads |
| Mobile app | `witness` | Phone (APK), desktop as fallback | Witness, alerts, `ask` answers, keys |

### Key points

- **The daemon never decides.** It forwards hook requests to the Core and
  returns the Core's answer; if the Core does not answer, it answers deny.
  If the daemon does not answer, the hook denies.
- **It runs as its own system user,** not the agent's, so an unprivileged
  agent cannot stop it or edit its files. A root compromise of the host is
  still out of scope (ADR-0002).
- **Sensors:** changes to protected paths (the agent's logs, shell history,
  the hook plugin directory, the daemon's own configuration) are reported to
  the Core as events, independently of the hook.
- **Heartbeat:** the daemon reports every few seconds; a silent daemon is an
  alert, like a silent hook (ADR-0004).
- **Host identity:** each daemon is enrolled with the Core by the owner and
  signs what it sends, so the Core knows which machine each event came from.
- **Hook path:** OpenCode plugin, then the local daemon on `127.0.0.1`, then
  the Core. The proxy path (ADR-0004) is unchanged.

## Dependencies and licences

None beyond ADR-0014. File watching adds a crate in a later ADR.

## Consequences

### Positive

- Several hosts and several agents per host, each attributed.
- Bypassing the hook no longer leaves the host unobserved.

### Tradeoffs

- One more component to build before the demo; the minimum for the demo is
  the relay and the heartbeat, sensors after.
- Installing a service with its own user differs per OS; Linux and Windows
  are covered first.

## Implementation

### Where it lives

- `host-daemon/`.

### Next steps

1. Relay `/decide` from the hook to the Core, fail closed.
2. Heartbeat and the Core-side alert for a silent daemon.
3. Enrolment and signed requests.
4. Sensors on protected paths.

## Related decisions

- ADR-0003: topology, extended here with one daemon per host.
- ADR-0004: the hook now calls the daemon, which calls the Core.
- ADR-0013: the mobile edge.

## History

- v1.0 (2026-10-24): Initial decision.
