# ADR-0018: Network containment through the firewall (OpenWrt and MikroTik first, Cisco next)

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

Denying a tool call stops one action. It does not stop an agent that has
already started a process, opened a connection, or gained root on the host
and bypassed its hook. Everything that runs on the compromised host can be
switched off by the compromise: a kill switch inside the host, or one that
only refuses writes to an evidence store, does not stop the agent.

The network equipment between the host and the internet is outside the
host's control. Cutting the host there contains it even if the host is fully
compromised.

## Options considered

### Option 1: kill the agent process from the host daemon

- Benefits: precise.
- Drawbacks: the daemon runs on the compromised host; a root compromise
  stops it first.

### Option 2: firewall on the host (iptables, Windows Firewall)

- Benefits: no extra hardware.
- Drawbacks: same problem; root on the host removes the rule.

### Option 3: the Core drives the network firewall

- Benefits: the cut happens on a device the agent cannot reach; works
  against a root compromise of the host.
- Drawbacks: needs a supported router and credentials on the Core; a wrong
  cut takes a machine offline.

## Decision

The Core contains a host by adding its address to a quarantine list on the
network firewall. Quarantined hosts can reach only the Core; everything else
is dropped. Adapters behind one trait:

| Adapter | API | Order |
|---|---|---|
| OpenWrt (22.03+, fw4/nftables) | ubus JSON-RPC over HTTPS (`/ubus`), through a small rpcd plugin we ship that only adds, removes and lists addresses in an nftables set | First, for the demo |
| MikroTik RouterOS 7 | REST over HTTPS (`/rest/ip/firewall/address-list`) | First, for the demo |
| Cisco | Meraki Dashboard API, or ASA/FTD REST | Next |
| Dry run | Records the action, touches nothing | Default when no router is configured |

### Key points

- **Triggers:** an evasion alert (ADR-0004), a host daemon that stops its
  heartbeat (ADR-0015), a denied action of the highest severity (data
  exfiltration, record tampering), or the owner from the app.
- **Automatic, reversible by the owner:** the cut is immediate; lifting it
  needs the owner passkey (ADR-0017). Both are events in the chain.
- **Least privilege:** the router account used by the Core may only edit the
  quarantine list, not the rest of the configuration. On OpenWrt, the rpcd
  ACL of the Core's user grants only the methods of our plugin
  (`add`, `remove`, `list`); no shell, no `uci` access. The rule that drops
  quarantined traffic is installed once by the owner.
- **The Core is never cut:** the quarantine rule allows the Core so the
  record keeps flowing.
- **No NAT between monitored hosts and the Core:** the Core contains the
  address of the authenticated peer it sees. If a router masquerades the
  host's traffic towards the Core, that address is the router's, and the
  cut would miss the host. Routers between hosts and the Core route without
  NAT (masquerading only towards the internet). `docs/LAB.md` shows how.

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| hyper client over rustls (HTTPS to the router) | 1, 0.23 | MIT, Apache-2.0 OR ISC OR MIT |

## Consequences

### Positive

- Containment that a root compromise of the host cannot undo; the clearest
  difference from kill switches that live in the same machine.
- Visible in the demo: the agent's exfiltration attempt dies at the router.

### Tradeoffs

- Needs an OpenWrt or MikroTik router (or Cisco) in the demo network; the
  dry-run adapter keeps the demo working without one.
- A false positive takes a machine offline until the owner lifts it;
  thresholds are measured in ADR-0010.

## Implementation

### Next steps

1. `Firewall` trait and dry-run adapter in the `integrations` crate
   (ADR-0020).
2. OpenWrt rpcd plugin, its ACL and the nftables set and rule, as an
   installable package.
3. MikroTik adapter and the one-time rule the owner installs.
4. Cisco adapter.

## Related decisions

- ADR-0003, ADR-0004, ADR-0015: where the triggers come from.
- ADR-0017: the owner lifts a quarantine.

## History

- v1.0 (2026-10-24): Initial decision.
- v1.1 (2026-10-24): OpenWrt added as a first adapter, before acceptance.
- v1.2 (2026-10-24): No NAT between monitored hosts and the Core, before
  acceptance.
- v1.3 (2026-10-24): the observed MAC of the peer is a second target, and
  quarantine follows a contained machine to a new address or key
  (ADR-0028), before acceptance.
