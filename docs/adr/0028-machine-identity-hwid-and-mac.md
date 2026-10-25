# ADR-0028: Host selection beyond the IP address: machine id (HWID) and MAC

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

Containment (ADR-0018) selects a host by one value: the IP address of the
authenticated QUIC peer. An agent that is contained, or about to be, can
leave that selection without breaking anything:

- **Change the address**: a static alias, a DHCP release and renew, a second
  interface. The router list still holds the old address.
- **Re-key the daemon**: delete `host.key`, restart, reconnect. The Core sees
  a new host and nothing links it to the contained one.
- **Run a virtual machine** with bridged networking: it gets its own MAC and
  IP, and neither is in the router list.

The Core needs to recognise the same machine across these changes, and the
router needs a selector that survives an address change. The hard rule still
holds: a host must never be able to get *another* host contained, so nothing
a client declares may become a containment target.

## Options considered

### Option 1: keep the IP only

- Benefits: nothing to build.
- Drawbacks: every escape above works.

### Option 2: contain the MACs and machine id the daemon reports

- Benefits: simple.
- Drawbacks: a compromised daemon can report the MAC of the router, of the
  Core or of a colleague's machine, then trigger a critical finding and get
  that device cut. Violates the identity-not-addresses rule.

### Option 3: observed MAC as a target, declared machine id as a link

The Core learns the MAC of the peer from its own neighbour table (ARP), a
value it observes, not one the client declares. The daemon reports a machine
id (HWID) that links its identities and addresses over time; the HWID only
decides *whether* to contain a connecting peer, never *what* to cut.

- Benefits: survives address changes (MAC) and re-keying (HWID); a forged
  HWID can only get the forger itself contained.
- Drawbacks: the MAC is only visible on the same L2 segment; a root agent
  can change its MAC and its machine id; a bridged VM has its own MAC.

### Option 4: contain the switch port

Find the port where the host's MAC is learned and cut the port.

- Benefits: also catches VMs bridged behind the same port.
- Drawbacks: needs a managed switch and its API; wrong on shared ports
  (Wi-Fi, an unmanaged switch behind the port) where it cuts everybody.

## Decision

Option 3 now, Option 4 as the next step for wired hosts on managed switches.

### Key points

- **Three kinds of identifier, three levels of trust.**

  | Identifier | Source | Trust | Used for |
  |---|---|---|---|
  | Daemon identity (Ed25519) | TLS handshake | Authenticated | Who is speaking |
  | IP, MAC | The Core's socket and neighbour table | Observed | Containment targets |
  | HWID, network interfaces | `HostHello` from the daemon | Declared | Linking, labels, warnings |

- **HWID.** `SHA-256("hawk.hwid.v1" || machine id)`, first 16 bytes, hex. The
  machine id is `/etc/machine-id` (Linux), `MachineGuid` (Windows) or
  `IOPlatformUUID` (macOS). Hashed with our own domain so the raw id, which
  systemd asks applications not to expose, never leaves the host.
- **Observed MAC.** The Core reads its neighbour table for the peer's IP
  (`/proc/net/arp` on the Pi). Behind a router (routed or masqueraded) there
  is no MAC: containment falls back to the IP alone, as today.
- **Containment targets** are the peer's IP and, when known, its observed
  MAC. Routers:
  - OpenWrt: a second nftables set `guardian_quarantine_mac`
    (`type ether_addr`), dropped in the same forward chain, Core excepted.
  - MikroTik: a mangle rule per MAC with
    `action=add-src-to-address-list` into the existing quarantine list, so
    any address that MAC uses lands in the list on its first packet.
- **Sticky quarantine by machine.** The Core remembers every contained
  machine by daemon identity, HWID and observed MAC. When any of them
  reconnects from a new address, or with a new key, the Core contains the
  new IP and MAC at once and records why (`re-contained: same hwid`).
- **Re-keying alert.** A new daemon identity that reports the HWID of
  another identity raises a high alert, contained or not.
- **Virtual adapters.** The daemon reports its interfaces with a `virtual`
  flag (known hypervisor MAC prefixes and interface names). The app warns
  that a bridged VM on that host escapes IP and MAC containment, and the
  port (Option 4) is the answer.
- **Selection in the app.** The host list shows and filters by name, IP,
  observed MAC, HWID and fingerprint.

## Dependencies and licences

None. Machine id and interfaces are read from files and system commands
(arguments passed separately, never through a shell).

## Consequences

### Positive

- Changing the address, renewing DHCP or re-keying the daemon no longer
  frees a contained machine.
- The owner can find a host by any of its identifiers.

### Tradeoffs

- The HWID is declared: an agent with root can change the machine id. It
  then looks like a new machine, which host enrolment (owner approval of
  every new host, ADR-0029) and attestation (ADR-0021, TPM-bound
  identity) close.
- A root agent can change its MAC; MikroTik's mangle rule and OpenWrt's set
  then miss the new MAC, but sticky quarantine catches the reconnection.
- A bridged VM that never runs our daemon has a MAC and IP the Core has
  never seen. Only port containment (Option 4) or default-deny for
  unenrolled MACs stops it.
- The sticky set lives in memory: a Core restart forgets it (the router
  lists persist).

## Implementation

### Where it lives

- `guardian-core/src/machine.rs`: `Mac`, `hwid`, `Nic`, virtual-adapter
  heuristics. No I/O.
- `host-daemon/src/machine.rs`: reads the machine id and interfaces.
- `guardian/src/neighbors.rs`: the observed MAC of a peer.
- `guardian/src/hosts.rs`: per-host HWID, MAC and interfaces; the sticky set.
- `integrations`: `Firewall::quarantine_mac` / `release_mac` for dry run,
  OpenWrt (`integrations/openwrt/`) and MikroTik.
- `witness/ui`: identifiers, the VM warning and the filter.

### Next steps

1. Port containment on MikroTik switches (`/interface/bridge/host` to find
   the port, a bridge filter to cut it), only on ports with one learned MAC.
2. Persist the sticky set with the record.
3. Alert when the Core's neighbour table shows a hypervisor MAC that no
   enrolled host reported.

## Related decisions

- ADR-0018: containment through the firewall; this adds the MAC target.
- ADR-0021: attestation makes the machine identity unforgeable.
- ADR-0023: the daemon identity from the TLS handshake.

## References

- systemd `machine-id(5)`: the id is confidential; hash it per application.
- RouterOS mangle `add-src-to-address-list`, nftables `ether_addr` sets.

## History

- v1.0 (2026-10-24): Initial decision.
