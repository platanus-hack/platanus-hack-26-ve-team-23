# ADR-0024: Discovery on the local network and an activation wizard

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The first witness asked the owner to type the Core's address. A Core fresh
out of the box has no screen, its address is assigned by DHCP, and asking the
owner for an IP address is a poor first experience. A dormant Core (unpaired)
or one without configuration must be found and activated from the app.

## Options considered

### Option 1: type the address

- Benefits: nothing to build.
- Drawbacks: the owner has to find the IP; error-prone; looks unfinished.

### Option 2: mDNS / DNS-SD on the local network

- Benefits: zero configuration; the Core announces itself with its identity
  and state; proven in Nepheral (`mdns-sd`).
- Drawbacks: multicast can be blocked between VLANs or on guest networks;
  Android needs a multicast lock.

## Decision

The Core announces `_hawk-core._udp.local.` with its QUIC port and TXT
records `id` (Ed25519 public key, hex), `state` (`unpaired` or `active`),
`name` and `v`. The witness and the host daemons browse for it.

The witness replaces the address field with an activation wizard:

1. **Discover**: list the Cores found on the network, with state and a short
   fingerprint.
2. **Verify**: the owner compares the fingerprint with the one the Core
   prints at boot (log, console; a screen or QR later).
3. **Pair**: the app creates its keys and pairs over QUIC (ADR-0017,
   ADR-0023); both sides show the six-digit code.
4. **Configure**: name the Core and choose the firewall (dry run, MikroTik,
   OpenWrt) with its credentials; the configuration is signed by the owner
   and applied by the Core immediately.
5. **Done**: the dashboard opens; the app remembers the Core by identity and
   finds its new address by discovery if it changes.

Host daemons use the `GUARDIAN_CORE` address when set, otherwise the first
active Core discovered; if `GUARDIAN_CORE_ID` is set, only that identity is
accepted.

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| mdns-sd | 0.13 | MIT OR Apache-2.0 |
| local-ip-address | 0.6 | MIT OR Apache-2.0 |

## Consequences

### Positive

- Activation without typing addresses; the app follows the Core by identity.

### Tradeoffs

- Discovery fails across VLANs; the daemon override and a manual address in
  a later version cover it.
- A daemon without `GUARDIAN_CORE_ID` trusts the first active Core it finds
  until host enrolment exists (ADR-0029).

## Implementation

### Where it lives

- `edge-net/src/discovery.rs`, the Core's announcement, the witness wizard.

## Related decisions

- ADR-0017, ADR-0018, ADR-0023.

## History

- v1.1 (2026-10-24): the wizard also takes a typed address ("Not listed?
  Type its address") for networks where multicast does not reach, such as
  another VLAN or the Android emulator. The app connects without a pin,
  shows the fingerprint the handshake proved, and pairing continues as
  before: the owner compares the fingerprint and the six-digit code.
- v1.0 (2026-10-24): Initial decision.
