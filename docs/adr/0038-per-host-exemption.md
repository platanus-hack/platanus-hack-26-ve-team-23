# ADR-0038: The owner can exempt one machine, for a while

- **Status:** Proposed
- **Date:** 2026-10-25
- **Deciders:** Javier Hernandez, team-23 (approval pending)

## Context

Every approved machine is filtered: each tool call is decided before it runs
(ADR-0004, ADR-0022). That is the product. But there are moments when an owner
needs one machine to work without being stopped: a long migration that trips
`rm -r` on every step, a demo, debugging HAWK itself, or a rule that fires on
something legitimate while the catalogue is fixed.

Today the only ways out are blunt: disapprove the machine (which denies
everything instead of allowing it), raise the global thresholds (ADR-0033,
which loosens *every* machine), or uninstall the hook (which also stops the
record). None of these is "let this one machine through, and keep watching
it".

The danger is obvious: an exemption is a switch that turns the monitor off.
Whoever can set it can neutralise HAWK for a host, so who may set it, how it is
recorded and how it ends matter more than the feature itself.

## Options considered

### Option 1: a local switch on the host (environment variable, flag)

- Benefits: trivial.
- Drawbacks: the monitored machine decides whether it is monitored. The agent
  runs with the user's permissions, so the agent could set it. This inverts
  the whole threat model (ADR-0002) and is refused.

### Option 2: the owner disapproves the machine

- Benefits: exists already.
- Drawbacks: disapproval denies, it does not allow. It is the opposite
  outcome, and the machine stops being able to work at all.

### Option 3: an exemption in the Core's signed configuration, per machine, with an expiry

- Benefits: only the owner can set it; it is chained and recorded like any
  other configuration; it names one machine; it ends by itself.
- Drawbacks: one more field in the configuration and one more state the app
  has to show honestly.

## Decision

Option 3.

### Key points

- **It is part of the signed configuration chain** (ADR-0027):
  `CoreConfig.exemptions`. So it is signed by the owner, it is the next link
  of the chain and cannot be rolled back or forked, and applying it is
  recorded as a `Configured` event in the record the agent cannot rewrite.
- **Only the owner, never the pipeline.** A remote configuration signed by the
  enterprise signer may not add, change or remove an exemption, the same
  carve-out the enterprise signer itself has (ADR-0027). A compromised cloud
  account must not be able to switch HAWK off for a machine.
- **It names an identity, not an address.** The exemption carries the host
  daemon's Ed25519 identity (hex), and the Core matches it against the
  authenticated QUIC peer, never against a hostname, an address or anything
  else a client declares (ADR-0023, ADR-0028). A machine cannot talk its way
  into another machine's exemption.
- **It expires, always.** `until_ms` is mandatory and bounded
  (`MAX_EXEMPTION_MS`, 24 hours): there is no open-ended exemption. An expired
  exemption simply stops applying, with nothing to remember to undo. The owner
  renews it if the work is still going.
- **It stops the blocking, not the watching.** Detection still runs, and every
  call is still recorded with the findings it produced, plus the exemption
  that let it through. The record therefore shows exactly what *would* have
  happened, so an exemption can hide nothing after the fact. What it does
  suppress is the outcome: the call is allowed and the machine is not
  quarantined.
- **It cannot be silent.** The Core reports its active exemptions in the
  status the app reads, so the app can show, in plain sight, that a machine is
  not being protected right now.
- **Everything else still fails closed.** An unpaired Core, an unapproved
  host, an unwritable record or an unavailable detector still deny
  (ADR-0022), exemption or not: the exemption decides what to do with a
  finding, not whether HAWK is working.

## Dependencies and licences

None.

| Dependency | Version | Licence |
|---|---|---|
| None | | |

## Consequences

### Positive

- An owner can unblock one machine for a bounded time without loosening the
  other machines, and without losing the record.
- The dangerous cases are closed by construction: the monitored machine cannot
  exempt itself, the cloud cannot exempt it, and nobody can leave an exemption
  on for ever.

### Tradeoffs

- While an exemption is active that machine is not protected, only observed.
  This is the point of the feature, and why it expires, names one machine and
  is shown in the app.
- A critical finding on an exempt machine is recorded and reported but does
  not quarantine. An owner who wants containment regardless should not exempt
  the machine.
- One more field in `CoreConfig`. It is left out of the JSON while empty, so
  configurations signed before it existed keep their hash and signature, the
  same way thresholds were added (ADR-0033).

## Implementation

### Where it lives

- `guardian-core/src/wire.rs`: `Exemption`, `CoreConfig.exemptions`,
  `exemption_for`, `MAX_EXEMPTION_MS`.
- `guardian/src/core.rs`: refuses an exemption from the enterprise signer and
  one with a missing, past or too distant expiry.
- `guardian/src/api.rs`: `decide` applies it after detection and recording.
- `witness/ui`: the owner picks the machine and the duration, and the app
  shows an active exemption. **Not built yet, and it needs one more decision,
  found while building the Core side:** changing `CoreConfig.exemptions` means
  republishing a whole `CoreConfig`, which carries the router's secrets, and
  the Core deliberately never sends those to the app (it answers with a
  `ConfigSummary`). So the app cannot rebuild the configuration to add an
  exemption to it. The way out is a dedicated owner-signed request, the way
  `Approve`, `Release` and `Identify` already work: `Request::Exempt { host,
  until_ms, reason, signature }`, which the Core verifies against the owner's
  key and then applies onto its own active configuration, appending the next
  link of the chain itself. Until that exists, an exemption can only be set by
  publishing a configuration from the settings screen, where the owner is
  already entering the firewall's details.

## Related decisions

- ADR-0002 (control the agent, not the model), ADR-0022 (fail closed),
  ADR-0023 (identity, not addresses), ADR-0027 (configuration chain and who
  signs), ADR-0033 (thresholds, the precedent for an owner-set field).

## History

- v1.0 (2026-10-25): Initial proposal.
