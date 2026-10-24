# ADR-0020: Integrations: firewall adapters and event sinks, starting with Kafka

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

Organisations already run systems that control their network and collect
their security events: routers and firewalls (OpenWrt, MikroTik, Cisco),
event buses (Kafka) and SIEMs that read from them. A monitor that lives in
its own island is a demo; one that acts through the network equipment and
publishes into the existing event pipeline is a product. Integrations are
also what the user sees working on stage.

## Options considered

### Option 1: integrations inside the Core binary, ad hoc

- Benefits: fastest for the first one.
- Drawbacks: each new integration touches the decision path; no common
  failure handling.

### Option 2: an `integrations` crate with two traits

- Benefits: one place for every adapter; the Core depends on traits; each
  adapter is a Cargo feature, so the Pi build carries only what it uses.
- Drawbacks: a small abstraction to design up front.

## Decision

A new crate, `integrations`, with two traits:

| Trait | Purpose | Adapters |
|---|---|---|
| `Firewall` | Quarantine and release a host (ADR-0018) | OpenWrt, MikroTik, Cisco, dry run |
| `EventSink` | Publish events outside the Core | Kafka, webhook (JSON over HTTPS), syslog in CEF for SIEMs |

### Key points

- **Kafka first:** one topic per event family (`decisions`, `alerts`,
  `containment`, `heads`), keyed by host, with the pure-Rust `rskafka`
  client so the Pi build needs no C toolchain.
- **Metadata only:** sinks receive the decision, rule, severity, host,
  session, tool name and the chain head, never the encrypted content of the
  record (ADR-0007). Opening the content still needs the two keys.
- **Sinks never block decisions:** publishing is asynchronous with a bounded
  queue; when a sink is down, events wait or are dropped from the queue with
  a counter, and the record on the Core stays complete.
- **Firewall calls do block containment:** a failed quarantine raises an
  alert to the phone and is retried.
- **Each adapter is a Cargo feature** of `integrations`.

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| rskafka | 0.6 | MIT OR Apache-2.0 |

## Consequences

### Positive

- Fits into the security stack an organisation already runs.
- A visible demo: the agent misbehaves, the router cuts it, the event lands
  in Kafka and on the phone at the same time.

### Tradeoffs

- More surface to maintain; adapters without hardware to test against run
  only against recorded responses.

## Implementation

### Where it lives

- `integrations/` (to be created).

### Next steps

1. Traits and dry-run adapters.
2. OpenWrt and MikroTik firewall adapters.
3. Kafka sink, with a Kafka service in `docker-compose.yml` for tests.
4. Webhook and CEF syslog sinks.

## Related decisions

- ADR-0018: containment.
- ADR-0007: what stays encrypted.

## History

- v1.0 (2026-10-24): Initial decision.
