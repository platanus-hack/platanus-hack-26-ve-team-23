# ADR-0027: Offline first, optional cloud features for any owner; a configuration chain without rollback

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

HAWK must work out of the box with nothing but the Core, the host daemons
and the owner's phone on a local network: no cloud account, no internet. A
company with many Cores wants more: an off-site copy of the record
(ADR-0026), and the Core's configuration managed as code from its cloud,
without touching each device. Remote configuration is dangerous if whoever
holds the cloud account can reconfigure the Core, for example to switch
containment off.

## Options considered

### Option 1: one edition with the cloud built in

- Benefits: one code path.
- Drawbacks: breaks the offline promise; the cloud becomes a requirement and
  a single point of control.

### Option 2: offline by default, enterprise features opt-in

- Benefits: the default stays self-contained; the optional features add
  guarantees without taking control away from the owner.
- Drawbacks: two configurations to document and test.

## Decision

**Default: 100% offline.** Out of the box the Core keeps its configuration in
its own storage (`config.json` in the data directory; to be sealed by the
TPM), set only by the owner from the app over QUIC. No archive, no remote
configuration, no infrastructure as code. Everything in ADR-0001 to ADR-0025
works this way.

**Optional features, available to every owner.** Each one is switched on
separately, by a personal owner as much as by a company; nothing is gated by
edition. "Enterprise" only names the typical use (many Cores managed as
code), not a restriction.

| Optional feature | Enabled by | ADR |
|---|---|---|
| Off-site archive of sealed batches | `ARCHIVE_*` | 0026 |
| Remote configuration managed as code | `CONFIG_REMOTE=1` and `CONFIG_*` | this one |
| Infrastructure as code | `infra/aws` (AWS, LocalStack, any S3 with Object Lock), `infra/render` (Render with RustFS) | 0026, this one |

**The configuration chain (always, offline included).** Every configuration is a link:

- `version` is exactly the active version plus one, and `prev` is the hash of
  the active configuration (`config_hash`). The signature covers both, so an
  old configuration can never be replayed (no rollback), a version cannot be
  skipped, and history cannot fork.
- Every applied configuration is appended to `config-chain.jsonl` and
  recorded as a `Configured` event in the main chain, so it is covered by the
  signed heads and, when the archive is on, by the archive.

**Who can sign.**

- The **owner** always, from the app.
- An **enterprise signer** (a P-256 key held by a pipeline: a company's, or
  a personal owner's own automation; for example in a secret store or a
  cloud KMS), only if the owner put its public key in a configuration the
  owner signed. The enterprise signer can publish
  the next link remotely, but it **cannot set, change or remove the
  enterprise signer**: only the owner can. Remote configurations must not
  carry router secrets in clear text; those are set by the owner from the app
  (sealing secrets to the Core is pending).

**Remote configuration.** The pipeline signs the next `CoreConfig` with
`guardian config-sign` and publishes the `SignedConfig` to
`config/latest.json` in the bucket (OpenTofu can upload it). The Core reads it
every `CONFIG_POLL_SECS` with a read-only credential. It applies it only if it
is the next link and signed by the authorised enterprise signer. A lower
version (rollback attempt) or a different configuration with the active
version (fork) is refused and raises a critical alert in the chain. If the
bucket is unreachable, the Core keeps its own configuration and keeps
working.

## Dependencies and licences

None beyond ADR-0026.

## Consequences

### Positive

- HAWK runs immediately and fully offline; the cloud is never required.
- Any owner who wants it, personal or company, gets an off-site archive and
  configuration as code with an immutable, signed, chained history, and the
  cloud account alone cannot change a Core.

### Tradeoffs

- A compromised enterprise signer can change configuration within what the
  owner allowed; every change is recorded and alerted. Revisit with k-of-n
  signatures for companies (ADR-0007).
- Secrets cannot travel in remote configurations until they are sealed to the
  Core.

## Implementation

### Where it lives

- `guardian-core/src/wire.rs`: `CoreConfig` (version, prev, enterprise
  signer), `config_hash`, `SignedConfig`.
- `guardian/src/core.rs`: `apply_config`, `config-chain.jsonl`.
- `guardian/src/api.rs`: `poll_remote_config`.
- `integrations/src/remote_config.rs`: fetching from S3.
- `guardian config-keygen`, `guardian config-sign`.

## Related decisions

- ADR-0007 (k of n later), ADR-0017 (owner key), ADR-0024 (configuration from
  the wizard), ADR-0026 (archive).

## History

- v1.0 (2026-10-24): Initial decision.
