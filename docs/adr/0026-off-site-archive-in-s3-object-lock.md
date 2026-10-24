# ADR-0026: Off-site archive of sealed batches in S3 with Object Lock

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The record lives on the Core. If the Core is destroyed or stolen, the record
is gone; if the company that runs it wants to rewrite history, the only
counterweight is the owner's phone. AUDGENTIC answers this with a public
blockchain. We want an external, tamper-resistant copy without a chain.

## Options considered

### Option 1: anchor heads in a public chain

- Benefits: independent validators.
- Drawbacks: gas, credentials and a chain to explain; rejected in ADR-0006.

### Option 2: copy to a normal cloud bucket

- Benefits: simple.
- Drawbacks: whoever holds the cloud account can delete or overwrite it.

### Option 3: S3 with Object Lock in compliance mode

- Benefits: during the retention period no one, not even the account root,
  can delete or overwrite an object or shorten its retention; the batches are
  already sealed to the owner, so the cloud never reads them.
- Drawbacks: the cloud provider is part of the availability of the backup.

## Decision

After signing each head, the Core uploads, in the background:

| Object | Content |
|---|---|
| `<prefix>/batches/<first_seq>-<seq>.bin` | The encoded events of the batch, payloads sealed to the owner's epoch key |
| `<prefix>/heads/<seq>.json` | The signed head v2 (ADR-0025) |

Sequence numbers are zero-padded so keys sort; keys carry nothing else.

- **Bucket:** versioning, Object Lock in **compliance** mode with a default
  retention (90 days in the module), public access blocked, encryption with
  a dedicated KMS key, a policy that rejects anything but TLS, lifecycle to
  an archive class after 30 days.
- **Credential of the Core:** may only put objects under its prefix: no
  read, list or delete. For the demo an IAM user; later IAM Roles Anywhere,
  so no long-lived key sits on the Pi.
- **Never blocks a decision:** uploads go through a bounded queue with
  retries; a batch that cannot be uploaded is logged and counted, and the
  record on the Core stays complete.
- **Infrastructure as code:** a small OpenTofu (Terraform-compatible) module
  in `infra/aws/`. The same module targets **LocalStack** for the demo, which
  runs on a separate PC as the "cloud" (`infra/localstack/`).
- **Signing requests:** S3 SigV4 through the `rusty-s3` crate, not our own
  implementation (ADR-0014).
- **Configuration:** `ARCHIVE_ENDPOINT`, `ARCHIVE_REGION`, `ARCHIVE_BUCKET`,
  `ARCHIVE_PREFIX`, `ARCHIVE_ACCESS_KEY`, `ARCHIVE_SECRET_KEY`.

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| rusty-s3 | 0.10 | BSD-2-Clause |
| md-5 (Content-MD5, required by Object Lock) | 0.10 | MIT OR Apache-2.0 |
| webpki-roots (public CAs for AWS endpoints) | through hyper-rustls | CDLA-Permissive-2.0 |
| OpenTofu (tool, not shipped) | 1.8+ | MPL-2.0 |
| LocalStack community (demo tool, not shipped) | 3+ | Apache-2.0 |

## Consequences

### Positive

- The record survives the loss of the Core, and history cannot be rewritten
  without the copy in the archive contradicting it.
- An external witness without a blockchain; the cloud sees only ciphertext,
  sizes and sequence numbers.

### Tradeoffs

- The cloud provider affects the availability of the backup, not its
  confidentiality or integrity (sealing and signed heads).
- LocalStack's community edition does not enforce IAM; the least-privilege
  policy is exercised only on real AWS.

## Implementation

### Where it lives

- `integrations/src/archive.rs`, `guardian/src/core.rs` (batch hand-off),
  `infra/aws/`, `infra/localstack/`.

## Related decisions

- ADR-0006, ADR-0007, ADR-0020, ADR-0025.

## History

- v1.0 (2026-10-24): Initial decision.
