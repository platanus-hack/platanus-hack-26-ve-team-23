# integrations

Firewall adapters and event sinks (ADR-0018, ADR-0020).

- **Status:** dry-run, MikroTik (REST) and OpenWrt (ubus + rpcd plugin)
  firewalls; Kafka and webhook sinks. Cisco planned.

## Firewall

Chosen with `GUARDIAN_FIREWALL` = `dry-run` (default) | `mikrotik` |
`openwrt`. A configuration error falls back to dry run and logs an error.
HTTPS to a router requires pinning its certificate fingerprint
(`*_CERT_SHA256`); plain HTTP is accepted for labs only.

| Router | Variables | Router side |
|---|---|---|
| MikroTik RouterOS 7 | `MIKROTIK_URL`, `MIKROTIK_USER`, `MIKROTIK_PASSWORD`, `MIKROTIK_CERT_SHA256`, `MIKROTIK_LIST` | An address list and one drop rule; an account with `rest-api,read,write` |
| OpenWrt 22.03+ | `OPENWRT_URL`, `OPENWRT_USER`, `OPENWRT_PASSWORD`, `OPENWRT_CERT_SHA256` | `openwrt/guardian` in `/usr/libexec/rpcd/`, `openwrt/guardian-acl.json` in `/usr/share/rpcd/acl.d/`, `openwrt/guardian.nft` in `/etc/nftables.d/` (edit `CORE_ADDRESS`), an rpcd login with `read`/`write` = `guardian-core` |

## Sinks

`KAFKA_BROKERS` (comma-separated, topics `<KAFKA_TOPIC_PREFIX>.decisions`,
`.alerts`, `.containment`, `.heads`) and `GUARDIAN_WEBHOOK_URL`. Publishing
is asynchronous through a bounded queue and never blocks a decision; only
metadata is published, never the sealed record.

## What it must never do

- Accept an HTTPS certificate without a pinned fingerprint.
- Block a decision while publishing.

## Tests

`cargo test -p integrations`. The router adapters are tested for
configuration and protocol handling; end-to-end tests need a router (see the
lab in `PENDIENTES.md`).
