# Action tree

What the system does in every situation decided so far. Each branch cites
the ADR that decides it.

## 0. Core state (ADR-0017)

```
Core boots
├── UNPAIRED
│   ├── /decide -> DENY everything
│   ├── records nothing
│   └── exposes only /pair -> phone scans, creates passkey, codes confirmed
│       └── OK -> "Paired" event (first in the chain) -> ACTIVE
└── ACTIVE -> everything below
```

## 1. A tool call (ADR-0004, ADR-0005, ADR-0022)

```
Model proposes a tool call
├─[A] PROXY on the Core: records request and response, extracts the call,
│     opens a cross-check window (5 s)
└─[B] HOOK -> host daemon (127.0.0.1) -> Core /decide
      ├── daemon unreachable ........ hook -> DENY
      ├── Core unreachable .......... daemon -> DENY
      ├── malformed or oversized .... DENY
      ├── host quarantined .......... DENY
      └── Core evaluates
          ├── rules (call + last N calls) and classifier -> findings
          ├── highest severity decides:
          │   ├── CRITICAL -> DENY + ALERT + QUARANTINE
          │   ├── HIGH ----> DENY + ALERT
          │   ├── MEDIUM --> ASK owner (approve / reject / 60 s -> DENY)
          │   └── LOW/none -> ALLOW
          └── any internal error -> DENY
```

## 2. Cross-check (ADR-0004)

```
When the window closes
├── proxy saw it AND hook asked ...... OK
├── proxy saw it, hook did NOT ask ... EVASION -> CRITICAL ALERT + QUARANTINE
└── hook asked, proxy did NOT see it . ANOMALY -> HIGH ALERT
```

## 3. Host signals (ADR-0015, ADR-0021)

```
host daemon
├── sensor: protected path changed
│   ├── agent logs or history ............ HIGH ALERT
│   └── hook plugin or daemon config ..... CRITICAL ALERT + QUARANTINE
├── heartbeat (challenge-response, TPM key)
│   └── late, missing or invalid (15 s) .. CRITICAL ALERT + QUARANTINE
└── boot quote does not match ............ host inactive / QUARANTINE
```

## 4. Containment (ADR-0018, ADR-0020)

```
QUARANTINE host
├── adapter: OpenWrt | MikroTik | Cisco | dry run
│   ├── OK -> "Contained" event -> host reaches only the Core
│   └── failure -> "containment failed" alert -> retry
├── meanwhile: every /decide from the host -> DENY
└── release -> owner passkey only -> "Released" event
```

## 5. Record and sinks (ADR-0006, ADR-0019, ADR-0020)

```
Every event
├── appended to the hash chain on the Core
├── head signed Ed25519 + ML-DSA
│   ├── every few minutes -> phone
│   └── after every HIGH or CRITICAL event -> phone immediately
└── sinks, asynchronous, never blocking (metadata only)
    ├── Kafka   ├── webhook   └── CEF syslog
```

## 6. Owner on the phone (ADR-0007, ADR-0013, ADR-0017)

```
App (Datadog-style)
├── answer an ASK .............. ALLOW / DENY
├── release a quarantine ....... passkey
├── open the record ............ passkey + weekly key -> "LogOpened" event
├── verify the chain ........... recompute and compare with stored heads
└── phone unreachable -> ASK expires as DENY; heads and alerts queue on the Core
```
