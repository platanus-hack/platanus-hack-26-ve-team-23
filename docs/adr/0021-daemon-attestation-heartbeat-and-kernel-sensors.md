# ADR-0021: Daemon attestation, challenge-response heartbeat and kernel sensors

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The host daemon (ADR-0015) runs on the untrusted host. The Core needs to know
which machine a daemon runs on, whether it booted what it should, and
whether it is alive right now. Nothing that runs on the host can resist an
attacker with root on that host, kernel code included: root can stop the
daemon, unload kernel programs and use the host's keys while it is inside.

## Options considered

### Option 1: trust the daemon's plain heartbeat

- Benefits: trivial.
- Drawbacks: any process can send "I am alive"; a replayed or forged
  heartbeat hides a dead daemon.

### Option 2: try to make the daemon unkillable

- Benefits: sounds strong.
- Drawbacks: impossible against root; claiming it would be false.

### Option 3: attest what can be attested, and punish silence

- Benefits: honest guarantees; an attacker who kills the daemon is cut off
  at the network, one who leaves it alive is observed.
- Drawbacks: needs a TPM (real or virtual) for the strongest parts.

## Decision

### Identity and boot state

- At enrolment, the daemon creates its signing key **inside the TPM**,
  non-exportable. The owner enrols the public key with the Core (ADR-0017).
- **Measured boot quote:** the Core sends a nonce; the TPM signs the PCR
  values with it. On Linux, IMA adds the hash of the daemon binary. A quote
  that does not match the enrolled values keeps the host inactive or
  quarantines it.

### Liveness: challenge-response heartbeat

Every heartbeat answers a nonce from the Core and carries a monotonic
counter and the hash of the events the daemon observed since the previous
heartbeat, signed with the TPM key. The Core checks it against what the
proxy and the hook reported independently, so a frozen or forged daemon
cannot produce consistent heartbeats.

### Dead man's switch

| Condition | Action |
|---|---|
| Valid heartbeat in time | Host trusted |
| Late, missing or invalid heartbeat | Critical alert and network quarantine (ADR-0018) |
| Quote does not match | Host not activated, or quarantined |

The attacker can leave the daemon running and be observed, or stop it and be
cut off.

### Kernel sensors

- **Linux:** eBPF programs loaded by the daemon with Aya: observe `execve`,
  unlink, rename and truncate on protected paths, and outbound `connect`.
  Later, BPF LSM hooks block those operations in the kernel.
- **Windows:** no kernel driver (it needs Microsoft driver signing); ETW
  consumers in user mode for process, file and network events, after the
  hackathon.
- For the demo the agent runs in a Linux VM (Hyper-V Gen2 with a virtual
  TPM), whose only network path is the router of ADR-0018.

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| aya, aya-ebpf | latest | MIT OR Apache-2.0 |
| tss-esapi (TPM 2.0 on Linux) | 7 | Apache-2.0 |

Windows TPM access reuses the approach of Nepheral's `tpm.rs`.

## Consequences

### Positive

- The Core knows which machine and which boot state it trusts.
- Killing the sensor is itself the strongest signal.

### Tradeoffs

- A root attacker can use the TPM key through the running daemon while it is
  inside; the event hash in heartbeats limits what they can fake.
- eBPF needs a recent kernel (5.7 or later for BPF LSM).

## Implementation

### Next steps

1. Challenge-response heartbeat with a software key, then the vTPM key.
2. Dead man's switch wired to quarantine.
3. eBPF sensors for exec, protected paths and connect.
4. PCR quote with IMA; BPF LSM blocking.

## Related decisions

- ADR-0015: the daemon. ADR-0018: quarantine. ADR-0017: enrolment.

## History

- v1.2 (2026-10-24): the boot measurement is wired end to end: the daemon
  reads the PCRs (`host-daemon/src/tpm.rs`, Linux only for now) and reports
  the digest in `HostHello` and in every signed heartbeat; the Core stores it
  at hello and quarantines a host whose heartbeat carries a different
  measurement. The TPM-signed quote and the non-exportable key are still the
  hardware follow-up.
- v1.1 (2026-10-24): the software parts are implemented: owner enrolment of
  the host identity (ADR-0023), a challenge-response heartbeat signed with
  the daemon's Ed25519 key carrying a monotonic counter and the digest of the
  observed calls, and the dead man's switch that quarantines a host silent
  for 15 s. The key still lives in `host.key` (software); sealing it in the
  TPM/vTPM and the measured-boot quote stay pending (hardware).
- v1.0 (2026-10-24): Initial decision.
