# ADR-0017: The Core stays inactive until paired with a phone; the owner credential is a passkey

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

A Core that starts working as soon as it is plugged in has no owner: nobody
receives its heads, nobody can open its record, and anyone on the network
could claim it. The owner also needs a credential that survives losing the
phone. ADR-0008 proposed a BIP-39 mnemonic written on paper; most users lose
paper, and phones already offer passkeys synced by the platform (for example
Google Password Manager on Android, through Credential Manager).

## Options considered

### Option 1: mnemonic on paper (ADR-0008)

- Benefits: no third party.
- Drawbacks: users lose or photograph the paper; recovery depends on it.

### Option 2: hardware-bound key only, no recovery

- Benefits: strongest.
- Drawbacks: a lost phone means re-pairing from zero and losing access to
  the record.

### Option 3: passkey, synced by the platform's password manager

A WebAuthn credential (P-256, ES256) created by the phone for the Core.

- Benefits: familiar to users; recovered by signing in to the same account
  on a new phone; every use asks for biometrics; the Core verifies
  standard assertions.
- Drawbacks: the platform account (Google, for example) becomes a recovery
  path, so its compromise is a compromise of the owner credential; a
  passkey needs a relying-party domain with Digital Asset Links for the
  Android app.

## Decision

### Pairing

1. A new Core boots **unpaired**. In this state it records nothing, answers
   every `/decide` with deny, and exposes only a pairing endpoint on the
   local network.
2. The Core shows a one-time pairing code (QR in its log or on a status
   page, and a short code) containing its public key and a nonce.
3. The phone scans it, creates the owner passkey, and sends the Core the
   passkey's public key and credential id, together with a fresh assertion
   over the nonce.
4. Both sides display a short confirmation code derived from both public
   keys; the owner confirms they match. This defeats a device in the middle
   on the local network.
5. The Core stores the owner public key, starts its chain with a
   `Paired` event as the first entry, and becomes **active**.

Re-pairing to a different owner requires an assertion from the current
owner passkey, or a physical reset of the Core that wipes its record.

### Owner credential

- **The opening key of ADR-0007 is the owner passkey.** An open request is a
  WebAuthn assertion over a challenge issued by the Core, valid for a short
  time, recorded as an event.
- **Sync is allowed:** the owner may keep the passkey in the platform's
  password manager (for example Google). Recovery is signing in on a new
  phone. This replaces the mnemonic of ADR-0008 as the default; a hardware
  security key can be registered as a second credential.
- **Weekly epoch keys stay random, local and non-recoverable** (unchanged
  from ADR-0008). They are not derived from the passkey (no WebAuthn PRF),
  so syncing the passkey never makes erased weeks readable again. A new
  phone reads from the next epoch on.

## Dependencies and licences

None decided yet. A WebAuthn verification crate on the Core, and Credential
Manager access in the Android build, are chosen in the implementation and
must satisfy ADR-0011.

## Consequences

### Positive

- A Core is useless to anyone but its owner from the first boot.
- Recovery without paper, with a flow users already know.

### Tradeoffs

- The platform account is part of the trust model for the owner
  credential; written down in SECURITY.md.
- Passkeys need a domain for the relying party; for the demo, a domain with
  `assetlinks.json` is required, or the demo falls back to a key in the
  Android Keystore.
- The record of the current week is unreadable after losing the phone.

## Implementation

### Next steps

1. Unpaired and active states in `guardian`; deny-all while unpaired.
2. Pairing message types in `guardian-core`.
3. Pairing screen in `witness` (scan, confirm code).
4. WebAuthn assertion verification on the Core.

## Related decisions

- ADR-0007: the opening key is now the owner passkey.
- ADR-0008: superseded by this ADR for owner recovery; its rule on epoch
  keys is kept.
- ADR-0013: the app that pairs.

## References

- W3C Web Authentication Level 3; Android Credential Manager.

## History

- v1.1 (2026-10-24): pairing v2 (ADR-0030): the owner signs the nonce, the
  transport identity, the head keys generated at activation and the app.
- v1.0 (2026-10-24): Initial decision.
