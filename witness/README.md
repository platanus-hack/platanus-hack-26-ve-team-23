# witness

The owner's phone: independent witness of the record and holder of the two
keys.

- **Runs on:** the owner's phone.
- **Status:** planned. Implements ADR-0006, ADR-0007, ADR-0008. For the demo
  a minimal client may stand in for a full app.

## What it does

- Stores every signed chain head received from the Guardian.
- Shows alerts (denied actions, evasion) and answers `ask` decisions.
- Holds the opening key (owner signing key) and the weekly epoch keys,
  non-exportable, behind biometrics.
- Signs short-lived open requests and decrypts the batches it receives.
- Verifies a record against the stored heads.

## What it must never do

- Derive epoch keys from the mnemonic.
- Send any key to the Guardian or the PC.
