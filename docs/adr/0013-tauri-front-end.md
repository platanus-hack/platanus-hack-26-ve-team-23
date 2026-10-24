# ADR-0013: Tauri 2 for every front end

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23

## Context

The project needs two screens:

- **The witness** on the owner's phone: signed heads, alerts, `ask`
  decisions, the two keys, the verifier.
- **A dashboard** for the demo and the evaluation: live events from the
  Guardian, decisions, metrics.

The witness must verify the hash chain with exactly the same code as the
Guardian (ADR-0012), and keep keys in the platform's secure storage.

## Options considered

### Option 1: Tauri 2 with a plain HTML, CSS and JavaScript UI

- Benefits: the logic is Rust and links `guardian-core` directly; one code
  base for desktop and Android; small binaries; the team has a working
  example in `nepheral-desktop` (Tauri 2, Android Keystore over JNI, plain
  web UI).
- Drawbacks: Tauri mobile is younger than native toolkits; Android builds
  need the Android SDK and NDK.

### Option 2: Flutter or React Native

- Benefits: mature mobile tooling.
- Drawbacks: the chain verifier would be reimplemented in Dart or
  JavaScript, or bridged over FFI; a second stack to learn.

### Option 3: a web dashboard served by the Guardian

- Benefits: nothing to install.
- Drawbacks: the witness must not depend on the Guardian it witnesses; a
  browser cannot hold non-exportable keys.

## Decision

Every front end is a Tauri 2 application. The `witness` crate builds the
phone app (Android) and a desktop build used as the dashboard and as a
fallback witness in the demo. The UI is plain HTML, CSS and JavaScript, with
no front-end framework, as in `nepheral-desktop`. All logic (verification,
keys, signing, decryption) lives in Rust commands; the web view only
displays and forwards user input.

### Key points

- **One crate, two outputs:** the same `witness` crate and the same UI build
  the desktop app (`cargo run -p witness`) and the Android APK
  (`cargo tauri android build --apk`). The library is built as `staticlib`,
  `cdylib` and `rlib`, and `run()` is the mobile entry point. There is no
  separate mobile code base.
- **Look and feel of an observability dashboard** (in the style of Datadog):
  a dark theme; a header with the Core's state (unpaired, active, alert)
  and the hosts it watches; tiles with counters (calls decided, denied,
  asked, evasion alerts); time series of decisions per minute; top rules
  fired; a live event stream with filters by host, session, tool and
  severity; and an alert inbox where `ask` decisions are answered. Charts
  are drawn by us in SVG or canvas, with no chart library.
- **First screen is pairing** while the Core is unpaired (ADR-0017).
- **Keys never reach the web view.** Commands return results, not key
  material.
- **Android keys:** non-exportable keys in the Android Keystore, reached over
  JNI, with biometric confirmation (ADR-0007).
- **Desktop witness for the demo** if the phone build is not ready; said so
  on stage.

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| tauri, tauri-build | 2 | MIT OR Apache-2.0 |
| jni (Android only) | 0.21 | MIT OR Apache-2.0 |
| ndk-context (Android only) | 0.1 | MIT OR Apache-2.0 |

## Consequences

### Positive

- The witness and the Guardian share one chain implementation.
- Code for the shell, Keystore access and UI structure can be taken from
  Nepheral.

### Tradeoffs

- Android builds need the SDK and NDK on at least one team machine.
- iOS is out of scope for the hackathon.

## Implementation

### Where it lives

- `witness/`: Tauri crate (`src/`, `ui/`, `tauri.conf.json`,
  `capabilities/`).

### Next steps

1. Desktop build showing live heads from the Guardian.
2. Android build with Keystore-backed keys.

## Related decisions

- ADR-0007, ADR-0008: the keys the witness holds.
- ADR-0012: the shared crates.

## References

- `nepheral-desktop` in Nepheral-core.

## History

- v1.0 (2026-10-24): Initial decision.
