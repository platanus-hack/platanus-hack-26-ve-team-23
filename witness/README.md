# witness

The owner's app: independent witness of the record and holder of the two
keys. One Tauri 2 crate builds both the desktop app and the Android APK
(ADR-0013).

- **Status:** skeleton window showing the genesis head. Heads, alerts, keys
  and verifier planned (ADR-0006, ADR-0007, ADR-0008).

## Screens

Styled like an observability dashboard (Datadog-like), see ADR-0013:

1. **Pairing** (while the Core is unpaired, ADR-0017): scan the Core's code,
   create the owner passkey, confirm the short code.
2. **Overview:** Core state, hosts, counters, decisions per minute, top
   rules.
3. **Events:** live stream with filters by host, session, tool, severity.
4. **Alerts:** denied actions, evasion alerts, `ask` decisions to answer.
5. **Record:** signed heads, verification, opening with the passkey.

## Build

| Output | Command | Needs |
|---|---|---|
| Desktop | `cargo run -p witness` | WebView2 (Windows) or WebKitGTK 4.1 (Linux) |
| APK | `cd witness && cargo tauri android build --apk` | Tauri CLI (`cargo install tauri-cli`), Android SDK and NDK; run `cargo tauri android init` once |

## Layout

- `src/lib.rs`: `run()`, also the mobile entry point.
- `src/commands.rs`: the only functions the web view may call.
- `ui/`: plain HTML, CSS and JavaScript; display only.
- `icons/`: placeholder icons copied from Nepheral; replace with the project
  logo.

## What it must never do

- Pass key material to the web view.
- Derive epoch keys from the mnemonic.
- Send any key to the Guardian or the PC.
