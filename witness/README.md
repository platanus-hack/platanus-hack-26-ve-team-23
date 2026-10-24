# witness

The owner's app: independent witness of the record and holder of the two
keys. One Tauri 2 crate builds both the desktop app and the Android APK
(ADR-0013).

- **Status:** connected to the Core. Pairing, the Datadog-style dashboard
  (state, tiles, decisions per minute, top rules, filterable event stream)
  and verification of every signed head against the identity pinned at
  pairing. Opening the sealed record, `ask` answers and alerts push are
  pending (see `PENDIENTES.md`).

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

## How it connects

- The Core address is typed in the header (`http://<pi>:8080`).
- **Pairing:** `pair_core` fetches the offer (`GET /pair`), signs it with the
  owner key, sends the epoch public key (`POST /pair`) and checks the six-digit
  code. Compare it with the one in the Core's log. The Core's identity is
  pinned in the app's data directory.
- **Dashboard:** `dashboard` reads `/status`, `/identity`, `/events` and
  `/heads` every three seconds. Heads are checked against the pinned key,
  never against what the Core claims now: a swapped Core fails every head.
- The owner and epoch keys are files in the app's data directory for the
  desktop build and the demo; on Android they move to the Keystore.

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
