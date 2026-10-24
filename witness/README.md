# witness

The owner's app: it controls the Core from the phone. One Tauri 2 crate
builds the Android APK and a desktop build used for development (ADR-0013).

- **Status:** QUIC with mutual TLS to the Core with its own device identity;
  activation wizard (find by mDNS, verify fingerprint, pair, configure);
  dashboard (state, decisions over time, rules, hosts, events, integrity);
  every signed head verified against the identity pinned at pairing; hosts
  listed by fingerprint with an Identify button. Pending: opening the sealed
  record, answering `ask`, alerts, Android Keystore, multicast lock and
  passkeys (see `PENDIENTES.md`).

## Activation wizard (ADR-0024)

1. **Find:** Cores announcing themselves on the network, with state and
   fingerprint. Only unpaired ones can be activated.
2. **Verify:** compare the fingerprint with the Core's log line
   `core identity fingerprint=…`.
3. **Pair:** the app creates its keys and signs the pairing for that Core,
   that offer and this device; both sides show the same six digits.
4. **Configure:** name and firewall (dry run, MikroTik, OpenWrt), signed by
   the owner and applied by the Core immediately.

"Change Core" forgets the Core on this device and runs the wizard again.

## Keys

In the app's data directory for the desktop build and the demo:
`device.key` (Ed25519, transport identity), `owner.key` (P-256, owner
signatures), `epoch.key` (X25519, opens the record), `pinned.json` (the
Core's public keys), `core.json` (its id, last address and name). On Android
they move to the Keystore.

## Preview

Open `ui/index.html` in a browser: outside Tauri it loads `ui/preview.js`
with sample data (`?wizard` starts in the activation). Inside the app that
file is never loaded.

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

## Preview

Open `ui/index.html` directly in a browser: outside Tauri it loads
`ui/preview.js` with sample data, so the design can be reviewed without a Core.
Inside the app that file is never loaded.

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
