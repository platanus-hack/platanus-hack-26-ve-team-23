# witness

The owner's app: it controls the Core from the phone. One Tauri 2 crate
builds the Android APK and a desktop build used for development (ADR-0013).
Its design, screens and UI contract are in ADR-0031.

- **Status:** QUIC with mutual TLS to the Core with its own device identity
  (ADR-0023); activation wizard (find by mDNS, verify fingerprint, pair,
  configure); five screens (overview, machines, events, record, settings);
  every signed head verified against the identity pinned at pairing; machines
  listed by fingerprint, MAC and HWID with Identify, Approve and Release; the
  Record screen opens the sealed record, verifies the chain and decrypts it
  with the epoch key; pending `ask`s are answered with the owner's signature
  and alerts appear as a notice; Spanish and English; light and dark.
  Pending: Android Keystore, multicast lock and passkeys (see
  `PENDIENTES.md`).

## The five screens

| Screen | What it answers | Commands |
|---|---|---|
| Overview | Is HAWK working? What is asked of me? Decisions over time, the rules that fire most, the latest decisions | `dashboard`, `answer_ask` |
| Machines | Who is watching? Who waits for approval? Who is contained? | `dashboard`, `identify_host`, `approve_host`, `release_host` |
| Events | What was decided, with filters by outcome, severity and text | `dashboard` |
| Record | Is the history intact (heads verified against the pinned identity)? Open the sealed record | `dashboard`, `open_record` |
| Settings | This Core, this device, theme and language, change name, firewall or attention thresholds (ADR-0033), what HAWK does and does not do, forget the Core | `app_info`, `configure_core`, `forget_core` |

The state shown at the top is derived from the dashboard (active, dormant,
unreachable, identity differs, heads do not verify, paired with another
device). When the Core cannot be reached the last good reading stays on
screen, dimmed and dated. A containment the firewall refused is shown as a
failure.

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

## Build

| Output | Command | Needs |
|---|---|---|
| Desktop | `cargo run -p witness` | WebView2 (Windows) or WebKitGTK 4.1 (Linux) |
| APK | `cd witness && cargo tauri android build --apk` | Tauri CLI (`cargo install tauri-cli`), Android SDK and NDK; run `cargo tauri android init` once |

## How it connects

- **QUIC with mutual TLS 1.3 only.** There is no HTTP between the app and the
  Core (ADR-0023). The app pins the Core's key at pairing and compares keys,
  never addresses.
- **Discovery:** `discover` listens for the Core's mDNS announcements; the
  wizard also accepts an address typed by hand (`probe_core`).
- **Pairing:** `pair_core` signs the Core's offer with the owner key bound to
  that Core, that nonce and this device, sends the epoch public key and
  checks the six digit code both screens show (ADR-0017).
- **Dashboard:** `dashboard` reads the Core's state, events, hosts, pending
  asks and signed heads every three seconds. Heads are checked against the
  pinned key, never against what the Core claims now: a swapped Core fails
  every head.
- The owner and epoch keys are files in the app's data directory for the
  desktop build and the demo; on Android they move to the Keystore. They
  never reach the web view.

## Preview

Open `ui/index.html` directly in a browser, or serve the folder
(`python3 -m http.server` inside `ui/`): outside Tauri it loads
`ui/preview.js`, which answers the twelve commands with sample data whose
fields are those of the Rust structs. Inside the app that file is never
loaded.

| Query | Shows |
|---|---|
| `?s=normal` (default) | A busy Core: asks waiting, one machine contained, two to approve |
| `?s=quiet` | A paired Core with no activity |
| `?s=dormant` | The Core answers but is not paired: it denies everything |
| `?s=offline` | The Core is out of reach from the first call |
| `?s=stale` | Reachable once, then out of reach: the last data, dimmed |
| `?s=identity` | The Core's identity differs from the pinned one |
| `?s=heads` | Some signed heads do not verify |
| `?s=elsewhere` | The Core is paired with another device |
| `?s=wizard`, `?s=wizard-empty` | No Core paired, with and without discovered Cores |

Also `?lang=es|en`, `?theme=light|dark`, `?v=overview|hosts|events|record|settings`
and `?live` (adds a decision every few seconds).

## Checks

- `node tools/audit-i18n.js`: every text key used by the HTML and the scripts
  exists in Spanish and English, with the same placeholders.
- Accessibility: run axe-core (WCAG 2.1 AA and best practice) over the
  scenarios above in both themes; the last run had no violations.

## Layout

- `src/lib.rs`: `run()`, also the mobile entry point.
- `src/commands.rs`: the only functions the web view may call.
- `ui/index.html`: structure, icon sprite, activation, sheet.
- `ui/style.css`: tokens, layout, components, light and dark.
- `ui/app.js`: state, rendering and the twelve commands.
- `ui/i18n.js`, `ui/kit.js`, `ui/chart.js`: text, DOM helpers (`textContent`
  only), the SVG chart.
- `ui/preview.js`: browser preview data and scenarios.
- `tools/audit-i18n.js`: the text key audit (Node, not shipped).
- `ui/fonts/`: Saira and JetBrains Mono (SIL OFL 1.1, texts included).
- `icons/`: the HAWK mark on a dark rounded square.

## What it must never do

- Pass key material to the web view.
- Derive epoch keys from the mnemonic.
- Send any key to the Guardian or the PC.
- Put text that came from the network into the page as markup.
