# ADR-0031: The owner app's design, information structure and UI contract

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23 (approval pending)

## Context

ADR-0013 fixes the technology of the owner app (Tauri 2, plain HTML, CSS and
JavaScript, logic in Rust commands) and sketches its look: a dark dashboard.
The Rust side has since grown to twelve commands (ADR-0017, ADR-0024,
ADR-0028, ADR-0029, ADR-0030), and the app has to present what they return
honestly: a Core that is out of reach, a Core whose identity changed, heads
that do not verify and a Core paired with another device are different
situations and must not look alike.

Two things were missing:

- A written structure for the screens, so the UI follows the commands and
  not the other way round.
- A visual identity. The project is now called HAWK, with a grey and black
  identity and the "Plumas" mark, and the app must look like the product the
  landing page presents.

## Options considered

### Option 1: keep a dark-only dashboard with colour for status

- Benefits: the usual look of an observability tool.
- Drawbacks: status carried by colour alone fails colour-blind owners and
  mixes with the brand; a dark-only screen is hard to read outdoors on a
  phone.

### Option 2: grey and black identity, light and dark, status by shape and word

- Benefits: one identity from the landing page to the app; every state has a
  glyph, a shape and a word, so it never depends on colour; follows the
  system theme.
- Drawbacks: no red/green shortcut, so the hierarchy has to come from tone,
  weight and position.

## Decision

Option 2. The app is one HTML page with five sections and an activation
flow, built only from the twelve commands of `witness/src/commands.rs`.

### Key points

- **Five sections, one job each.** Overview (is HAWK working, what is asked
  of me), Machines (who is watching, who is contained), Events (what was
  decided), Record (is the history intact, open the sealed record) and
  Settings (this Core, this device, appearance, forget the Core). A rail on
  wide windows and a tab bar on phones carry the same five entries, with
  badges for pending asks and machines waiting for approval.
- **The first screen is the activation** while no Core is paired (ADR-0017,
  ADR-0024): find, verify the fingerprint, pair with the six digit code,
  configure. A configuration saved from Settings uses the same form.
- **One state, many words.** `deriveState` reduces the dashboard to one of
  these states, each with its own title, glyph and sentence: connecting,
  active, dormant (the Core answers but is not paired and denies
  everything), unreachable, identity differs from the pinned one, heads do
  not verify, and paired with another device. When the Core is unreachable
  but a good reading exists, the last data stays on screen, dimmed and
  dated (stale); it is never shown as current. Contained machines are part
  of the active state (a count, a card with Release), not a separate state.
- **Never hide a failure.** A containment that the firewall refused
  (`containment_failed` in the event) is shown as a failure, not as a
  contained machine. A pending approval whose HWID conflicts with a known
  machine disables Approve and shows the Core's reason in the app's
  language.
- **Status is never colour alone.** Verdicts are chips with a glyph and a
  word: allow (neutral), ask (filled mid-grey, question mark), deny (outline,
  cross), contain (inverted, ban). Severity is a four step meter with a word.
  The chart uses fills, a hatch for asks and a table view for the same data.
- **Palette and type.** Light: ground #F2F2EF, panels #E6E6E2, ink #111214.
  Dark: ground #141516, panels #222427, ink #ECEDEA. The theme follows the
  system and can be set to light or dark; the choice is kept in the web
  view's local storage and the app works without it. One family (Saira) for
  everything; JetBrains Mono only for literal values (fingerprints, hashes,
  tool calls). Panels are separated by tone, with no shadows or hairlines.
- **Language.** Spanish and English, same keys, same placeholders;
  `witness/tools/audit-i18n.js` fails when a key is missing or differs. Text from the
  network (host names, tools, rules, reasons) is inserted with `textContent`
  and shown as the Core wrote it, except the Core's two fixed conflict
  sentences, which are translated.
- **No external resources and no chart library.** Fonts are files in
  `ui/fonts`; charts are drawn in SVG by `ui/chart.js`. The content security
  policy of `tauri.conf.json` is unchanged (no inline script, no remote
  origin).
- **Accessibility as a test.** axe-core (WCAG 2.1 AA and best practice) must
  report no violations on every section, in both themes and both languages;
  primary actions are at least 44 px high; reduced motion is respected; every
  control is reachable by keyboard; the chart has a table alternative.
- **Preview mode.** Outside Tauri, `ui/preview.js` answers the same twelve
  commands with data whose fields are exactly those of the Rust structs
  (`Dashboard`, `HostInfo`, `PendingAsk`, `HeadView`, `RecordView`,
  `Discovered`, `PairResult`, `AppInfo`). Scenarios (`?s=normal`, `quiet`,
  `dormant`, `offline`, `stale`, `identity`, `heads`, `elsewhere`, `wizard`,
  `wizard-empty`) cover the states above. Inside the app the file is never
  loaded.
- **Keys never reach the web view** (ADR-0013): the UI holds no key, signs
  nothing and verifies nothing; it displays what the commands return.

## Dependencies and licences

| Dependency | Version | Licence |
|---|---|---|
| Saira (variable font file, shipped in `ui/fonts`) | latin, wdth axis | OFL-1.1 |
| JetBrains Mono (variable font file, shipped in `ui/fonts`) | latin, wght axis | OFL-1.1 |

No Rust crate and no JavaScript package is added. OFL-1.1 is allowed for
font files by ADR-0011 (v1.2): it allows bundling and commercial use as long
as the licence text travels with the files (the `*-OFL.txt` files sit next to
them) and the fonts are not sold on their own.

## Consequences

### Positive

- The app and the landing page are one identity.
- Every Core state has its own look, so an owner cannot read "unreachable" as
  "safe".
- The UI can be reviewed in a browser without a Core, with data the real
  structs can produce.

### Tradeoffs

- No red and green: urgency comes from tone, position and the words.
- Two languages to keep in step (checked by the audit script).
- The mock in `preview.js` must follow `commands.rs`; the audit of field
  names is manual for now.
- Revisit if a third language or an iOS build is added.

## Implementation

### Where it lives

- `witness/ui/index.html`: structure, icons (sprite), activation, sheet.
- `witness/ui/style.css`: tokens, layout, components, themes.
- `witness/ui/app.js`: state, rendering, the twelve commands.
- `witness/ui/i18n.js`, `kit.js`, `chart.js`: text, DOM helpers, the chart.
- `witness/ui/preview.js`: browser preview data and scenarios.
- `witness/tools/audit-i18n.js`: key audit (not shipped in the app).
- `witness/icons/`: the HAWK mark on a dark rounded square.

### Next steps

1. Build the Tauri app on desktop and Android and review the screens on the
   device (safe areas, system bars).
2. Add an automated browser test that runs the scenarios and axe in CI.
3. Publish the landing page in `misc/landing/`, which embeds this UI in a
   phone frame.

## Related decisions

- ADR-0013: technology of the app; this ADR refines its look and screens.
- ADR-0017, ADR-0024, ADR-0029: pairing, activation wizard, host approval.
- ADR-0022: fail closed; the app shows a denied state as denied.
- ADR-0023: links over QUIC with mutual TLS; the app has no HTTP.
- ADR-0027: offline first; the app needs no cloud.

## History

- v1.0 (2026-10-24): Initial proposal.
- v1.1 (2026-10-24): Font licence settled by ADR-0011 v1.2; the landing
  page lives in `misc/landing/`.
