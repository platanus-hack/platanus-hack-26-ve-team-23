---
version: alpha
name: HAWK
description: |
  Grey and black, nothing else. A light grey ground with black ink, and
  "night" surfaces (near-black) for anything that is a live machine: the
  agent console, the install band, the phone. One typeface, Saira, whose
  width axis carries the personality: expanded and heavy for display,
  normal width for reading. Square corners everywhere except the phone and
  its app. The mark is a V that is thick at the tips and narrows to a point
  (B2, "Plumas"). Format follows awesome-design-md (VoltAgent).

colors:
  ground: "#E4E5E1"        # page
  raised: "#D6D7D3"        # filled panels, list rows, secondary buttons
  sunk: "#CACBC6"          # pressed and hover on raised; board parts
  ink: "#111214"           # text, primary buttons, the mark
  ink-2: "#4E5155"         # secondary notes only (running text stays ink)
  line: "#B9BAB5"          # board outline in the drawing; no UI rules
  night: "#141516"         # console, install band, phone body
  night-2: "#222427"       # bars and code blocks on night
  night-3: "#3A3D41"       # "ask" verdict
  night-ink: "#ECEDEA"     # text on night
  night-ink-2: "#A0A4A9"   # secondary text on night
  app-screen: "#F2F2EF"    # phone app background
  app-panel: "#E6E6E2"     # phone app panels

typography:
  family: Saira (Google Fonts, variable wdth 50..125, wght 100..900)
  code: JetBrains Mono, only for literal code (commands, tool calls, fingerprints)
  display-1: { size: "clamp(46px, 6.8vw, 96px)", weight: 640, wdth: 116, tracking: -0.03em, leading: 0.96 }
  display-2: { size: "clamp(34px, 4.8vw, 72px)", weight: 640, wdth: 116, tracking: -0.03em, leading: 0.96 }
  statement: { size: "clamp(22px, 2vw, 30px)", weight: 560, wdth: 108, tracking: -0.01em, leading: 1.2 }
  lede: { size: "clamp(18px, 1.45vw, 21px)", weight: 400, wdth: 100, leading: 1.55 }
  body: { size: 18px, weight: 400, wdth: 100, leading: 1.55 }
  small: { size: 15px }
  wordmark: { size: 19px, weight: 760, wdth: 125, tracking: 0.06em, case: upper }
  rules:
    - Headlines stay at two lines or fewer at every width.
    - Five sizes on a page at most.
    - No uppercase micro labels, no eyebrows above headings.

layout:
  grid: 12 columns, 24px gap, max 1320px
  margin: "clamp(16px, 4vw, 48px)"
  section-gap: "clamp(120px, 14vw, 208px)"
  section-head: heading in columns 1-7, lede in 8-12, bottom aligned
  separation: tone steps (4px gaps between raised rows), never hairlines or shadows

components:
  button-primary: { bg: ink, fg: ground, height: 54px, padding: "0 24px", radius: 0, weight: 600 }
  button-plain: { bg: raised, fg: ink, radius: 0 }
  nav: wordmark, up to five plain links, one filled action ("Instalar")
  console: night surface; verdicts are chips
  verdicts:
    allow: { label: Permitido, fg: night-ink, bg: night-2 }
    ask: { label: Te pregunta, fg: night-ink, bg: night-3 }
    deny: { label: Denegado, fg: night-ink, outline: "1.5px night-ink" }
    contain: { label: Aislado, fg: night, bg: night-ink, also: "console gets a 2px night-ink outline; network label reads Máquina aislada" }
  code-block: { bg: night-2, fg: night-ink, font: code, copy button: night-ink fill }
  phone-app: radius 36px screen, 18px panels, pill buttons; the only rounded things

mark:
  name: B2 Plumas
  path: "M0 0 L24 5 L30 22 L36 5 L60 0 L30 36 Z"   # viewBox 0 0 60 36
  files: hawk-mark.svg (ink), hawk-mark-light.svg (night-ink)
  clear-space: half the mark's height on every side
  never: color it, outline it, put it in a gradient

imagery:
  - One 3D model of a Raspberry Pi 4, drawn in code with the real board's measurements (hawk-pi.js, three.js), always in HAWK greys (matte PCB and parts in the grey ramp, ink-coloured silicon, no hue). It sits behind the page at 13% to 56% opacity so it reads as a board but never competes with the text, and moves to a different angle per section. Four parts carry labels (radio, processor, Ethernet, microSD) that follow the model.
  - The "Cabe en una mano" section holds the same model as an explorer (pi-explorer.js): drag to turn, pinch or wheel to zoom, buttons to pick a part or explode it.
  - Fallbacks: without WebGL, or when the file is opened in a way that blocks ES modules, the page shows the flat SVG board drawing instead (class no-3d). With reduced motion the model jumps between poses and neither drifts nor follows the pointer.
  - The phone shows the real app (app/, a copy of witness/ui made by sync-app.sh) in an iframe with sample data; it can be tapped.
  - Diagrams are drawn in SVG with the same tokens.
  - Never show a made-up "product box". No photographs.

motion:
  ease: "cubic-bezier(.16, 1, .3, 1)"
  signature: on load, current runs through the drawn board (the SVG fallback) to the four parts, then their labels appear
  sections: parts arrive in order (heading, text, picture), 22px rise, 80ms stagger, once
  model: eases between section poses (about 1 s), opacity follows each section; never hides text
  stream: decisions scroll under the hero, 48s loop
  reduced-motion: everything visible, no travel, the stream wraps and stops
