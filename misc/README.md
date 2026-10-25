# misc

Internal material that is not part of the product, the crates or the
hackathon submission.

| Folder | What it is |
|---|---|
| `landing/` | The HAWK landing page: 3D Raspberry Pi (three.js), part explorer, the real app in a phone frame, and the host daemon installer (`install.sh`). Design tokens and rules in `landing/DESIGN.md`. |

## Landing

    cd misc/landing && python3 -m http.server 8765

Open http://localhost:8765. It needs a server: the 3D modules do not load
from `file://`. `landing/app/` is a copy of `witness/ui` made by
`./sync-app.sh`; run it after every change to the app so the phone shows the
current UI. `logo-v.html` is a design scratch page and loads Saira from Google
Fonts; the landing itself uses the local font files.

Third-party files: three.js and its addons in `landing/vendor/` (MIT,
`three-LICENSE.txt`), Saira and JetBrains Mono in `landing/fonts/` (OFL-1.1,
allowed for font files by ADR-0011).

Published on Render as the static site `hawk-landing`
(`infra/render/render.yaml`, see `infra/README.md`). Its build runs
`fetch_downloads.py`, which copies the GitHub releases into `downloads/`
(ignored by git) and checks them against `SHA256SUMS` (ADR-0032).

Open items (creating the Render service, the release the installer downloads, signing
`SHA256SUMS`): `docs/ROADMAP.md`, M13 and M14.
