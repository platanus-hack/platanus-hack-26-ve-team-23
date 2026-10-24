# ADR-0032: Continuous integration, releases and public downloads

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Javier Hernandez, team-23 (approval pending)

## Context

Every check (`just check`, `just audit`, the i18n audit) ran only on the
developers' machines, and on the main development machine the Rust toolchain
is not even on the PATH. Nothing builds the binaries people install.

The landing page (`misc/landing`, on Render) offers a one-line installer for
the host daemon. `install.sh` downloads a release archive and its
`SHA256SUMS`, but the code lives in a private repository: its GitHub releases
cannot be downloaded without a session, so the installer cannot work. The
owner app and the Core also have no downloadable build.

Constraints: the repository stays private until the team decides what to
publish (CLAUDE.md); no secret in the repository; licences of ADR-0011; the
product itself must never depend on the cloud (ADR-0027), so downloads are a
distribution channel, not a runtime dependency.

## Options considered

### Option 1: make the repository, or a mirror of the releases, public

- Benefits: GitHub serves the files; nothing to host.
- Drawbacks: publishing the code or a public mirror is a decision the team
  has not taken; a mirror is one more repository to keep in step.

### Option 2: private GitHub releases, copied to the landing's static site at build time

CI builds and attaches every file to a release of the private repository.
The Render build of the landing reads those releases with a read-only token
and publishes them under `/downloads/`.

- Benefits: the code stays private; one source of truth (the release); the
  files are served over HTTPS from our own domain; a failed fetch fails the
  Render build, which keeps the previous deploy online.
- Drawbacks: a token with read access to the repository lives in Render; the
  landing must be redeployed after each release (a deploy hook from CI).

### Option 3: an object store (S3, R2) for downloads

- Benefits: made for large files.
- Drawbacks: another account and credential; the landing already is a static
  host on the domain we want.

## Decision

Option 2.

### Key points

- **CI on every push and pull request** (`.github/workflows/ci.yml`): the
  same commands as the `justfile` (`cargo fmt --check`, clippy with warnings
  as errors, `cargo test --workspace`) on Linux, the tests again on macOS,
  `cargo deny check`, and the app's i18n audit. Read-only token permissions.
- **Release on a `v*` tag** (`.github/workflows/release.yml`), or by hand
  for a tag that already exists. The tag must equal the workspace version.
  It builds:
  - the host daemon for `x86_64-linux` and `aarch64-linux` (glibc 2.28,
    cross-compiled with cargo-zigbuild), `x86_64-windows`, and
    `aarch64-macos` and `x86_64-macos`;
  - the Core (`guardian`) for `aarch64-linux` (the Pi) and `x86_64-linux`;
  - the owner app for the desktop: `.deb` and AppImage (Linux), NSIS
    installer (Windows), a universal `.dmg` (macOS), signed and notarized
    when the `APPLE_*` secrets exist and ad-hoc signed otherwise;
  - the OpenCode plugin, published as `hawk-opencode-plugin.ts`
    (`guardian.ts` up to 0.1.1);
  - an Android APK, built in debug mode and marked experimental until the
    release keystore exists (ADR-0017 follow-up). Its job may fail without
    blocking the release.
- **Names are fixed** because `install.sh` depends on them:
  `hawk-<v>-<x86_64|aarch64>-<linux|macos>.tar.gz` (folder
  `hawk-<v>-<arch>-<os>/host-daemon`), `hawk-<v>-x86_64-windows.zip`,
  `hawk-core-<v>-<arch>-linux.tar.gz`, `hawk-witness-<v>-...`,
  `hawk-opencode-plugin.ts`, `SHA256SUMS`. `install.sh` checks the plugin
  against `SHA256SUMS` too, since it runs inside OpenCode.
- **Checksums now, signature when the key exists.** `SHA256SUMS` covers
  every file. If the repository secret `MINISIGN_SECRET_KEY` exists, CI also
  publishes `SHA256SUMS.minisig`; `install.sh` verifies it when its embedded
  public key is set and `minisign` is installed, and says plainly when it
  only checked the sums. A checksum served next to the file proves integrity,
  not origin; the installer never calls it a signature.
- **Downloads on the landing.** The Render build runs
  `misc/landing/fetch_downloads.py`, which copies every release into
  `downloads/v<version>/` and writes `downloads/index.html` and
  `downloads/latest.json`. It needs `GITHUB_TOKEN` in the Render service
  (fine-grained, read-only "Contents" on this repository only). Without the
  token the landing deploys with no downloads; with a token, any error fails
  the build so Render keeps the previous deploy. CI calls the landing's
  deploy hook (`RENDER_DEPLOY_HOOK_LANDING`) after publishing a release.
- **No secret in the repository**: tokens, the deploy hook and the minisign
  key are GitHub or Render secrets set by the owner.
- **Supply chain.** Only first-party GitHub actions and two widely used ones
  (rust toolchain, cargo-deny); zig and cargo-zigbuild come from PyPI at a
  pinned version. Pinning actions by commit is the next step.

## Dependencies and licences

Build tools only; nothing is linked into the product.

| Dependency | Version | Licence |
|---|---|---|
| actions/checkout, actions/cache, actions/upload-artifact, actions/download-artifact, actions/setup-java | v4 | MIT |
| dtolnay/rust-toolchain | master | MIT OR Apache-2.0 |
| EmbarkStudios/cargo-deny-action | v2 | MIT OR Apache-2.0 |
| cargo-zigbuild (PyPI, brings ziglang) | latest (0.19 rejected an aarch64 linker flag) | MIT |
| tauri-cli (cargo install, Android job) | 2 | MIT OR Apache-2.0 |
| ziglang | as required by cargo-zigbuild | MIT |
| @tauri-apps/cli (npx) | 2 | MIT OR Apache-2.0 |
| minisign (optional, Ubuntu package) | distro | ISC |

## Consequences

### Positive

- Every change runs the checks that today depend on one machine.
- `curl -fsSL https://<landing>/install.sh | sh` works without making the
  code public.
- One place to download the daemon, the Core, the app and the plugin.

### Tradeoffs

- Actions minutes on a private repository are metered and macOS minutes
  cost ten times more; the team accepted the cost because macOS hosts and
  owners are common.
- On macOS `install.sh` installs the daemon binary only; a launchd service
  under its own user (the daemon must not run as the agent's user) is
  pending.
- The Render token can read the whole private repository, not only its
  releases (GitHub has no narrower scope); it is read-only and lives only in
  Render.
- Revisit when the repository becomes public (GitHub releases can then be
  linked directly) or when the APK gets a release keystore.

## Implementation

### Where it lives

- `.github/workflows/ci.yml`, `.github/workflows/release.yml`.
- `misc/landing/fetch_downloads.py`: Render build step.
- `misc/landing/install.sh`: download base and verification.
- `infra/render/render.yaml`: build command and the `GITHUB_TOKEN` variable.

### Next steps

1. Owner: create the fine-grained token and set it in Render; copy the
   landing's deploy hook to the GitHub secret `RENDER_DEPLOY_HOOK_LANDING`.
2. Generate a minisign key, keep the secret key in GitHub, embed the public
   key in `install.sh`.
3. Pin every action by commit hash.
4. Release keystore for the APK; Apple Developer ID certificate and
   notarization secrets; launchd service on macOS.

## Related decisions

- ADR-0011: licences; build tools are listed here but not shipped.
- ADR-0012, ADR-0013: what is built (workspace, Tauri app).
- ADR-0027: downloads are optional; nothing at runtime contacts them.
- ADR-0031: the app and the landing page.

## References

- `docs/standards/development-workflow.md`.
- `misc/landing/install.sh`.

## History

- v1.0 (2026-10-24): Initial proposal.
- v1.1 (2026-10-24): macOS added (daemon for both architectures, universal
  `.dmg`, tests in CI), at the team's request.
- v1.2 (2026-10-24): cargo-zigbuild unpinned (0.19 failed to link aarch64
  with current rustc); the Android job uses `cargo tauri` instead of npx.
- v1.3 (2026-10-24): the plugin is published as `hawk-opencode-plugin.ts`,
  checked against `SHA256SUMS` by the installer, and the downloads page
  says what each file is.
