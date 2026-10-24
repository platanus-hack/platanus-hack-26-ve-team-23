# Contributing

This page is the short version; the full standards are in
[`docs/standards`](docs/standards/README.md).

## Security issues

Never report them in public. Follow [SECURITY.md](SECURITY.md).

## The path of a change: document first

Code is the last step, not the first. Every change that alters behaviour,
design, the threat model, what the Guardian records or the set of
dependencies follows this path:

1. **RFC** ([`docs/rfcs`](docs/rfcs/README.md)), when the change needs
   discussion before anyone decides. Skip it when the decision is clear.
2. **ADR** ([`docs/adr`](docs/adr/README.md)): the decision, the options
   with their benefits and drawbacks, the consequences, and every new
   dependency with its licence.
3. **Code:** a pull request that implements the ADR and links it.
4. **Changelog:** an entry under `Unreleased` in [CHANGELOG.md](CHANGELOG.md).

Only fixes that restore documented behaviour and changes to the
documentation itself go straight to a pull request.

## Licences of dependencies

Only the licences allowed by
[ADR-0011](docs/adr/0011-dependency-licences.md): no GPL, LGPL or AGPL, no
non-commercial or custom model licences.

## Coding agents

Agents follow [AGENTS.md](AGENTS.md). You own every line you submit,
whatever tool produced it.
