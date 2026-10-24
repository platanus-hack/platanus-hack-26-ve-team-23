# Security Policy

HAWK is a hackathon prototype for monitoring AI agents. It has not been
audited. Do not rely on it to contain a hostile agent in production.

## Reporting a vulnerability

Report it privately through GitHub: **Security** tab, then **Report a
vulnerability**. Include what an attacker could do, steps to reproduce on a
local setup, and whether you believe it is being exploited.

**Do not open a public issue for a security report.**

## Scope

In scope: `agent-hook`, `guardian`, `witness` and `eval` in this repository.
Out of scope: OpenCode, Ollama and other third-party software (report those
upstream).

## Known, declared limitations

These are documented trade-offs, not open reports. See
[docs/WHITEPAPER.md](docs/WHITEPAPER.md) for the threat model.

- An agent with root on the PC can change the firewall, talk to Ollama
  directly and stop the hook. HAWK detects the bypass when the proxy and the
  hook disagree, and keeps what was recorded before, but does not prevent it.
- Actions the agent takes without a tool call are not seen.
- The small monitor misses some multi-step attacks; the measured rate is
  published with the evaluation results.
- In the personal edition, someone holding the unlocked phone can read the
  record.
- If the owner keeps the passkey in a synced password manager (for example
  Google), a compromise of that account is a compromise of the owner
  credential. Erased weeks stay unreadable, because epoch keys are never
  derived from the passkey.
- A company that controls the Guardian and every phone can rewrite the
  record; public anchoring is a future option, not implemented.
