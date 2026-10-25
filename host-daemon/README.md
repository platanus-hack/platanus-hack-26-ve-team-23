# host-daemon

Runs on every monitored machine (ADR-0015). It relays the agent hook to the
Core, serves the OpenAI-compatible proxy for OpenCode on loopback, and has no
user interface except the identification notice.

- **Status:** loopback HTTP for the OpenCode plugin on `HOST_DAEMON_ADDR`
  (default `127.0.0.1:7070`, loopback enforced); QUIC with mutual TLS to the
  Core with its own Ed25519 identity (`host.key`); Core discovery by mDNS or
  `GUARDIAN_CORE`; Core identity pinned (`GUARDIAN_CORE_ID`, or the first
  Core it talks to, stored in `core.pin`); identification notice; the
  OpenAI-compatible LLM proxy that forwards to Ollama and relays a copy of
  each exchange to the Core; the signed heartbeat answering the Core's
  challenge. On Windows `host.key` is sealed by the TPM through the
  Platform Crypto Provider (`seal.rs`; `HAWK_TPM=0` turns it off); an
  existing key is sealed in place with the same identity. Pending: signing
  with a TPM-resident key, the measured-boot quote and Linux sealing (see
  ADR-0021).

## The heartbeat (ADR-0021)

The Core challenges the daemon (`HeartbeatChallenge { nonce }`) and the daemon
answers with a signed `Heartbeat { nonce, counter, digest, signature, boot }`:
a monotonic counter (persisted in `heartbeat.counter`), the digest of the tool
calls it relayed since the previous heartbeat, and its boot measurement. On
Linux the boot measurement is the SHA-256 digest of the first PCRs read from
the TPM driver (`tpm.rs`); without a TPM it is absent. The key is the daemon's
Ed25519 identity.

## The LLM proxy (ADR-0004)

OpenCode points its model base URL at this daemon (`/v1/…` and `/api/…` are
proxied). The daemon forwards to Ollama (`OLLAMA_URL`, default
`http://127.0.0.1:11434`), streams the answer back unchanged, and after each
response sends a `ProxyRecord` to the Core over QUIC. The plugin must send the
model's tool-call id as `call_id` (from `input.callID`) so the Core can
cross-check the two.

## Claude Code and Codex (ADR-0034)

Both agents run a `PreToolUse` command hook before every tool call. This
binary is that hook:

| Command | What it does |
|---|---|
| `hawk-host-daemon hook claude` / `hook codex` | Reads the call on stdin, normalises it (`Bash`, `exec_command`, Windows `PowerShell` → `bash`; `Write`, `Edit`, `apply_patch` → `write`/`edit` with `path`; …), asks this daemon (`HOST_DAEMON_URL`, default `http://127.0.0.1:7070`) and exits 2 to block. Any failure blocks. |
| `hawk-host-daemon hooks install [claude\|codex]` | Registers the hook in `~/.claude/settings.json` (with `"onFailure": "block"`) and `~/.codex/hooks.json`, keeping every other setting and a `.hawk-backup` of the first version. Codex asks to approve the hook once (`/hooks`). |
| `hawk-host-daemon hooks uninstall` / `hooks status` | Removes only HAWK's entry / says whether each agent is watched. |

`install.sh` runs `hooks install` for the agents it finds, as the agent's
user. The session sent to the Core starts with `claude:` or `codex:`, so the
record says which agent acted.

## Identification notice

When the owner presses "Identify" for this machine in the app, the Core asks
the daemon over the existing QUIC connection to show itself. The daemon shows
a notice with the Core's name, the hostname and this machine's fingerprint
(`msg` on Windows, `notify-send` or `wall` on Linux, a notification on macOS)
and logs it. Values from the network are sanitised and passed as one
argument, never through a shell.

## Configuration

`HOST_DAEMON_ADDR`, `HOST_DAEMON_DATA_DIR` (default `./host-daemon-data`),
`GUARDIAN_CORE`, `GUARDIAN_CORE_ID`, `OLLAMA_URL`, `RUST_LOG`. At start it
logs `host identity fingerprint=… hostname=…`.

## What it must never do

- Decide on its own, or allow when the Core cannot be reached.
- Listen on anything other than loopback.
- Talk to a Core whose identity is not the pinned one.
- Run as the same user as the agents.

## Tests

`cargo test -p host-daemon` (relay against a QUIC stand-in Core, wrong
identity refused, no Core, malformed calls, notice sanitising).
