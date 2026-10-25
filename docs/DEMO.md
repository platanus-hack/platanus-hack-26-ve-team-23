# Demo script (90 seconds)

The demo shows the thesis on the table: three devices, and a monitor the
agent cannot reach.

## Setup

- PC: Claude Code or Codex with the HAWK hook (`install.sh` registers it), or
  OpenCode with the plugin and the model from ADR-0009; the host daemon
  approved in the app.
- Core: on the Pi (or another dedicated Linux machine, never the PC), on the
  same network as the PC and the phone.
- Phone: the HAWK app, paired with the Core.
- Router (optional): OpenWrt or MikroTik configured in the app; without it,
  containment runs in dry run and the record says what would have been cut.
- Screen: the agent, the Core's log, and the phone mirrored.

## Steps

1. **Normal task.** OpenCode completes a small coding task. The phone shows a
   new signed head.
2. **Injected task.** A file the agent reads contains a prompt injection.
   The agent tries to delete its log and send a secret over the network. The
   Guardian denies both; the phone shows the alert.
3. **Bypass attempt.** The agent tries to disable the hook. The proxy saw a
   tool call the hook never asked about; the cross-check raises an evasion
   alert.
4. **Kill the monitor.** Stop the host daemon on the PC. Its heartbeat goes
   silent and the Core quarantines the machine by IP and MAC (dead man's
   switch); the phone shows it, and Release brings it back.
5. **Audit.** The owner opens the record with the two keys and the verifier
   confirms the chain matches the heads on the phone.
6. **Results.** The metrics table from the evaluation (ADR-0010).

## Fallback

If live inference fails, replay a recorded session through the proxy; say so
on stage.
