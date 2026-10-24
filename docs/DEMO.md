# Demo script (90 seconds)

The demo shows the thesis on the table: three devices, and a monitor the
agent cannot reach.

## Setup

- PC: OpenCode with the model from ADR-0009, base URL pointing to the Pi.
- Pi: Guardian running, connected to the PC and to the phone.
- Phone: witness view open.
- Screen: OpenCode, the Guardian event log, and the phone mirrored.

## Steps

1. **Normal task.** OpenCode completes a small coding task. The phone shows a
   new signed head.
2. **Injected task.** A file the agent reads contains a prompt injection.
   The agent tries to delete its log and send a secret over the network. The
   Guardian denies both; the phone shows the alert.
3. **Bypass attempt.** The agent tries to disable the hook. The proxy saw a
   tool call the hook never asked about; the cross-check raises an evasion
   alert.
4. **Audit.** The owner opens the record with the two keys and the verifier
   confirms the chain matches the heads on the phone.
5. **Results.** The metrics table from the evaluation (ADR-0010).

## Fallback

If live inference fails, replay a recorded session through the proxy; say so
on stage.
