// OpenCode plugin: asks the host daemon before every tool call (ADR-0004,
// ADR-0015). A thin shim with no logic: it forwards the call and obeys the
// answer. Anything other than an explicit "allow" blocks the tool.
//
// One default export works with both plugin APIs of OpenCode: V1 calls
// `server()` and uses the hooks it returns; V2 (1.19 and later) reads `id`
// and `setup()` and ignores `server()`.
//
// Install: copy this file to `.opencode/plugins/` in the project, or to
// `~/.config/opencode/plugins/` for every project (one copy only: a second
// copy asks twice). The daemon address comes from HOST_DAEMON_URL (default
// http://127.0.0.1:7070).

type Decision =
  | { decision: "allow" }
  | { decision: "deny"; reason: string }
  | { decision: "ask"; reason: string };

type Call = {
  session: string;
  tool: string;
  args: unknown;
  cwd: string;
  call_id?: string;
};

const DAEMON = process.env.HOST_DAEMON_URL ?? "http://127.0.0.1:7070";
// Longer than the owner's 60 s to answer an "ask" (ADR-0022).
const TIMEOUT_MS = 70_000;

async function decide(call: Call): Promise<Decision> {
  try {
    const response = await fetch(`${DAEMON}/decide`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(call),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!response.ok) {
      return { decision: "deny", reason: `daemon answered ${response.status}` };
    }
    return (await response.json()) as Decision;
  } catch {
    return { decision: "deny", reason: "host daemon unreachable" };
  }
}

// Throws unless the answer is an explicit "allow": throwing stops the tool.
async function enforce(call: Call): Promise<void> {
  const answer = await decide(call);
  if (answer.decision !== "allow") {
    const reason = "reason" in answer ? answer.reason : "denied";
    throw new Error(`Blocked by HAWK: ${reason}`);
  }
}

export default {
  id: "hawk",

  // V1: the hooks object.
  server: async ({ directory }: { directory: string }) => ({
    "tool.execute.before": async (
      input: { tool: string; sessionID: string; callID: string },
      output: { args: unknown },
    ) =>
      enforce({
        session: input.sessionID,
        tool: input.tool,
        args: output.args ?? {},
        cwd: directory,
        call_id: input.callID,
      }),
  }),

  // V2: register the same check before every tool execution.
  async setup(ctx: any) {
    const cwd: string = ctx?.directory ?? ctx?.worktree ?? process.cwd();
    await ctx.tool.hook("execute.before", async (event: any) =>
      enforce({
        session: String(event?.sessionID ?? event?.session?.id ?? "opencode"),
        tool: String(event?.tool ?? ""),
        args: event?.input ?? event?.args ?? {},
        cwd,
        call_id: event?.callID ?? event?.id,
      }),
    );
  },
};
