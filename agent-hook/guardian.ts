// OpenCode plugin: asks the host daemon before every tool call (ADR-0004,
// ADR-0015). A thin shim with no logic: it forwards the call and obeys the
// answer. Anything other than an explicit "allow" blocks the tool.
//
// Install: copy this file to `.opencode/plugin/` in the project, or to
// `~/.config/opencode/plugin/` for every project. The daemon address comes
// from HOST_DAEMON_URL (default http://127.0.0.1:7070).

type Decision =
  | { decision: "allow" }
  | { decision: "deny"; reason: string }
  | { decision: "ask"; reason: string };

type ToolInput = { tool: string; sessionID: string; callID: string };
type ToolOutput = { args: unknown };
type PluginContext = { directory: string };

const DAEMON = process.env.HOST_DAEMON_URL ?? "http://127.0.0.1:7070";
// Longer than the owner's 60 s to answer an "ask" (ADR-0022).
const TIMEOUT_MS = 70_000;

async function decide(call: object): Promise<Decision> {
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

export const GuardianPlugin = async ({ directory }: PluginContext) => ({
  "tool.execute.before": async (input: ToolInput, output: ToolOutput) => {
    const answer = await decide({
      session: input.sessionID,
      tool: input.tool,
      args: output.args ?? {},
      cwd: directory,
      call_id: input.callID,
    });
    if (answer.decision !== "allow") {
      const reason = "reason" in answer ? answer.reason : "denied";
      throw new Error(`Blocked by HAWK: ${reason}`);
    }
  },
});
