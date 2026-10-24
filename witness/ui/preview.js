// Sample data for reviewing the design in a plain browser (open
// ui/index.html directly). Loaded by app.js only when Tauri is absent.
(() => {
  const now = Date.now();
  const hosts = ["10.0.0.7", "10.0.0.9", "10.0.0.12"];
  const tools = ["bash", "read", "edit", "write", "grep", "webfetch"];
  const rules = [
    ["guardian.hook.edit", "critical"],
    ["workspace.outside", "high"],
    ["logs.truncate", "high"],
    ["net.unusual-destination", "medium"],
    ["secrets.read", "high"],
  ];
  let seed = 7;
  const rand = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);

  const events = [];
  let seq = 0;
  for (let t = now - 60 * 60_000; t < now; t += 9_000 + rand() * 20_000) {
    const host = hosts[Math.floor(rand() * hosts.length)];
    const r = rand();
    const decision = r < 0.82 ? "allow" : r < 0.9 ? "ask" : "deny";
    const rule = decision === "allow" ? null : rules[Math.floor(rand() * (decision === "ask" ? 5 : 4))];
    events.push({
      seq: seq++, timestamp_ms: Math.round(t), kind: "decision", session: `s-${host.slice(-2)}`,
      tool: tools[Math.floor(rand() * tools.length)], decision,
      rule: rule ? rule[0] : null, severity: rule ? (decision === "ask" ? "medium" : rule[1]) : null,
      reason: null, host,
    });
    if (rule && rule[1] === "critical" && decision === "deny") {
      events.push({
        seq: seq++, timestamp_ms: Math.round(t) + 300, kind: "containment", session: null, tool: null,
        decision: null, rule: null, severity: "critical", reason: "contained", host,
      });
    }
  }
  const heads = [];
  for (let s = 9; s < seq; s += 10) {
    heads.push({
      seq: s, timestamp_ms: events[Math.min(s, events.length - 1)].timestamp_ms,
      head: Array.from({ length: 64 }, (_, i) => "0123456789abcdef"[(s * 7 + i * 13) % 16]).join(""),
      valid: true,
    });
  }

  window.__TAURI__ = {
    core: {
      invoke: async (cmd) => {
        if (cmd === "app_info") return { version: "0.1.0-preview", paired_here: true };
        if (cmd === "dashboard") {
          return {
            reachable: true, error: null, paired_here: true, identity_matches: true,
            status: { paired: true, events: seq, head: heads.at(-1).head, last_signed_seq: heads.at(-1).seq },
            events, heads_total: heads.length, heads_invalid: 0, heads,
          };
        }
        throw new Error("preview: command not available");
      },
    },
  };
})();
