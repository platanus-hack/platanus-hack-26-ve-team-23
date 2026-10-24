// Sample data for reviewing the design in a plain browser (open
// ui/index.html directly; add ?wizard to start in the activation wizard).
// Loaded by app.js only when Tauri is absent.
(() => {
  const now = Date.now();
  const hosts = [
    { id: "a1".repeat(32), fingerprint: "3f9a-0c1d-77e2-b410", address: "10.0.0.7", hostname: "dev-ana", os: "linux" },
    { id: "b2".repeat(32), fingerprint: "c04e-91aa-5d3b-08f7", address: "10.0.0.9", hostname: "dev-luis", os: "windows" },
    { id: "c3".repeat(32), fingerprint: "7b21-e6c9-1f08-a3d5", address: "10.0.0.12", hostname: "ci-runner-02", os: "linux" },
  ];
  const tools = ["bash", "read", "edit", "write", "grep", "webfetch"];
  const rules = [
    ["guardian.hook.edit", "critical"],
    ["workspace.outside", "high"],
    ["logs.truncate", "high"],
    ["net.unusual-destination", "medium"],
    ["secrets.read", "high"],
  ];
  let seed = 7;
  const rand = () => (seed = (seed * 16807) % 2147483647) / 2147483647;

  const events = [];
  let seq = 0;
  for (let t = now - 60 * 60_000; t < now; t += 9_000 + rand() * 20_000) {
    const host = hosts[Math.floor(rand() * hosts.length)].address;
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

  let paired = !location.search.includes("wizard");
  let name = "Lab Core";
  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  window.__TAURI__ = {
    core: {
      invoke: async (cmd, args) => {
        switch (cmd) {
          case "app_info":
            return {
              version: "0.1.0-preview",
              device_fingerprint: "9e4d-22b1-c8f0-5a17",
              core: paired ? { id: "ff".repeat(32), fingerprint: "d2c7-4a90-e15b-63f8", name } : null,
            };
          case "discover":
            await wait(900);
            return [
              { id: "ff".repeat(32), fingerprint: "d2c7-4a90-e15b-63f8", name: "hawk-5c1f2a", state: "unpaired", address: "192.168.88.20:7443" },
              { id: "ee".repeat(32), fingerprint: "08b3-f71e-2c64-9ad0", name: "Office Core", state: "active", address: "192.168.88.31:7443" },
            ];
          case "pair_core":
            await wait(700);
            return { confirmation_code: "482917", fingerprint: "d2c7-4a90-e15b-63f8" };
          case "configure_core":
            name = args.name;
            paired = true;
            return name;
          case "identify_host":
            await wait(400);
            return null;
          case "forget_core":
            paired = false;
            return null;
          case "dashboard":
            return {
              reachable: true, error: null, paired_here: true, identity_matches: true,
              status: { paired: true, events: seq, head: heads.at(-1).head, last_signed_seq: heads.at(-1).seq, name, firewall: "dry-run" },
              events,
              hosts: hosts.map((h, i) => ({ ...h, connected: i !== 2, last_seen_ms: now - i * 45_000 })),
              heads_total: heads.length, heads_invalid: 0, heads,
            };
          default:
            throw new Error(`preview: ${cmd} not available`);
        }
      },
    },
  };
})();
