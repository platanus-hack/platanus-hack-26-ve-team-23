// Display only: every value comes from a Rust command. Nothing is rendered
// with innerHTML; all text goes through textContent.
const { invoke } = window.__TAURI__.core;

const $ = (id) => document.getElementById(id);
const REFRESH_MS = 3000;
const WINDOW_MIN = 30;

let coreUrl = localStorage.getItem("coreUrl") || $("core-url").value;
$("core-url").value = coreUrl;
let last = null;

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function setState(text, kind) {
  const pill = $("state");
  pill.textContent = text;
  pill.className = `pill pill-${kind}`;
}

function showBanner(text) {
  const banner = $("banner");
  banner.hidden = !text;
  banner.textContent = text || "";
}

function render(d) {
  last = d;
  $("pairing").hidden = !(d.reachable && d.status && !d.status.paired && !d.paired_here);

  if (!d.reachable) {
    setState("core unreachable", "bad");
    showBanner(d.error);
    return;
  }

  const unpaired = !d.status.paired;
  if (unpaired) setState("unpaired: denying everything", "warn");
  else if (d.identity_matches === false) setState("identity changed", "bad");
  else if (d.heads_invalid > 0) setState("invalid heads", "bad");
  else setState("active", "ok");

  if (d.identity_matches === false) {
    showBanner("The Core's identity is not the one pinned at pairing. Do not trust this Core.");
  } else if (d.heads_invalid > 0) {
    showBanner(`${d.heads_invalid} signed head(s) do not verify against the pinned key.`);
  } else if (!unpaired && !d.paired_here) {
    showBanner("This Core is paired with another device: heads cannot be verified here.");
  } else {
    showBanner("");
  }

  const decisions = d.events.filter((e) => e.kind === "decision");
  const count = (v) => decisions.filter((e) => e.decision === v).length;
  $("t-total").textContent = decisions.length;
  $("t-allow").textContent = count("allow");
  $("t-deny").textContent = count("deny");
  $("t-ask").textContent = count("ask");
  $("t-contained").textContent = d.events.filter((e) => e.kind === "containment").length;
  $("t-heads").textContent = d.heads_total;
  $("t-heads-sub").textContent = d.heads_total
    ? `${d.heads_total - d.heads_invalid} valid, ${d.heads_invalid} invalid`
    : "";

  drawChart(decisions);
  drawRules(decisions);
  drawEvents();
  drawHeads(d.heads);
}

function drawChart(decisions) {
  const svg = $("chart");
  svg.replaceChildren();
  const now = Math.floor(Date.now() / 60000);
  const series = { allow: [], deny: [], ask: [] };
  for (const key of Object.keys(series)) series[key] = new Array(WINDOW_MIN).fill(0);
  for (const e of decisions) {
    const age = now - Math.floor(e.timestamp_ms / 60000);
    if (age >= 0 && age < WINDOW_MIN && series[e.decision]) series[e.decision][WINDOW_MIN - 1 - age] += 1;
  }
  const max = Math.max(1, ...Object.values(series).flat());
  const colors = { allow: "#3fb950", deny: "#f85149", ask: "#d29922" };
  const ns = "http://www.w3.org/2000/svg";
  for (const [key, values] of Object.entries(series)) {
    const points = values
      .map((v, i) => `${(i / (WINDOW_MIN - 1)) * 600},${130 - (v / max) * 120}`)
      .join(" ");
    const line = document.createElementNS(ns, "polyline");
    line.setAttribute("points", points);
    line.setAttribute("fill", "none");
    line.setAttribute("stroke", colors[key]);
    line.setAttribute("stroke-width", "2");
    svg.appendChild(line);
  }
  const axis = document.createElementNS(ns, "text");
  axis.setAttribute("x", "4");
  axis.setAttribute("y", "12");
  axis.setAttribute("fill", "#8b949e");
  axis.setAttribute("font-size", "11");
  axis.textContent = `max ${max}/min`;
  svg.appendChild(axis);
}

function drawRules(decisions) {
  const list = $("rules");
  list.replaceChildren();
  const counts = new Map();
  for (const e of decisions) if (e.rule) counts.set(e.rule, (counts.get(e.rule) || 0) + 1);
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  if (!top.length) {
    list.appendChild(el("li", "no rule has fired yet", "muted"));
    return;
  }
  const max = top[0][1];
  for (const [rule, n] of top) {
    const li = el("li");
    const bar = el("div", undefined, "bar");
    bar.style.width = `${(n / max) * 100}%`;
    li.append(bar, el("span", rule), el("span", String(n)));
    list.appendChild(li);
  }
}

function drawEvents() {
  const body = $("events");
  body.replaceChildren();
  if (!last) return;
  const decision = $("f-decision").value;
  const severity = $("f-severity").value;
  const text = $("f-text").value.trim().toLowerCase();
  const rows = last.events
    .filter((e) => !decision || e.decision === decision)
    .filter((e) => !severity || e.severity === severity)
    .filter((e) => !text || [e.host, e.session, e.tool, e.rule].some((v) => (v || "").toLowerCase().includes(text)))
    .slice(-200)
    .reverse();
  for (const e of rows) {
    const tr = el("tr");
    tr.append(
      el("td", new Date(e.timestamp_ms).toLocaleTimeString()),
      el("td", String(e.seq)),
      el("td", e.kind),
      el("td", e.host || ""),
      el("td", e.tool || ""),
      el("td", e.decision || "", e.decision || ""),
      el("td", e.severity || "", e.severity ? `sev-${e.severity}` : ""),
      el("td", e.rule || ""),
    );
    body.appendChild(tr);
  }
}

function drawHeads(heads) {
  const list = $("heads");
  list.replaceChildren();
  for (const h of [...heads].reverse()) {
    const li = el("li", `#${h.seq}  ${h.head}  ${h.valid ? "verified" : "INVALID"}`, h.valid ? "valid" : "invalid");
    list.appendChild(li);
  }
}

async function refresh() {
  try {
    render(await invoke("dashboard", { coreUrl }));
  } catch (err) {
    setState("error", "bad");
    showBanner(String(err));
  }
}

$("connect").addEventListener("submit", (event) => {
  event.preventDefault();
  coreUrl = $("core-url").value.trim();
  localStorage.setItem("coreUrl", coreUrl);
  refresh();
});

$("pair").addEventListener("click", async () => {
  $("pair").disabled = true;
  try {
    const result = await invoke("pair_core", { coreUrl });
    $("pair-result").textContent = `Paired. Confirm that the Core's log shows the code ${result.confirmation_code}.`;
  } catch (err) {
    $("pair-result").textContent = String(err);
  } finally {
    $("pair").disabled = false;
    refresh();
  }
});

for (const id of ["f-decision", "f-severity"]) $(id).addEventListener("change", drawEvents);
$("f-text").addEventListener("input", drawEvents);

refresh();
setInterval(refresh, REFRESH_MS);
