// Display only: every value comes from a Rust command (ADR-0013). Untrusted
// strings from the Core (hosts, tools, rules) are inserted with textContent,
// never innerHTML.

const $ = (id) => document.getElementById(id);
const SVG = "http://www.w3.org/2000/svg";
const REFRESH_MS = 3000;
const BUCKETS = 30;
const OUTCOMES = [
  ["allow", "Allowed"],
  ["ask", "Asked"],
  ["deny", "Denied"],
];

let invoke;
let coreUrl = localStorage.getItem("coreUrl") || $("core-url").value;
let rangeMin = Number(localStorage.getItem("rangeMin") || 60);
let data = null;
let inFlight = false;

// Helpers ---------------------------------------------------------------------

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function svg(tag, attrs, className) {
  const node = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
  if (className) node.setAttribute("class", className);
  return node;
}

const fmt = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });
const timeFmt = (ms, withSeconds) =>
  new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: withSeconds ? "2-digit" : undefined });

function niceCeil(value) {
  if (value <= 4) return 4;
  const exp = 10 ** Math.floor(Math.log10(value));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * exp >= value) return m * exp;
  return 10 * exp;
}

function inRange(events) {
  const from = Date.now() - rangeMin * 60_000;
  return events.filter((e) => e.timestamp_ms >= from);
}

// State header -------------------------------------------------------------------

function setState(kind, text) {
  const state = $("state");
  state.dataset.kind = kind;
  state.querySelector(".status-icon").textContent = { good: "✓", warning: "!", critical: "✕" }[kind] || "•";
  state.querySelector(".status-text").textContent = text;
}

function showBanner(text) {
  $("banner").hidden = !text;
  $("banner").textContent = text || "";
}

// Render -------------------------------------------------------------------------

function render() {
  const d = data;
  if (!d) return;
  $("updated").textContent = `Updated ${timeFmt(Date.now(), true)}`;
  $("pairing").hidden = !(d.reachable && d.status && !d.status.paired && !d.paired_here);

  if (!d.reachable) {
    setState("critical", "Core unreachable");
    showBanner(d.error);
    return;
  }
  const paired = d.status.paired;
  if (!paired) setState("warning", "Unpaired: every action is denied");
  else if (d.identity_matches === false) setState("critical", "Core identity changed");
  else if (d.heads_invalid > 0) setState("critical", "Record integrity failed");
  else setState("good", "Core active");

  if (d.identity_matches === false) {
    showBanner("The Core's identity is not the one pinned at pairing. Do not trust its record.");
  } else if (d.heads_invalid > 0) {
    showBanner(`${d.heads_invalid} signed head(s) do not verify against the pinned identity.`);
  } else if (paired && !d.paired_here) {
    showBanner("This Core is paired with another device, so its heads cannot be verified here.");
  } else {
    showBanner("");
  }

  const events = inRange(d.events);
  const decisions = events.filter((e) => e.kind === "decision");
  const containments = events.filter((e) => e.kind === "containment");
  renderKpis(decisions, containments, d);
  renderChart(decisions);
  renderRules(decisions);
  renderHosts(events);
  renderEvents(events);
  renderIntegrity(d);
}

function renderKpis(decisions, containments, d) {
  const count = (v) => decisions.filter((e) => e.decision === v).length;
  $("k-blocked").textContent = fmt.format(count("deny"));
  $("k-blocked-sub").textContent = `in the last ${$("range").querySelector(".on").textContent}`;
  $("k-total").textContent = fmt.format(decisions.length);
  $("k-rate").textContent = `${(decisions.length / rangeMin).toFixed(1)} per minute`;
  $("k-ask").textContent = fmt.format(count("ask"));
  const hosts = new Set(containments.map((e) => e.host).filter(Boolean));
  $("k-contained").textContent = fmt.format(hosts.size);
  if (!d.paired_here) {
    $("k-integrity").textContent = "–";
    $("k-integrity-sub").textContent = "not paired with this app";
  } else if (d.heads_invalid > 0 || d.identity_matches === false) {
    $("k-integrity").textContent = "Failed";
    $("k-integrity-sub").textContent = `${d.heads_invalid} of ${d.heads_total} heads invalid`;
  } else {
    $("k-integrity").textContent = "Verified";
    $("k-integrity-sub").textContent = `${d.heads_total} signed heads`;
  }
}

function buckets(decisions) {
  const now = Date.now();
  const span = (rangeMin * 60_000) / BUCKETS;
  const start = now - rangeMin * 60_000;
  const out = Array.from({ length: BUCKETS }, (_, i) => ({ from: start + i * span, allow: 0, ask: 0, deny: 0 }));
  for (const e of decisions) {
    const i = Math.min(BUCKETS - 1, Math.floor((e.timestamp_ms - start) / span));
    if (i >= 0 && out[i][e.decision] !== undefined) out[i][e.decision] += 1;
  }
  return out;
}

function renderChart(decisions) {
  const chart = $("chart");
  const width = Math.max(320, chart.clientWidth || 600);
  const height = 220;
  const m = { top: 8, right: 4, bottom: 22, left: 34 };
  const plotW = width - m.left - m.right;
  const plotH = height - m.top - m.bottom;
  chart.setAttribute("viewBox", `0 0 ${width} ${height}`);
  chart.replaceChildren();

  const series = buckets(decisions);
  const max = niceCeil(Math.max(0, ...series.map((b) => b.allow + b.ask + b.deny)));
  const y = (v) => m.top + plotH - (v / max) * plotH;
  const slot = plotW / BUCKETS;
  const colW = Math.min(24, Math.max(4, slot - 4));

  // Recessive hairline grid and clean ticks.
  for (let i = 0; i <= 4; i++) {
    const v = (max / 4) * i;
    const yy = Math.round(y(v)) + 0.5;
    chart.appendChild(svg("line", { x1: m.left, x2: width - m.right, y1: yy, y2: yy }, i === 0 ? "baseline" : "grid-line"));
    const label = svg("text", { x: m.left - 6, y: yy + 4, "text-anchor": "end" }, "tick");
    label.textContent = fmt.format(v);
    chart.appendChild(label);
  }
  for (const [i, anchor] of [[0, "start"], [Math.floor(BUCKETS / 2), "middle"], [BUCKETS - 1, "end"]]) {
    const x = anchor === "start" ? m.left : anchor === "end" ? width - m.right : m.left + slot * i + slot / 2;
    const label = svg("text", { x, y: height - 6, "text-anchor": anchor }, "tick");
    label.textContent = timeFmt(series[i].from);
    chart.appendChild(label);
  }

  series.forEach((b, i) => {
    const group = svg("g", { tabindex: "0", role: "img" }, "col");
    group.setAttribute("aria-label", `${timeFmt(b.from)}: ${b.allow} allowed, ${b.ask} asked, ${b.deny} denied`);
    const x = m.left + slot * i + (slot - colW) / 2;
    group.appendChild(svg("rect", { x: m.left + slot * i, y: m.top, width: slot, height: plotH }, "hover-band hit"));

    // Stack from the baseline: allow, ask, deny. A 2px surface gap separates
    // segments; only the top segment gets the 4px rounded data end.
    const stack = OUTCOMES.map(([key]) => [key, b[key]]).filter(([, v]) => v > 0);
    let acc = 0;
    stack.forEach(([key, v], si) => {
      const top = y(acc + v);
      const bottom = y(acc) - (si > 0 ? 2 : 0);
      const h = Math.max(1, bottom - top);
      const r = si === stack.length - 1 ? Math.min(4, h, colW / 2) : 0;
      const path = `M${x},${top + h} V${top + r} Q${x},${top} ${x + r},${top} H${x + colW - r} Q${x + colW},${top} ${x + colW},${top + r} V${top + h} Z`;
      group.appendChild(svg("path", { d: path }, `seg ${key}`));
      acc += v;
    });

    const show = () => showTooltip(b, m.left + slot * i + slot / 2);
    group.addEventListener("pointerenter", show);
    group.addEventListener("focus", show);
    group.addEventListener("pointerleave", hideTooltip);
    group.addEventListener("blur", hideTooltip);
    chart.appendChild(group);
  });

  // Table twin: every value reachable without hovering.
  const body = $("chart-table").querySelector("tbody");
  body.replaceChildren();
  for (const b of series) {
    if (!b.allow && !b.ask && !b.deny) continue;
    const tr = el("tr");
    tr.append(el("td", timeFmt(b.from)), el("td", b.allow, "num"), el("td", b.ask, "num"), el("td", b.deny, "num"));
    body.appendChild(tr);
  }
}

function showTooltip(b, xCenter) {
  const tip = $("tooltip");
  tip.replaceChildren(el("div", `From ${timeFmt(b.from)}`, "t-head"));
  for (const [key, label] of [...OUTCOMES].reverse()) {
    const row = el("div", undefined, "t-row");
    const line = el("i");
    line.style.background = `var(--${{ allow: "allowed", ask: "warning", deny: "critical" }[key]})`;
    row.append(line, el("b", b[key]), el("span", label));
    tip.appendChild(row);
  }
  tip.hidden = false;
  const wrap = $("chart-wrap").getBoundingClientRect();
  const scale = wrap.width / Math.max(1, Number($("chart").getAttribute("viewBox").split(" ")[2]));
  const left = Math.min(Math.max(0, xCenter * scale - tip.offsetWidth / 2), wrap.width - tip.offsetWidth);
  tip.style.left = `${left}px`;
  tip.style.top = "0px";
}

function hideTooltip() {
  $("tooltip").hidden = true;
}

function renderRules(decisions) {
  const list = $("rules");
  list.replaceChildren();
  const counts = new Map();
  for (const e of decisions) if (e.rule) counts.set(e.rule, (counts.get(e.rule) || 0) + 1);
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 7);
  if (!top.length) {
    list.appendChild(el("li", "No rule has fired in this range.", "muted"));
    return;
  }
  const max = top[0][1];
  for (const [rule, n] of top) {
    const li = el("li");
    const track = el("div", undefined, "track");
    const bar = el("div", undefined, "bar");
    bar.style.width = `${Math.max(3, (n / max) * 100)}%`;
    track.appendChild(bar);
    li.append(el("span", rule, "name"), el("span", fmt.format(n), "val"), track);
    list.appendChild(li);
  }
}

function renderHosts(events) {
  const list = $("host-list");
  list.replaceChildren();
  const hosts = new Map();
  for (const e of events) {
    if (!e.host) continue;
    const h = hosts.get(e.host) || { last: 0, calls: 0, denied: 0, contained: false };
    h.last = Math.max(h.last, e.timestamp_ms);
    if (e.kind === "decision") h.calls += 1;
    if (e.decision === "deny") h.denied += 1;
    if (e.kind === "containment") h.contained = true;
    hosts.set(e.host, h);
  }
  if (!hosts.size) {
    list.appendChild(el("li", "No host has reported in this range.", "muted"));
    return;
  }
  for (const [addr, h] of [...hosts.entries()].sort((a, b) => b[1].last - a[1].last)) {
    const li = el("li");
    const chip = el("span", h.contained ? "Contained" : "Active", `chip ${h.contained ? "contained" : "allow"}`);
    li.append(
      el("span", addr, "addr"),
      chip,
      el("span", `${h.calls} calls · ${h.denied} denied`, "meta"),
      el("span", `last ${timeFmt(h.last)}`, "meta time"),
    );
    list.appendChild(li);
  }
}

function renderEvents(events) {
  const body = $("event-rows");
  body.replaceChildren();
  const outcome = $("f-outcome").value;
  const severity = $("f-severity").value;
  const text = $("f-text").value.trim().toLowerCase();
  const rows = events
    .filter((e) => !outcome || (outcome === "containment" ? e.kind === "containment" : e.decision === outcome))
    .filter((e) => !severity || e.severity === severity)
    .filter((e) => !text || [e.host, e.session, e.tool, e.rule].some((v) => (v || "").toLowerCase().includes(text)))
    .slice(-300)
    .reverse();
  $("events-empty").hidden = rows.length > 0;
  for (const e of rows) {
    const tr = el("tr");
    let chip;
    if (e.kind === "containment") chip = el("span", "Contained", "chip contained");
    else if (e.decision) chip = el("span", { allow: "Allowed", ask: "Asked", deny: "Denied" }[e.decision], `chip ${e.decision}`);
    else chip = el("span", e.kind, "chip neutral");
    const outcomeCell = el("td");
    outcomeCell.appendChild(chip);
    const sevCell = el("td");
    if (e.severity) sevCell.appendChild(el("span", e.severity, `sev ${e.severity}`));
    tr.append(
      el("td", timeFmt(e.timestamp_ms, true)),
      el("td", e.seq, "num"),
      outcomeCell,
      sevCell,
      el("td", e.host || ""),
      el("td", e.tool || ""),
      el("td", e.rule || ""),
    );
    body.appendChild(tr);
  }
}

function renderIntegrity(d) {
  const identity = $("identity");
  identity.replaceChildren();
  const pinned = !d.paired_here
    ? el("span", "Not paired with this app", "chip neutral")
    : d.identity_matches === false
      ? el("span", "Identity differs from the pinned one", "chip deny")
      : el("span", "Identity matches the pinned one", "chip allow");
  identity.append(pinned, el("span", `${d.heads_total} heads · last signed #${d.status?.last_signed_seq ?? "–"}`, "muted"));

  const list = $("heads");
  list.replaceChildren();
  for (const h of [...d.heads].reverse()) {
    const li = el("li");
    li.append(
      el("span", h.valid ? "Verified" : "Invalid", `chip ${h.valid ? "allow" : "deny"}`),
      el("span", `#${h.seq}`, "seq"),
      el("code", h.head),
      el("time", timeFmt(h.timestamp_ms, true)),
    );
    list.appendChild(li);
  }
}

// Data -------------------------------------------------------------------------

async function refresh() {
  if (inFlight) return;
  inFlight = true;
  try {
    // The previous render stays on screen while this loads: no flash.
    data = await invoke("dashboard", { coreUrl });
    render();
  } catch (err) {
    setState("critical", "Error");
    showBanner(String(err));
  } finally {
    inFlight = false;
  }
}

function wire() {
  $("core-url").value = coreUrl;
  const theme = localStorage.getItem("theme") || "dark";
  document.documentElement.dataset.theme = theme;
  $("theme").textContent = theme === "dark" ? "Light theme" : "Dark theme";

  $("connect").addEventListener("submit", (event) => {
    event.preventDefault();
    coreUrl = $("core-url").value.trim();
    localStorage.setItem("coreUrl", coreUrl);
    refresh();
  });

  for (const button of $("range").querySelectorAll("button")) {
    button.classList.toggle("on", Number(button.dataset.min) === rangeMin);
    button.addEventListener("click", () => {
      rangeMin = Number(button.dataset.min);
      localStorage.setItem("rangeMin", String(rangeMin));
      for (const b of $("range").querySelectorAll("button")) b.classList.toggle("on", b === button);
      render();
    });
  }

  $("theme").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    localStorage.setItem("theme", next);
    $("theme").textContent = next === "dark" ? "Light theme" : "Dark theme";
  });

  $("chart-table-toggle").addEventListener("click", () => {
    const table = $("chart-table");
    table.hidden = !table.hidden;
    $("chart-wrap").hidden = !table.hidden;
    $("chart-table-toggle").textContent = table.hidden ? "Table" : "Chart";
    if (table.hidden) render();
  });

  for (const link of document.querySelectorAll(".nav a")) {
    link.addEventListener("click", () => {
      for (const l of document.querySelectorAll(".nav a")) l.classList.toggle("active", l === link);
    });
  }

  $("pair").addEventListener("click", async () => {
    $("pair").disabled = true;
    try {
      const result = await invoke("pair_core", { coreUrl });
      $("pair-result").textContent = result.confirmation_code;
      $("pair-result").title = "Check that the Core's log shows this code";
    } catch (err) {
      $("pair-result").textContent = "";
      showBanner(String(err));
    } finally {
      $("pair").disabled = false;
      refresh();
    }
  });

  for (const id of ["f-outcome", "f-severity"]) $(id).addEventListener("change", render);
  $("f-text").addEventListener("input", render);
  window.addEventListener("resize", render);
}

async function boot() {
  // Outside Tauri (a plain browser), load sample data so the design can be
  // reviewed without a Core. Inside the app this branch never runs.
  if (!window.__TAURI__) {
    await new Promise((resolve, reject) => {
      const script = el("script");
      script.src = "preview.js";
      script.onload = resolve;
      script.onerror = reject;
      document.head.appendChild(script);
    });
  }
  invoke = window.__TAURI__.core.invoke;
  try {
    const info = await invoke("app_info");
    $("version").textContent = `v${info.version}`;
  } catch {
    $("version").textContent = "";
  }
  wire();
  refresh();
  setInterval(refresh, REFRESH_MS);
}

boot();
