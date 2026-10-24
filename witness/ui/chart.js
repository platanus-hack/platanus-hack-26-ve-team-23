// Decisions over time as stacked columns: allowed, asked, denied. Grey and black
// only, so the three outcomes differ by tone, by texture (asked is hatched) and
// by a legend and a table with the same numbers, never by colour alone.
(() => {
  "use strict";
  const { t } = window.HAWK.i18n;
  const { el, svgEl, number, time, niceCeil } = window.HAWK.kit;

  const BUCKETS = 30;
  const OUTCOMES = ["allow", "ask", "deny"];

  function buckets(decisions, rangeMin, now) {
    const span = (rangeMin * 60_000) / BUCKETS;
    const start = now - rangeMin * 60_000;
    const out = Array.from({ length: BUCKETS }, (_, i) => ({ from: start + i * span, allow: 0, ask: 0, deny: 0 }));
    for (const e of decisions) {
      const i = Math.min(BUCKETS - 1, Math.floor((e.timestamp_ms - start) / span));
      if (i >= 0 && out[i][e.decision] !== undefined) out[i][e.decision] += 1;
    }
    return out;
  }

  function render({ svg, wrap, tooltip, table, decisions, rangeMin }) {
    const width = Math.max(280, wrap.clientWidth || 600);
    const height = width < 480 ? 176 : 224;
    const m = { top: 10, right: 4, bottom: 24, left: 30 };
    const plotW = width - m.left - m.right;
    const plotH = height - m.top - m.bottom;
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.setAttribute("height", String(height));
    svg.replaceChildren();

    const defs = svgEl("defs");
    const pattern = svgEl("pattern", { id: "hatch", width: "5", height: "5", patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" });
    pattern.append(svgEl("rect", { width: "5", height: "5" }, "hatch-base"), svgEl("line", { x1: "0", y1: "0", x2: "0", y2: "5", "stroke-width": "2" }, "hatch-line"));
    defs.appendChild(pattern);
    svg.appendChild(defs);

    const series = buckets(decisions, rangeMin, Date.now());
    const totals = { allow: 0, ask: 0, deny: 0 };
    for (const b of series) for (const k of OUTCOMES) totals[k] += b[k];
    const max = niceCeil(Math.max(0, ...series.map((b) => b.allow + b.ask + b.deny)));
    const y = (v) => m.top + plotH - (v / max) * plotH;
    const slot = plotW / BUCKETS;
    const colW = Math.min(18, Math.max(4, slot - 3));

    for (let i = 0; i <= 4; i++) {
      const v = (max / 4) * i;
      const yy = Math.round(y(v)) + 0.5;
      svg.appendChild(svgEl("line", { x1: m.left, x2: width - m.right, y1: yy, y2: yy }, i === 0 ? "baseline" : "grid-line"));
      const label = svgEl("text", { x: m.left - 6, y: yy + 4, "text-anchor": "end" }, "tick");
      label.textContent = number(v);
      svg.appendChild(label);
    }
    for (const [i, anchor] of [[0, "start"], [Math.floor(BUCKETS / 2), "middle"], [BUCKETS - 1, "end"]]) {
      const x = anchor === "start" ? m.left : anchor === "end" ? width - m.right : m.left + slot * i + slot / 2;
      const label = svgEl("text", { x, y: height - 6, "text-anchor": anchor }, "tick");
      label.textContent = time(series[i].from);
      svg.appendChild(label);
    }

    const empty = totals.allow + totals.ask + totals.deny === 0;
    if (empty) {
      const msg = svgEl("text", { x: width / 2, y: m.top + plotH / 2, "text-anchor": "middle" }, "empty-text");
      msg.textContent = t("chart.empty");
      svg.appendChild(msg);
    }

    series.forEach((b, i) => {
      const group = svgEl("g", { tabindex: "0", role: "img" }, "col");
      group.setAttribute("aria-label", `${time(b.from)}: ${b.allow} ${t("verdict.allow")}, ${b.ask} ${t("verdict.ask")}, ${b.deny} ${t("verdict.deny")}`);
      const x = m.left + slot * i + (slot - colW) / 2;
      group.appendChild(svgEl("rect", { x: m.left + slot * i, y: m.top, width: slot, height: plotH }, "hit"));

      // Stack from the baseline. A 2px gap separates segments; only the top
      // segment gets the 4px rounded end.
      const stack = OUTCOMES.map((key) => [key, b[key]]).filter(([, v]) => v > 0);
      let acc = 0;
      stack.forEach(([key, v], si) => {
        const top = y(acc + v);
        const bottom = y(acc) - (si > 0 ? 2 : 0);
        const h = Math.max(1.5, bottom - top);
        const r = si === stack.length - 1 ? Math.min(4, h, colW / 2) : 0;
        const d = `M${x},${top + h} V${top + r} Q${x},${top} ${x + r},${top} H${x + colW - r} Q${x + colW},${top} ${x + colW},${top + r} V${top + h} Z`;
        group.appendChild(svgEl("path", { d }, `seg ${key}`));
        acc += v;
      });

      const show = () => showTip(b, m.left + slot * i + slot / 2);
      group.addEventListener("pointerenter", show);
      group.addEventListener("focus", show);
      group.addEventListener("pointerleave", hide);
      group.addEventListener("blur", hide);
      svg.appendChild(group);
    });

    function showTip(b, xCenter) {
      tooltip.replaceChildren(el("div", t("chart.tipFrom", { time: time(b.from) }), "t-head"));
      for (const key of [...OUTCOMES].reverse()) {
        const row = el("div", undefined, "t-row");
        row.append(el("i", undefined, `sw ${key}`), el("b", b[key]), el("span", t(`verdict.${key}`)));
        tooltip.appendChild(row);
      }
      tooltip.hidden = false;
      const box = wrap.getBoundingClientRect();
      const scale = box.width / width;
      const left = Math.min(Math.max(0, xCenter * scale - tooltip.offsetWidth / 2), box.width - tooltip.offsetWidth);
      tooltip.style.left = `${left}px`;
      tooltip.style.top = "0px";
    }
    function hide() { tooltip.hidden = true; }

    // The table twin: every value reachable without hovering.
    const body = table.querySelector("tbody");
    body.replaceChildren();
    for (const b of series) {
      if (!b.allow && !b.ask && !b.deny) continue;
      const tr = el("tr");
      tr.append(el("td", time(b.from)), el("td", b.allow, "num"), el("td", b.ask, "num"), el("td", b.deny, "num"));
      body.appendChild(tr);
    }
    if (!body.children.length) {
      const tr = el("tr");
      const td = el("td", t("chart.empty"), "empty-cell");
      td.colSpan = 4;
      tr.appendChild(td);
      body.appendChild(tr);
    }
    return totals;
  }

  window.HAWK.chart = { render };
})();
