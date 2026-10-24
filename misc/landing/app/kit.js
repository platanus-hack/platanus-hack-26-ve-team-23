// Small display helpers shared by the app: DOM builders (textContent only, never
// innerHTML), number and time formats, the sheet, and toasts (ADR-0013).
(() => {
  "use strict";
  const { t, tn, locale } = window.HAWK.i18n;
  const SVG = "http://www.w3.org/2000/svg";

  // DOM ---------------------------------------------------------------------
  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  function svgEl(tag, attrs, className) {
    const node = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
    if (className) node.setAttribute("class", className);
    return node;
  }

  function icon(name, className) {
    const svg = svgEl("svg", { "aria-hidden": "true", focusable: "false" }, `ic${className ? ` ${className}` : ""}`);
    const use = svgEl("use", {});
    use.setAttribute("href", `#i-${name}`);
    svg.appendChild(use);
    return svg;
  }

  // A verdict or state, never by colour alone: shape, glyph and word.
  const CHIP_ICON = { allow: "check", ask: "ask", deny: "x", contain: "quarantine", pending: "approve", neutral: null, offline: "offline", connected: "check", alert: "alert" };
  function chip(kind, label) {
    const node = el("span", undefined, `chip ${kind}`);
    const glyph = CHIP_ICON[kind];
    if (glyph) node.appendChild(icon(glyph));
    node.appendChild(el("span", label));
    return node;
  }

  const SEV_LEVEL = { low: 1, medium: 2, high: 3, critical: 4 };
  function severity(sev) {
    const level = SEV_LEVEL[sev] || 0;
    const wrap = el("span", undefined, `sev sev-${sev || "none"}`);
    const meter = el("span", undefined, "meter");
    meter.setAttribute("aria-hidden", "true");
    for (let i = 1; i <= 4; i++) meter.appendChild(el("i", undefined, i <= level ? "on" : ""));
    wrap.append(meter, el("span", sev ? t(`sev.${sev}`) : ""));
    return wrap;
  }

  function button(label, className, onClick, iconName) {
    const node = el("button", undefined, className);
    node.type = "button";
    if (iconName) node.appendChild(icon(iconName));
    node.appendChild(el("span", label));
    if (onClick) node.addEventListener("click", onClick);
    return node;
  }

  function setButtonLabel(node, label) {
    const span = node.querySelector("span:last-child");
    if (span) span.textContent = label;
    else node.textContent = label;
  }

  // Formats -------------------------------------------------------------------
  function number(n) {
    return new Intl.NumberFormat(locale(), { notation: n >= 10000 ? "compact" : "standard", maximumFractionDigits: 1 }).format(n);
  }
  function oneDecimal(n) {
    return new Intl.NumberFormat(locale(), { maximumFractionDigits: 1, minimumFractionDigits: 0 }).format(n);
  }
  function time(ms, withSeconds) {
    return new Date(ms).toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit", second: withSeconds ? "2-digit" : undefined, hour12: locale() === "en-US" });
  }
  function dateTime(ms) {
    const d = new Date(ms);
    const day = d.toLocaleDateString(locale(), { day: "numeric", month: "short" });
    return `${day}, ${time(ms, true)}`;
  }
  function ago(ms) {
    const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
    if (s < 5) return t("ago.now");
    if (s < 60) return t("ago.s", { n: s });
    if (s < 3600) return t("ago.m", { n: Math.round(s / 60) });
    return t("ago.h", { n: Math.round(s / 3600) });
  }
  function niceCeil(value) {
    if (value <= 4) return 4;
    const exp = 10 ** Math.floor(Math.log10(value));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * exp >= value) return m * exp;
    return 10 * exp;
  }
  const shortHwid = (hwid) => (hwid ? `${hwid.slice(0, 8)}…${hwid.slice(-4)}` : "");
  const pretty = (value) => {
    try { return JSON.stringify(value, null, 2); } catch (e) { return String(value); }
  };

  // Storage: a convenience only, the app works without it.
  const store = {
    get(key, fallback) {
      try { const v = localStorage.getItem(key); return v === null ? fallback : v; } catch (e) { return fallback; }
    },
    set(key, value) {
      try { localStorage.setItem(key, String(value)); } catch (e) { /* ignore */ }
    },
  };

  // Sheet -----------------------------------------------------------------------
  // One modal dialog for confirmations, details and forms. `sheet()` resolves
  // with the value of the action chosen, or undefined when dismissed.
  const dialog = () => document.getElementById("sheet");
  let sheetResolve = null;

  function closeSheet(value) {
    const d = dialog();
    const done = sheetResolve;
    sheetResolve = null;
    if (d.open) d.close();
    if (done) done(value);
  }

  function sheet({ title, body, actions, wide }) {
    const d = dialog();
    if (sheetResolve) closeSheet(undefined);
    document.getElementById("sheet-title").textContent = title;
    const bodyBox = document.getElementById("sheet-body");
    bodyBox.replaceChildren(...(Array.isArray(body) ? body : body ? [body] : []));
    const foot = document.getElementById("sheet-actions");
    foot.replaceChildren();
    foot.hidden = !actions || !actions.length;
    for (const a of actions || []) {
      const b = button(a.label, `pill ${a.kind || "ghost"}`, () => closeSheet(a.value), a.icon);
      foot.appendChild(b);
    }
    d.classList.toggle("wide", Boolean(wide));
    return new Promise((resolve) => {
      sheetResolve = resolve;
      if (typeof d.showModal === "function") d.showModal();
      else d.setAttribute("open", "");
      bodyBox.scrollTop = 0;
      const first = foot.querySelector("button.primary, button.danger") || foot.querySelector("button") || document.getElementById("sheet-close");
      if (first) first.focus({ preventScroll: true });
    });
  }

  function confirmSheet({ title, text, nodes, confirmLabel, cancelLabel, tone, icon: iconName }) {
    const body = [];
    if (nodes) body.push(...nodes);
    if (text) body.push(el("p", text, "sheet-text"));
    return sheet({
      title,
      body,
      actions: [
        { label: confirmLabel, kind: tone === "danger" ? "primary" : "primary", value: true, icon: iconName },
        { label: cancelLabel || t("approve.cancel"), kind: "ghost", value: false },
      ],
    }).then((v) => v === true);
  }

  function wireSheet() {
    const d = dialog();
    document.getElementById("sheet-close").addEventListener("click", () => closeSheet(undefined));
    d.addEventListener("cancel", (e) => { e.preventDefault(); closeSheet(undefined); });
    d.addEventListener("click", (e) => { if (e.target === d) closeSheet(undefined); });
  }

  // Toasts ------------------------------------------------------------------------
  function toast(message, kind, ms) {
    const box = document.getElementById("toasts");
    for (const old of box.children) if (old.dataset.text === message) old.remove();
    const node = el("div", undefined, `toast ${kind || "info"}`);
    node.dataset.text = message;
    node.append(icon(kind === "error" ? "alert" : kind === "alert" ? "alert" : "check"), el("span", message));
    box.appendChild(node);
    while (box.children.length > 3) box.firstChild.remove();
    const life = ms || (kind === "error" ? 7000 : 4200);
    setTimeout(() => node.classList.add("leaving"), life);
    setTimeout(() => node.remove(), life + 400);
    return node;
  }

  window.HAWK.kit = {
    el, svgEl, icon, chip, severity, button, setButtonLabel,
    number, oneDecimal, time, dateTime, ago, niceCeil, shortHwid, pretty,
    store, sheet, closeSheet, confirmSheet, wireSheet, toast, tn,
  };
})();
