// The owner's app. Display only: every value comes from a Rust command and no
// key material ever reaches this file (ADR-0013). Anything that came from the
// network (host names, tool names, rules, reasons) is inserted with textContent,
// never as markup.
(() => {
  "use strict";
  const { t, tn, apply, setLang, friendlyError, lang, locale } = window.HAWK.i18n;
  const K = window.HAWK.kit;
  const { el, icon, chip, severity, button, setButtonLabel, number, oneDecimal, time, dateTime, ago, shortHwid, pretty, store, sheet, closeSheet, confirmSheet, toast } = K;
  const $ = (id) => document.getElementById(id);

  const REFRESH_MS = 3000;
  const ASK_WINDOW_MS = 60_000; // the Core holds an ask this long (ADR-0022)
  const HEADS_DEFAULT = 6;
  const EVENT_STEP = 50;
  const VIEWS = [
    { id: "overview", icon: "overview" },
    { id: "hosts", icon: "hosts" },
    { id: "events", icon: "events" },
    { id: "record", icon: "record" },
    { id: "settings", icon: "settings" },
  ];

  const S = {
    invoke: null,
    info: null,
    data: null,
    lastGood: null,
    lastGoodAt: 0,
    view: "overview",
    rangeMin: Number(store.get("hawk.range", "60")) || 60,
    inFlight: false,
    timer: null,
    seenAlertSeq: null,
    knownAsks: null,
    alertBanner: null,
    chartAsTable: false,
    headsExpanded: false,
    record: null,
    recordBusy: false,
    chosen: null,
    wizardStep: "find",
    answering: new Set(),
  };

  // Navigation ---------------------------------------------------------------------

  function buildNav() {
    for (const host of [$("rail-nav"), $("tabbar")]) {
      host.replaceChildren();
      for (const v of VIEWS) {
        const b = el("button", undefined, "nav-item");
        b.type = "button";
        b.dataset.view = v.id;
        b.append(icon(v.icon), el("span", t(`nav.${v.id}`), "nav-label"), el("span", "", "badge"));
        b.addEventListener("click", () => go(v.id));
        host.appendChild(b);
      }
    }
  }

  function go(id, { silent } = {}) {
    if (!VIEWS.some((v) => v.id === id)) id = "overview";
    S.view = id;
    for (const section of document.querySelectorAll(".view")) section.hidden = section.dataset.view !== id;
    for (const b of document.querySelectorAll(".nav-item")) {
      if (b.dataset.view === id) b.setAttribute("aria-current", "page");
      else b.removeAttribute("aria-current");
    }
    $("screen-title").textContent = t(`nav.${id}`);
    if (!silent) {
      try { history.replaceState(null, "", `#/${id}`); } catch (e) { /* file:// in some browsers */ }
      window.scrollTo(0, 0);
    }
    if (id === "overview") renderChart();
  }

  function viewFromHash() {
    const m = /^#\/?([a-z]+)/.exec(location.hash || "");
    return m ? m[1] : "overview";
  }

  // State -----------------------------------------------------------------------------

  // What the Core reported, or the last good report while it is out of reach.
  function effective() {
    const d = S.data;
    if (!d) return { d: null, base: null, stale: false };
    if (!d.reachable && S.lastGood) return { d, base: S.lastGood, stale: true };
    return { d, base: d, stale: false };
  }

  function deriveState({ d, base, stale }) {
    if (!d) return { key: "connecting", tone: "warn", glyph: "refresh" };
    if (!d.reachable) return { key: "offline", tone: "bad", glyph: "offline" };
    if (!base.status || !base.status.paired) return { key: "dormant", tone: "warn", glyph: "alert" };
    if (base.identity_matches === false) return { key: "identity", tone: "bad", glyph: "alert" };
    if (base.heads_invalid > 0) return { key: "integrity", tone: "bad", glyph: "alert" };
    if (!base.paired_here) return { key: "elsewhere", tone: "warn", glyph: "alert" };
    return { key: "good", tone: "good", glyph: "approve" };
  }

  function inRange(events) {
    const from = Date.now() - S.rangeMin * 60_000;
    return events.filter((e) => e.timestamp_ms >= from);
  }

  const hostName = (hosts, address) => {
    const h = (hosts || []).find((x) => x.address === address);
    return h && h.hostname ? h.hostname : address || "";
  };

  // Hosts the Core has contained: what it reports, completed by the record's
  // containment and release events for addresses it no longer lists.
  // The Core notes "containment_failed: ..." when the firewall refused.
  const containFailed = (e) => e.kind === "containment" && /^containment_failed/.test(e.reason || "");

  function containedAddresses(hosts, events) {
    const set = new Set();
    for (const e of events) {
      if (!e.host) continue;
      if (e.kind === "containment" && !containFailed(e)) set.add(e.host);
      if (e.kind === "release") set.delete(e.host);
    }
    for (const h of hosts) {
      if (h.contained) set.add(h.address);
      else set.delete(h.address);
    }
    return set;
  }

  // Render --------------------------------------------------------------------------------

  function renderAll() {
    const eff = effective();
    renderState(eff);
    renderBanner(eff);
    if (!eff.base) { renderEmpty(); return; }
    const { base } = eff;
    document.body.classList.toggle("stale", eff.stale);
    renderAsks(base.asks || [], base.hosts || [], eff.stale);
    renderKpis(base);
    renderChart();
    renderRules(base);
    renderRecent(base);
    renderHosts(base, eff.stale);
    renderEvents(base);
    renderIntegrity(base);
    renderSettings(base);
    renderBadges(base);
  }

  function renderEmpty() {
    for (const id of ["ask-list", "rules", "recent", "host-list", "event-list", "heads"]) $(id).replaceChildren();
    $("asks").hidden = true;
  }

  function renderState(eff) {
    const st = deriveState(eff);
    const hero = $("hero");
    hero.dataset.kind = st.tone;
    $("hero-icon").firstElementChild.setAttribute("href", `#i-${st.glyph}`);
    $("state-title").textContent = st.key === "connecting" ? t("state.connecting") : t(`state.${st.key}.title`);
    $("state-sub").textContent = st.key === "connecting" ? "" : stateSub(st, eff);
    const pill = $("top-state");
    pill.dataset.kind = st.tone;
    pill.firstElementChild.firstElementChild.setAttribute("href", `#i-${st.glyph === "approve" ? "shield" : st.glyph}`);
    $("top-state-text").textContent = t(`state.short.${st.key}`);

    const base = eff.base;
    const name = (base && base.status && base.status.name) || (S.info && S.info.core && S.info.core.name) || t("core.default");
    $("core-name").textContent = name;
    $("core-fp").textContent = S.info && S.info.core ? S.info.core.fingerprint : t("common.none");
    $("updated").textContent = eff.stale ? t("live.stale", { time: time(S.lastGoodAt, true) }) : S.data ? time(Date.now(), true) : t("common.none");
    const live = $("rail-live");
    live.dataset.live = S.data && S.data.reachable ? "on" : "off";
    $("rail-live-text").textContent = S.data && S.data.reachable ? t("live.on") : t("live.off");
  }

  function stateSub(st, eff) {
    const base = eff.base;
    if (st.key === "integrity") return `${t("state.integrity.sub")} (${base.heads_invalid}/${base.heads_total})`;
    if (st.key === "good" && base) {
      const hosts = base.hosts || [];
      const connected = hosts.filter((h) => h.connected).length;
      const pending = hosts.filter((h) => !h.approved).length;
      const bits = [t("state.good.sub")];
      if (hosts.length) bits.push(t("hosts.count", { c: connected, n: hosts.length }) + (pending ? ` · ${tn("hosts.pendingCount", pending)}` : ""));
      return bits.join(" ");
    }
    return t(`state.${st.key}.sub`);
  }

  function renderBanner(eff) {
    const box = $("banner");
    const retry = $("banner-retry");
    let text = "";
    let withRetry = false;
    const d = eff.d;
    if (S.alertBanner && S.alertBanner.until > Date.now()) {
      text = S.alertBanner.text;
    } else if (!d) {
      text = "";
    } else if (!d.reachable) {
      text = eff.stale ? t("banner.stale", { time: time(S.lastGoodAt, true) }) : friendlyError(d.error || t("err.unreachable"));
      withRetry = true;
    } else if (d.identity_matches === false) {
      text = t("banner.identity");
    } else if (d.heads_invalid > 0) {
      text = tn("banner.heads", d.heads_invalid);
    } else if (d.status && d.status.paired && !d.paired_here) {
      text = t("banner.elsewhere");
    }
    box.hidden = !text;
    $("banner-text").textContent = text;
    retry.hidden = !withRetry;
  }

  function renderBadges(base) {
    const asks = (base.asks || []).length;
    const pending = (base.hosts || []).filter((h) => !h.approved).length;
    const set = (view, n, label) => {
      for (const b of document.querySelectorAll(`.nav-item[data-view="${view}"] .badge`)) {
        b.textContent = n ? String(n) : "";
        b.hidden = !n;
        if (n) b.setAttribute("aria-label", label); else b.removeAttribute("aria-label");
      }
    };
    set("overview", asks, tn("asks.count", asks));
    set("hosts", pending, tn("hosts.pendingCount", pending));
    document.title = asks ? `(${asks}) HAWK` : "HAWK";
  }

  function renderKpis(base) {
    const events = inRange(base.events || []);
    const decisions = events.filter((e) => e.kind === "decision");
    const count = (v) => decisions.filter((e) => e.decision === v).length;
    $("k-blocked").textContent = number(count("deny"));
    $("k-blocked-sub").textContent = t("kpi.blockedSub", { range: t(`range.${S.rangeMin}`) });
    $("k-total").textContent = number(decisions.length);
    $("k-rate").textContent = t("kpi.rate", { n: oneDecimal(decisions.length / S.rangeMin) });
    $("k-ask").textContent = number(count("ask"));
    const contained = containedAddresses(base.hosts || [], base.events || []).size;
    $("k-contained").textContent = number(contained);
    $("k-contained-sub").textContent = tn("kpi.containedSub", contained);

    let word = t("common.none");
    let sub = "";
    let bad = false;
    if (!base.paired_here) sub = t("kpi.integrityNone");
    else if (base.heads_invalid > 0 || base.identity_matches === false) { word = t("kpi.failed"); sub = t("kpi.integrityBad", { bad: base.heads_invalid, n: base.heads_total }); bad = true; }
    else if (base.heads_total === 0) sub = t("kpi.integrityNoHeads");
    else { word = t("kpi.verified"); sub = tn("kpi.integrityHeads", base.heads_total); }
    $("k-integrity").textContent = word;
    $("k-integrity").dataset.bad = bad ? "1" : "";
    $("k-integrity-sub").textContent = sub;
  }

  function renderChart() {
    const eff = effective();
    if (!eff.base || S.view !== "overview") return;
    const wrap = $("chart-wrap");
    const decisions = inRange(eff.base.events || []).filter((e) => e.kind === "decision");
    const totals = window.HAWK.chart.render({ svg: $("chart"), wrap, tooltip: $("tooltip"), table: $("chart-table"), decisions, rangeMin: S.rangeMin });
    $("chart-desc").textContent = t("chart.desc", totals);
  }

  function renderRules(base) {
    const list = $("rules");
    list.replaceChildren();
    const counts = new Map();
    for (const e of inRange(base.events || [])) if (e.kind === "decision" && e.rule) counts.set(e.rule, (counts.get(e.rule) || 0) + 1);
    const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
    if (!top.length) { list.appendChild(el("li", t("rules.empty"), "muted")); return; }
    const max = top[0][1];
    for (const [rule, n] of top) {
      const li = el("li");
      const bar = el("div", undefined, "bar");
      bar.style.width = `${Math.max(3, (n / max) * 100)}%`;
      const track = el("div", undefined, "track");
      track.appendChild(bar);
      li.append(el("code", rule, "name"), el("span", number(n), "val"), track);
      li.setAttribute("aria-label", `${rule}: ${t("rules.count", { n })}`);
      list.appendChild(li);
    }
  }

  function outcomeChip(e) {
    if (containFailed(e)) return chip("alert", t("verdict.containFailed"));
    if (e.kind === "containment") return chip("contain", t("verdict.contain"));
    if (e.kind === "decision" && ["allow", "ask", "deny"].includes(e.decision)) return chip(e.decision, t(`verdict.${e.decision}`));
    if (e.kind === "alert") return chip("alert", t("kind.alert"));
    return chip("neutral", kindLabel(e.kind));
  }
  function kindLabel(kind) {
    const key = `kind.${kind}`;
    return window.HAWK.i18n.has(key) ? t(key) : kind;
  }

  function renderRecent(base) {
    const list = $("recent");
    list.replaceChildren();
    const rows = inRange(base.events || []).filter((e) => e.kind === "decision" || e.kind === "containment").slice(-6).reverse();
    if (!rows.length) { list.appendChild(el("li", t("recent.empty"), "muted")); return; }
    for (const e of rows) list.appendChild(eventRow(e, base.hosts || [], true));
  }

  // Asks ----------------------------------------------------------------------------------

  function renderAsks(asks, hosts, stale) {
    const section = $("asks");
    const list = $("ask-list");
    section.hidden = !asks.length;
    $("asks-count").textContent = asks.length ? tn("asks.count", asks.length) : "";
    list.replaceChildren();
    for (const ask of asks) {
      const li = el("li", undefined, "ask");
      li.dataset.created = String(ask.created_at_ms);
      const head = el("div", undefined, "ask-head");
      head.append(el("code", ask.tool, "tool"), el("span", t("asks.on", { host: hostName(hosts, ask.host) }), "on"));
      const foot = el("div", undefined, "ask-foot");
      const left = el("span", "", "left");
      const actions = el("div", undefined, "actions");
      const allow = button(t("asks.allow"), "pill primary", () => answer(ask, true, [allow, deny]), "check");
      const deny = button(t("asks.deny"), "pill outline", () => answer(ask, false, [allow, deny]), "x");
      allow.disabled = deny.disabled = stale || S.answering.has(ask.id);
      actions.append(deny, allow);
      foot.append(left, actions);
      li.append(head, el("p", ask.reason, "reason"), foot);
      list.appendChild(li);
    }
    tickAsks();
  }

  function tickAsks() {
    for (const li of document.querySelectorAll("#ask-list .ask")) {
      const left = Math.ceil((Number(li.dataset.created) + ASK_WINDOW_MS - Date.now()) / 1000);
      const label = li.querySelector(".left");
      if (left <= 0) {
        li.classList.add("expired");
        label.textContent = t("asks.expired");
        for (const b of li.querySelectorAll("button")) b.disabled = true;
      } else {
        li.classList.remove("expired");
        // Phone and Core clocks differ a little: the countdown only guides.
        label.textContent = t("asks.left", { s: Math.min(left, 60) });
      }
    }
  }

  async function answer(ask, allow, buttons) {
    S.answering.add(ask.id);
    for (const b of buttons) b.disabled = true;
    try {
      await S.invoke("answer_ask", { id: ask.id, allow });
      toast(t(allow ? "asks.allowed" : "asks.denied", { tool: ask.tool }), "info");
    } catch (err) {
      toast(friendlyError(err), "error");
    } finally {
      S.answering.delete(ask.id);
      refresh();
    }
  }

  // Hosts ---------------------------------------------------------------------------------

  // Every identifier the owner may search a machine by (ADR-0028).
  function hostMatches(h, text) {
    if (!text) return true;
    const fields = [h.hostname, h.address, h.mac, h.hwid, h.fingerprint, h.os, ...(h.nics || []).flatMap((n) => [n.name, n.mac])];
    return fields.some((v) => (v || "").toLowerCase().includes(text));
  }

  function renderHosts(base, stale) {
    const hosts = base.hosts || [];
    const list = $("host-list");
    list.replaceChildren();
    const connected = hosts.filter((h) => h.connected).length;
    const pending = hosts.filter((h) => !h.approved).length;
    $("host-count").textContent = hosts.length ? t("hosts.count", { c: connected, n: hosts.length }) + (pending ? ` · ${tn("hosts.pendingCount", pending)}` : "") : "";

    const activity = new Map();
    for (const e of base.events || []) {
      if (!e.host) continue;
      const a = activity.get(e.host) || { calls: 0, denied: 0 };
      if (e.kind === "decision") a.calls += 1;
      if (e.decision === "deny") a.denied += 1;
      activity.set(e.host, a);
    }
    const contained = containedAddresses(hosts, base.events || []);

    const empty = $("hosts-empty");
    const text = $("host-filter").value.trim().toLowerCase();
    const shown = hosts.filter((h) => hostMatches(h, text));
    empty.hidden = shown.length > 0;
    empty.textContent = hosts.length ? t("hosts.noMatch") : t("hosts.none");
    // Contained first, then waiting for approval, then the rest by name.
    const rank = (h) => (contained.has(h.address) ? 0 : !h.approved ? 1 : h.connected ? 2 : 3);
    shown.sort((a, b) => rank(a) - rank(b) || (a.hostname || a.address).localeCompare(b.hostname || b.address));

    for (const h of shown) list.appendChild(hostCard(h, activity.get(h.address) || { calls: 0, denied: 0 }, contained.has(h.address), stale));
  }

  // The Core writes `conflict` in English from two fixed templates
  // (guardian/src/hosts.rs). Known ones are shown in the app language; anything
  // else is shown as the Core wrote it.
  function conflictText(raw) {
    let m = /^(\S+) reports the HWID of (\S+): the same machine with a new daemon key$/.exec(raw);
    if (m) return t("host.conflictRekey", { a: m[1], b: m[2] });
    m = /^(\S+) reports another HWID than it was approved with: its key may have been copied to another machine$/.exec(raw);
    if (m) return t("host.conflictCopied", { a: m[1] });
    return raw;
  }

  function hostCard(h, a, isContained, stale) {
    const li = el("li", undefined, `host${isContained ? " is-contained" : ""}${!h.approved ? " is-pending" : ""}`);
    const name = h.hostname || h.address;

    let state;
    if (isContained) state = chip("contain", t("host.contained"));
    else if (!h.approved) state = chip("pending", t("host.pending"));
    else if (h.connected) state = chip("connected", t("host.connected"));
    else state = chip("offline", t("host.offline"));

    const head = el("div", undefined, "host-head");
    const title = el("div", undefined, "host-title");
    title.append(el("span", name, "host-name"), el("code", h.fingerprint, "fp"));
    head.append(title, state);

    const ids = el("dl", undefined, "ids");
    const id = (label, value, titleText, muted) => {
      const row = el("div");
      if (titleText) row.title = titleText;
      row.append(el("dt", label), el("dd", value, muted ? "muted" : ""));
      ids.appendChild(row);
    };
    id(t("hosts.ip"), h.address);
    id(t("hosts.mac"), h.mac || t("hosts.macNone"), t("hosts.macTitle"), !h.mac);
    id(t("hosts.hwid"), h.hwid ? shortHwid(h.hwid) : t("hosts.hwidNone"), h.hwid ? t("hosts.hwidTitle", { hwid: h.hwid }) : undefined, !h.hwid);

    li.append(head, ids);
    if (h.conflict) li.appendChild(note("alert", conflictText(h.conflict), "warn bad"));
    const virtual = (h.nics || []).filter((n) => n.virtual);
    if (virtual.length) {
      const names = virtual.map((n) => n.name).slice(0, 3).join(", ") + (virtual.length > 3 ? ", …" : "");
      li.appendChild(note("net", t("hosts.vm", { names }), "warn"));
    }
    li.appendChild(el("p", t("hosts.stats", { os: h.os, calls: a.calls, denied: a.denied, time: ago(h.last_seen_ms) }), "meta"));

    const actions = el("div", undefined, "host-actions");
    const identify = button(t("hosts.identify"), "pill ghost", () => identifyHost(h, identify), "eye");
    identify.title = t("hosts.identifyTitle");
    identify.disabled = stale || !h.connected;
    actions.appendChild(identify);
    if (!h.approved) {
      const approve = button(t("hosts.approve"), "pill primary", () => approveHost(h), "approve");
      approve.title = t("hosts.approveTitle");
      approve.disabled = stale || !h.connected || Boolean(h.conflict);
      actions.appendChild(approve);
    }
    if (isContained) {
      const release = button(t("hosts.release"), "pill primary", () => releaseHost(h), "release");
      release.title = t("hosts.releaseTitle");
      release.disabled = stale;
      actions.appendChild(release);
    }
    li.appendChild(actions);
    return li;
  }

  function note(iconName, text, className) {
    const p = el("p", undefined, `host-note ${className || ""}`);
    p.append(icon(iconName), el("span", text));
    return p;
  }

  async function identifyHost(h, btn) {
    btn.disabled = true;
    try {
      await S.invoke("identify_host", { host: h.id });
      toast(t("hosts.identified", { host: h.hostname || h.address, fp: h.fingerprint }), "info", 6000);
      setButtonLabel(btn, t("common.sent"));
    } catch (err) {
      toast(friendlyError(err), "error");
    } finally {
      setTimeout(() => { setButtonLabel(btn, t("hosts.identify")); btn.disabled = !h.connected; }, 4000);
    }
  }

  function hostFacts(h) {
    const box = el("div", undefined, "sheet-facts");
    box.appendChild(el("code", h.fingerprint, "bigcode-sm"));
    const dl = el("dl", undefined, "kv compact");
    const row = (label, value) => { const d = el("div"); d.append(el("dt", label), el("dd", value)); dl.appendChild(d); };
    row(t("hosts.ip"), h.address);
    row(t("hosts.mac"), h.mac || t("hosts.macNone"));
    row(t("hosts.hwid"), h.hwid ? shortHwid(h.hwid) : t("hosts.hwidNone"));
    box.appendChild(dl);
    return box;
  }

  async function approveHost(h) {
    const name = h.hostname || h.address;
    const ok = await confirmSheet({
      title: t("approve.title", { host: name }),
      nodes: [hostFacts(h), el("p", t("approve.text"), "sheet-text"), el("p", t("approve.sign"), "sheet-text muted")],
      confirmLabel: t("approve.confirm"),
      icon: "approve",
    });
    if (!ok) return;
    try {
      await S.invoke("approve_host", { host: h.id, hwid: h.hwid || "" });
      toast(t("approve.done", { host: name }), "info");
    } catch (err) {
      toast(friendlyError(err), "error");
    }
    refresh();
  }

  async function releaseHost(h) {
    const name = h.hostname || h.address;
    const ok = await confirmSheet({
      title: t("release.title", { host: name }),
      nodes: [hostFacts(h), el("p", t("release.text"), "sheet-text")],
      confirmLabel: t("release.confirm"),
      icon: "release",
    });
    if (!ok) return;
    try {
      // `host` is the quarantined address, as the Core lists it (ADR-0018)
      await S.invoke("release_host", { host: h.address });
      toast(t("release.done", { host: name }), "info");
    } catch (err) {
      toast(friendlyError(err), "error");
    }
    refresh();
  }

  // Events --------------------------------------------------------------------------------

  function eventRow(e, hosts, compact) {
    const li = el("li");
    const row = el("button", undefined, `event-row${compact ? " compact" : ""}`);
    row.type = "button";
    row.append(
      el("span", time(e.timestamp_ms, true), "e-time"),
      outcomeCell(e),
      eventMain(e),
      el("span", hostName(hosts, e.host), "e-host"),
    );
    if (!compact) row.appendChild(e.severity ? severity(e.severity) : el("span", "", "sev none"));
    row.addEventListener("click", () => eventSheet(e, hosts));
    li.appendChild(row);
    return li;
  }
  function outcomeCell(e) {
    const c = el("span", undefined, "e-chip");
    c.appendChild(outcomeChip(e));
    return c;
  }
  function eventMain(e) {
    const main = el("span", undefined, "e-main");
    if (e.tool) main.appendChild(el("code", e.tool, "e-tool"));
    const detail = e.rule || e.reason;
    if (detail) main.appendChild(el("span", detail, "e-rule"));
    if (!e.tool && !detail) main.appendChild(el("span", kindLabel(e.kind), "e-rule"));
    return main;
  }

  function renderEvents(base) {
    const hosts = base.hosts || [];
    const outcome = $("f-outcome").value;
    const sev = $("f-severity").value;
    const text = $("f-text").value.trim().toLowerCase();
    const all = inRange(base.events || [])
      .filter((e) => !outcome || (outcome === "containment" ? e.kind === "containment" : outcome === "alert" ? e.kind === "alert" : e.decision === outcome))
      .filter((e) => !sev || e.severity === sev)
      .filter((e) => !text || [e.host, hostName(hosts, e.host), e.session, e.tool, e.rule, e.reason].some((v) => (v || "").toLowerCase().includes(text)));
    if (!S.eventLimit) S.eventLimit = EVENT_STEP;
    const rows = all.slice(-S.eventLimit).reverse();
    const list = $("event-list");
    const more = $("events-more");
    const left = all.length - rows.length;
    more.hidden = left <= 0;
    if (left > 0) more.textContent = t("events.more", { n: Math.min(EVENT_STEP, left) });
    list.replaceChildren(...rows.map((e) => eventRow(e, hosts, false)));
    $("events-empty").hidden = rows.length > 0;
    $("events-count").textContent = !all.length ? "" : all.length > rows.length ? t("events.countCapped", { n: rows.length, total: all.length }) : t("events.count", { n: all.length });
  }

  function kv(pairs) {
    const dl = el("dl", undefined, "kv");
    for (const [label, value, mono] of pairs) {
      if (value === undefined || value === null || value === "") continue;
      const d = el("div");
      const dd = el("dd");
      if (value instanceof Node) dd.appendChild(value);
      else dd.appendChild(mono ? el("code", String(value)) : document.createTextNode(String(value)));
      d.append(el("dt", label), dd);
      dl.appendChild(d);
    }
    return dl;
  }

  function eventSheet(e, hosts) {
    const body = [
      kv([
        [t("ev.time"), dateTime(e.timestamp_ms)],
        [t("ev.kind"), kindLabel(e.kind)],
        [t("ev.result"), outcomeChip(e)],
        [t("ev.host"), e.host ? `${hostName(hosts, e.host)}${hostName(hosts, e.host) !== e.host ? ` (${e.host})` : ""}` : ""],
        [t("ev.session"), e.session, true],
        [t("ev.tool"), e.tool, true],
        [t("ev.rule"), e.rule, true],
        [t("ev.sev"), e.severity ? severity(e.severity) : ""],
        [t("ev.reason"), e.reason],
      ]),
      el("p", t("ev.seal"), "sheet-text muted"),
    ];
    return sheet({ title: t("ev.title", { seq: e.seq }), body, actions: [{ label: t("a11y.close"), kind: "ghost", value: true }] });
  }

  // Integrity and record --------------------------------------------------------------------

  function renderIntegrity(base) {
    const idBox = $("identity-chip");
    idBox.replaceChildren();
    if (!base.paired_here) idBox.appendChild(chip("neutral", t("integrity.notPaired")));
    else if (base.identity_matches === false) idBox.appendChild(chip("deny", t("integrity.differs")));
    else idBox.appendChild(chip("allow", t("integrity.matches")));

    const seq = base.status && base.status.last_signed_seq !== null && base.status.last_signed_seq !== undefined ? base.status.last_signed_seq : "–";
    $("integrity-sum").textContent = base.heads_total ? tn("integrity.sum", base.heads_total, { seq }) : t("integrity.sumNone");

    const heads = [...(base.heads || [])].reverse();
    const shown = S.headsExpanded ? heads : heads.slice(0, HEADS_DEFAULT);
    const list = $("heads");
    list.replaceChildren();
    for (const h of shown) {
      const li = el("li");
      const code = el("code", h.head, "hash");
      code.title = h.head;
      li.append(chip(h.valid ? "allow" : "deny", t(h.valid ? "head.verified" : "head.invalid")), el("span", `#${h.seq}`, "seq"), code, el("time", time(h.timestamp_ms, true)));
      list.appendChild(li);
    }
    const more = $("heads-more");
    more.hidden = heads.length <= HEADS_DEFAULT;
    more.textContent = S.headsExpanded ? t("integrity.less") : t("integrity.more", { n: heads.length });
  }

  async function openRecord() {
    if (S.recordBusy) return;
    S.recordBusy = true;
    const btn = $("open-record");
    btn.disabled = true;
    $("record-status").textContent = t("record.opening");
    try {
      S.record = await S.invoke("open_record");
      renderRecord();
    } catch (err) {
      S.record = null;
      $("record-status").textContent = `${t("record.failedOpen")}: ${friendlyError(err)}`;
      $("record-status").dataset.kind = "bad";
      $("record-list").replaceChildren();
      $("record-tools").hidden = true;
    } finally {
      S.recordBusy = false;
      btn.disabled = false;
      setButtonLabel(btn, t(S.record ? "record.reopen" : "record.open"));
    }
  }

  function recordKindLabel(kind) {
    const key = `rk.${kind}`;
    return window.HAWK.i18n.has(key) ? t(key) : kind;
  }

  function renderRecord() {
    const rec = S.record;
    const status = $("record-status");
    if (!rec) return;
    status.dataset.kind = rec.verified ? "good" : "bad";
    status.replaceChildren(icon(rec.verified ? "check" : "alert"), el("span", rec.verified ? `${t("record.verified")} · ${rec.events.length}` : t("record.failed")));

    const kinds = [...new Set(rec.events.map((e) => e.kind))];
    const select = $("r-kind");
    const current = select.value;
    select.replaceChildren(new Option(t("record.allKinds"), ""));
    for (const k of kinds) select.appendChild(new Option(recordKindLabel(k), k));
    select.value = kinds.includes(current) ? current : "";
    $("record-tools").hidden = !rec.events.length;

    const wanted = select.value;
    const events = [...rec.events].filter((e) => !wanted || e.kind === wanted).reverse();
    const list = $("record-list");
    list.replaceChildren();
    if (!rec.events.length) { list.appendChild(el("li", t("record.empty"), "muted")); $("record-count").textContent = ""; return; }
    $("record-count").textContent = t("record.count", { n: events.length, total: rec.events.length });
    for (const e of events) list.appendChild(recordEntry(e));
  }

  function recordEntry(e) {
    const li = el("li");
    const d = el("details", undefined, "rec");
    const sum = el("summary");
    const c = e.content;
    const decision = c && c.decision && c.decision.decision;
    sum.append(
      el("span", `#${e.seq}`, "seq"),
      el("span", recordKindLabel(e.kind), "rk"),
      el("span", c && c.call && c.call.tool ? c.call.tool : "", "rtool"),
      decision && ["allow", "ask", "deny"].includes(decision) ? chip(decision, t(`verdict.${decision}`)) : el("span"),
      el("time", time(e.timestamp_ms, true)),
      icon("chevron", "caret"),
    );
    d.appendChild(sum);
    // The body is built when it is opened: records can be long.
    d.addEventListener("toggle", () => {
      if (d.open && !d.querySelector(".rec-body")) d.appendChild(recordBody(e));
    });
    li.appendChild(d);
    return li;
  }

  function recordBody(e) {
    const box = el("div", undefined, "rec-body");
    const c = e.content;
    if (c === null || c === undefined) { box.appendChild(el("p", t("record.noContent"), "muted")); return box; }
    if (e.kind === "Decision" && c && typeof c === "object" && c.call) {
      const call = c.call;
      box.appendChild(section(t("rec.call"), kv([
        [t("rec.tool"), call.tool, true],
        [t("rec.cwd"), call.cwd, true],
        [t("rec.session"), call.session, true],
        [t("rec.host"), call.host, true],
        [t("rec.callId"), call.call_id, true],
      ])));
      if (call.args !== undefined) {
        box.appendChild(section(t("rec.args"), el("pre", pretty(call.args), "json")));
      }
      const dec = c.decision || {};
      const decNodes = [];
      if (["allow", "ask", "deny"].includes(dec.decision)) decNodes.push(chip(dec.decision, t(`verdict.${dec.decision}`)));
      if (dec.reason) decNodes.push(el("p", dec.reason, "sheet-text"));
      box.appendChild(section(t("rec.decision"), decNodes));
      const findings = Array.isArray(c.findings) ? c.findings : [];
      const fList = el("ul", undefined, "findings");
      if (!findings.length) fList.appendChild(el("li", t("rec.noFindings"), "muted"));
      for (const f of findings) {
        const li = el("li");
        li.append(severity(f.severity), el("code", f.rule), el("span", f.reason));
        fList.appendChild(li);
      }
      box.appendChild(section(t("rec.findings"), fList));
      box.appendChild(section(t("rec.contain"), chip(c.contain ? "contain" : "neutral", c.contain ? t("rec.containYes") : t("rec.containNo"))));
    } else if (typeof c === "object" && !Array.isArray(c)) {
      const scalars = [];
      const nested = [];
      for (const [k, v] of Object.entries(c)) (v !== null && typeof v === "object" ? nested : scalars).push([k, v]);
      if (scalars.length) box.appendChild(section(t("rec.fields"), kv(scalars.map(([k, v]) => [k, v === null ? t("common.none") : String(v), true]))));
      for (const [k, v] of nested) box.appendChild(section(k, el("pre", pretty(v), "json")));
    } else {
      box.appendChild(el("pre", pretty(c), "json"));
    }
    const raw = el("details", undefined, "raw");
    raw.append(el("summary", t("record.raw")), el("pre", pretty(c), "json"));
    box.appendChild(raw);
    return box;
  }

  function section(title, content) {
    const s = el("section", undefined, "rec-sec");
    s.appendChild(el("h4", title));
    for (const n of Array.isArray(content) ? content : [content]) s.appendChild(n);
    return s;
  }

  // Settings ---------------------------------------------------------------------------------

  function renderSettings(base) {
    const st = base.status || {};
    $("set-core-name").textContent = st.name || (S.info && S.info.core && S.info.core.name) || t("core.default");
    $("set-core-fp").textContent = S.info && S.info.core ? S.info.core.fingerprint : t("common.none");
    $("set-firewall").textContent = st.firewall || t("settings.fwNone");
    $("set-thresholds").textContent = thresholdsText(st.thresholds);
    $("set-events").textContent = st.events !== undefined ? number(st.events) : t("common.none");
    $("device-fp").textContent = S.info ? S.info.device_fingerprint : t("common.none");
    $("version").textContent = S.info ? `v${S.info.version}` : "";
    syncSegments();
  }

  function syncSegments() {
    const theme = store.get("hawk.theme", "auto");
    for (const b of $("theme-seg").querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.dataset.themeChoice === theme));
    for (const b of $("lang-seg").querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.dataset.langChoice === lang()));
    for (const b of $("range").querySelectorAll("button")) b.setAttribute("aria-pressed", String(Number(b.dataset.min) === S.rangeMin));
  }

  const dark = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  function applyTheme() {
    const choice = store.get("hawk.theme", "auto");
    const effective = choice === "auto" ? (dark && dark.matches ? "dark" : "light") : choice;
    document.documentElement.dataset.theme = effective;
  }

  // Attention thresholds (ADR-0033): from which severity HAWK asks, and from which it denies.
  // Critical always denies and isolates; a high finding at least asks.

  const DEFAULT_THRESHOLDS = { ask_from: "medium", deny_from: "high" };
  const SEV_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

  function activeThresholds() {
    const st = (S.data && S.data.status) || (S.lastGood && S.lastGood.status) || {};
    return st.thresholds || DEFAULT_THRESHOLDS;
  }

  function sevLabel(sev) {
    return sev === "critical" ? t("cfg.denyCriticalOnly") : t(`sev.${sev in SEV_RANK ? sev : "high"}`);
  }

  function thresholdsText(th) {
    const v = th || DEFAULT_THRESHOLDS;
    return t("settings.thresholdsValue", { ask: sevLabel(v.ask_from), deny: sevLabel(v.deny_from) });
  }

  // The config form, shared by the wizard and Ajustes ----------------------------------------

  function configForm({ name, thresholds, submitLabel, skipLabel, onSaved, onSkip }) {
    const node = document.getElementById("tpl-config").content.firstElementChild.cloneNode(true);
    apply(node);
    const f = node.elements;
    const err = node.querySelector(".form-error");
    const fwNote = node.querySelector("[data-fw-note]");
    const router = node.querySelector(".router");
    f.name.value = name || "";
    const th = thresholds || DEFAULT_THRESHOLDS;
    f.ask.value = th.ask_from in SEV_RANK && th.ask_from !== "critical" ? th.ask_from : DEFAULT_THRESHOLDS.ask_from;
    f.deny.value = th.deny_from in SEV_RANK ? th.deny_from : DEFAULT_THRESHOLDS.deny_from;
    const sync = () => {
      const kind = f.fw.value;
      router.hidden = kind === "dry_run";
      for (const only of node.querySelectorAll("[data-only]")) only.hidden = only.dataset.only !== kind;
      fwNote.textContent = t(kind === "dry_run" ? "cfg.fwDryNote" : kind === "mikrotik" ? "cfg.fwMikrotikNote" : "cfg.fwOpenwrtNote");
    };
    f.fw.addEventListener("change", sync);
    sync();
    const submit = node.querySelector("[data-submit]");
    submit.textContent = submitLabel;
    const skip = node.querySelector("[data-skip]");
    if (skipLabel) { skip.hidden = false; skip.textContent = skipLabel; skip.addEventListener("click", onSkip); }

    const show = (msg) => { err.hidden = !msg; err.textContent = msg || ""; };
    node.addEventListener("submit", async (event) => {
      event.preventDefault();
      show("");
      const nameValue = f.name.value.trim();
      if (!nameValue) { show(t("cfg.needName")); f.name.focus(); return; }
      let firewall = { kind: f.fw.value };
      if (f.fw.value !== "dry_run") {
        if (!f.url.value.trim() || !f.user.value.trim()) { show(t("cfg.needRouter")); (f.url.value.trim() ? f.user : f.url).focus(); return; }
        // Exactly the shape of `FirewallConfig` in guardian-core (serde, tag "kind")
        firewall = { kind: f.fw.value, url: f.url.value.trim(), user: f.user.value.trim(), password: f.password.value, cert_sha256: f.cert.value.trim() || null };
        if (f.fw.value === "mikrotik") firewall.list = f.list.value.trim() || null;
      }
      const chosen = { ask_from: f.ask.value, deny_from: f.deny.value };
      if (SEV_RANK[chosen.ask_from] > SEV_RANK[chosen.deny_from]) { show(t("cfg.badThresholds")); f.ask.focus(); return; }
      submit.disabled = true;
      const label = submit.textContent;
      submit.textContent = t("cfg.saving");
      try {
        // Exactly the shape of `Thresholds` in guardian-core; the Rust command signs it.
        const saved = await S.invoke("configure_core", { name: nameValue, firewall, thresholds: chosen });
        f.password.value = "";
        await onSaved(saved);
      } catch (e) {
        show(friendlyError(e));
      } finally {
        submit.disabled = false;
        submit.textContent = label;
      }
    });
    return node;
  }

  async function reconfigure() {
    const name = (S.info && S.info.core && S.info.core.name) || "";
    const form = configForm({
      name,
      thresholds: activeThresholds(),
      submitLabel: t("cfg.saveSettings"),
      onSaved: async (saved) => {
        closeSheet(true);
        toast(t("settings.saved", { name: saved }), "info");
        await loadInfo();
        refresh();
      },
    });
    await sheet({ title: t("settings.reconfTitle"), body: [el("p", t("settings.reconfNote"), "sheet-text muted"), form], actions: [] });
  }

  async function changeCore() {
    const ok = await confirmSheet({ title: t("settings.changeTitle"), text: t("settings.changeText"), confirmLabel: t("settings.changeConfirm"), icon: "x" });
    if (!ok) return;
    try {
      await S.invoke("forget_core");
    } catch (err) {
      toast(friendlyError(err), "error");
      return;
    }
    S.data = null;
    S.lastGood = null;
    S.record = null;
    await loadInfo();
    openWizard();
  }

  // Activation (ADR-0024) ---------------------------------------------------------------------

  const STEPS = ["find", "verify", "pair", "configure"];

  function wizardStep(step) {
    S.wizardStep = step;
    for (const section of document.querySelectorAll("#wizard .step")) section.hidden = section.dataset.step !== step;
    for (const li of $("steps").children) {
      const at = STEPS.indexOf(li.dataset.step);
      const now = STEPS.indexOf(step);
      li.className = at < now ? "done" : at === now ? "current" : "";
      if (at === now) li.setAttribute("aria-current", "step"); else li.removeAttribute("aria-current");
    }
    wizardError("");
    const heading = document.querySelector(`#wizard .step[data-step="${step}"] h2`);
    if (heading) { heading.setAttribute("tabindex", "-1"); heading.focus({ preventScroll: true }); }
    $("wizard").scrollTop = 0;
  }

  function wizardError(text) {
    $("wizard-error").hidden = !text;
    $("wizard-error").textContent = text || "";
  }

  async function scan() {
    $("scan-spinner").classList.remove("idle");
    $("scan-status").textContent = t("wiz.scanning");
    $("scan").disabled = true;
    const list = $("found");
    list.replaceChildren();
    try {
      const cores = await S.invoke("discover");
      $("scan-status").textContent = cores.length ? tn("wiz.scanFound", cores.length) : t("wiz.scanNone");
      for (const core of cores) list.appendChild(foundCore(core));
    } catch (err) {
      $("scan-status").textContent = t("wiz.scanFail");
      wizardError(friendlyError(err));
    } finally {
      $("scan-spinner").classList.add("idle");
      $("scan").disabled = false;
    }
  }

  function foundCore(core) {
    const li = el("li");
    const pick = el("button", undefined, "pick");
    pick.type = "button";
    const unpaired = core.state === "unpaired";
    pick.disabled = !unpaired;
    pick.title = unpaired ? t("wiz.pickTitle") : t("wiz.activeTitle");
    const top = el("span", undefined, "f-top");
    top.append(el("span", core.name, "f-name"), chip(unpaired ? "ask" : "neutral", unpaired ? t("wiz.ready") : t("wiz.active")));
    pick.append(top, el("code", `${core.fingerprint} · ${core.address}`, "f-meta"));
    if (unpaired) pick.appendChild(icon("chevron", "caret"));
    pick.addEventListener("click", () => chooseCore(core));
    li.appendChild(pick);
    return li;
  }

  function chooseCore(core) {
    S.chosen = core;
    $("verify-fp").textContent = core.fingerprint;
    wizardStep("verify");
  }

  async function probe(event) {
    event.preventDefault();
    const address = $("manual-addr").value.trim();
    if (!address) return;
    wizardError("");
    $("manual-go").disabled = true;
    try {
      const core = await S.invoke("probe_core", { address });
      if (core.state !== "unpaired") { wizardError(t("wiz.manualActive", { name: core.name, fp: core.fingerprint })); return; }
      chooseCore(core);
    } catch (err) {
      wizardError(t("wiz.manualFail", { addr: address, err: friendlyError(err) }));
    } finally {
      $("manual-go").disabled = false;
    }
  }

  async function pair() {
    wizardStep("pair");
    $("pair-code-wrap").hidden = true;
    $("pair-hint").hidden = true;
    for (const id of ["pair-ok", "pair-no", "pair-retry"]) $(id).hidden = true;
    $("pair-intro").textContent = t("wiz.pairWorking");
    try {
      const result = await S.invoke("pair_core", { id: S.chosen.id, address: S.chosen.address });
      $("pair-intro").textContent = t("wiz.pairDone");
      const code = String(result.confirmation_code);
      $("pair-code").textContent = code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
      $("pair-code-wrap").hidden = false;
      $("pair-hint").hidden = false;
      $("pair-ok").hidden = false;
      $("pair-no").hidden = false;
      $("pair-ok").focus({ preventScroll: true });
    } catch (err) {
      $("pair-intro").textContent = t("wiz.pairFail");
      wizardError(friendlyError(err));
      $("pair-retry").hidden = false;
    }
  }

  async function pairMismatch() {
    try { await S.invoke("forget_core"); } catch (e) { /* nothing was kept */ }
    await loadInfo();
    wizardStep("find");
    wizardError(t("wiz.pairDiscarded"));
    scan();
  }

  function mountWizardConfig() {
    const box = $("wizard-config");
    box.replaceChildren(configForm({
      name: "",
      submitLabel: t("cfg.save"),
      skipLabel: t("cfg.later"),
      onSaved: async () => { await closeWizard(); },
      onSkip: () => closeWizard(),
    }));
  }

  function openWizard() {
    stopRefresh();
    document.body.classList.add("in-wizard");
    $("wizard").hidden = false;
    $("app").setAttribute("aria-hidden", "true");
    $("app").inert = true;
    wizardStep("find");
    scan();
  }

  async function closeWizard() {
    $("wizard").hidden = true;
    $("app").removeAttribute("aria-hidden");
    $("app").inert = false;
    document.body.classList.remove("in-wizard");
    await loadInfo();
    go("overview");
    startRefresh();
  }

  // Data ------------------------------------------------------------------------------------------

  async function loadInfo() {
    S.info = await S.invoke("app_info");
    $("version").textContent = `v${S.info.version}`;
    $("device-fp").textContent = S.info.device_fingerprint;
    return S.info;
  }

  function noticeAlerts(events) {
    const alerts = events.filter((e) => e.kind === "alert");
    const latest = alerts.length ? alerts[alerts.length - 1].seq : 0;
    if (S.seenAlertSeq === null) { S.seenAlertSeq = latest; return; }
    if (latest > S.seenAlertSeq) {
      S.seenAlertSeq = latest;
      const reason = alerts[alerts.length - 1].reason || t("banner.alertFallback");
      const text = t("banner.alert", { reason });
      S.alertBanner = { text, until: Date.now() + 8000 };
      toast(text, "alert", 7000);
      setTimeout(renderAll, 8100);
    }
  }

  function noticeAsks(asks, hosts) {
    const ids = new Set(asks.map((a) => a.id));
    if (S.knownAsks === null) { S.knownAsks = ids; return; }
    for (const a of asks) {
      if (!S.knownAsks.has(a.id)) toast(`${a.tool} · ${t("asks.on", { host: hostName(hosts, a.host) })}`, "alert", 6000);
    }
    S.knownAsks = ids;
  }

  async function refresh() {
    if (S.inFlight) return;
    S.inFlight = true;
    try {
      const d = await S.invoke("dashboard");
      S.data = d;
      if (d.reachable) {
        S.lastGood = d;
        S.lastGoodAt = Date.now();
        noticeAlerts(d.events || []);
        noticeAsks(d.asks || [], d.hosts || []);
      }
      renderAll();
    } catch (err) {
      S.data = { reachable: false, error: String(err), paired_here: false, identity_matches: null, status: null, events: [], hosts: [], asks: [], heads_total: 0, heads_invalid: 0, heads: [] };
      renderAll();
    } finally {
      S.inFlight = false;
    }
  }

  function startRefresh() {
    stopRefresh();
    const loop = async () => {
      if (!document.hidden) await refresh();
      S.timer = setTimeout(loop, REFRESH_MS);
    };
    loop();
  }
  function stopRefresh() {
    if (S.timer) clearTimeout(S.timer);
    S.timer = null;
  }

  // Wiring ------------------------------------------------------------------------------------------

  function wire() {
    K.wireSheet();
    applyTheme();
    if (dark && dark.addEventListener) dark.addEventListener("change", applyTheme);

    for (const b of $("range").querySelectorAll("button")) {
      b.addEventListener("click", () => {
        S.rangeMin = Number(b.dataset.min);
        store.set("hawk.range", S.rangeMin);
        syncSegments();
        renderAll();
      });
    }
    for (const b of $("theme-seg").querySelectorAll("button")) {
      b.addEventListener("click", () => { store.set("hawk.theme", b.dataset.themeChoice); applyTheme(); syncSegments(); });
    }
    for (const b of $("lang-seg").querySelectorAll("button")) {
      b.addEventListener("click", () => setLang(b.dataset.langChoice));
    }
    document.addEventListener("hawk:lang", () => {
      buildNav();
      go(S.view, { silent: true });
      renderAll();
      syncSegments();
      refreshChartToggle();
      if (!$("wizard").hidden) { renderWizardLang(); }
      if (S.record) renderRecord();
    });

    $("chart-toggle").addEventListener("click", () => {
      S.chartAsTable = !S.chartAsTable;
      refreshChartToggle();
      renderChart();
    });
    new ResizeObserver(() => { if (S.view === "overview" && !S.chartAsTable) renderChart(); }).observe($("chart-wrap"));

    $("host-filter").addEventListener("input", () => { const e = effective(); if (e.base) renderHosts(e.base, e.stale); });
    const redrawEvents = (reset) => { if (reset) S.eventLimit = EVENT_STEP; const e = effective(); if (e.base) renderEvents(e.base); };
    for (const id of ["f-outcome", "f-severity"]) $(id).addEventListener("change", () => redrawEvents(true));
    $("f-text").addEventListener("input", () => redrawEvents(true));
    $("events-more").addEventListener("click", () => { S.eventLimit = (S.eventLimit || EVENT_STEP) + EVENT_STEP; redrawEvents(false); });
    $("heads-more").addEventListener("click", () => { S.headsExpanded = !S.headsExpanded; const e = effective(); if (e.base) renderIntegrity(e.base); });
    $("open-record").addEventListener("click", openRecord);
    $("r-kind").addEventListener("change", renderRecord);
    $("reconfigure").addEventListener("click", reconfigure);
    $("change-core").addEventListener("click", changeCore);
    $("banner-retry").addEventListener("click", refresh);
    for (const b of document.querySelectorAll("[data-go]")) b.addEventListener("click", () => go(b.dataset.go));

    // Activation
    $("scan").addEventListener("click", scan);
    $("manual-form").addEventListener("submit", probe);
    $("verify-ok").addEventListener("click", pair);
    $("pair-ok").addEventListener("click", () => { wizardStep("configure"); mountWizardConfig(); });
    $("pair-no").addEventListener("click", pairMismatch);
    for (const back of document.querySelectorAll("[data-back]")) back.addEventListener("click", () => { wizardStep(back.dataset.back); if (back.dataset.back === "find") scan(); });

    document.addEventListener("visibilitychange", () => { if (!document.hidden && S.timer) refresh(); });
    window.addEventListener("hashchange", () => go(viewFromHash(), { silent: true }));
    setInterval(() => { tickAsks(); }, 1000);
  }

  function renderWizardLang() {
    if (S.wizardStep === "configure") mountWizardConfig();
    if (S.wizardStep === "find") $("scan-status").textContent = "";
    if (S.chosen && S.wizardStep === "verify") $("verify-fp").textContent = S.chosen.fingerprint;
  }

  function refreshChartToggle() {
    $("chart-toggle").setAttribute("aria-pressed", String(S.chartAsTable));
    $("chart-toggle").textContent = S.chartAsTable ? t("chart.asChart") : t("chart.asTable");
    $("chart-wrap").hidden = S.chartAsTable;
    $("legend").hidden = S.chartAsTable;
    $("chart-table-wrap").hidden = !S.chartAsTable;
  }

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = src;
      s.onload = resolve;
      s.onerror = reject;
      document.head.appendChild(s);
    });
  }

  async function boot() {
    // Outside Tauri (a plain browser), load sample data so the design can be
    // reviewed without a Core. Inside the app this branch never runs.
    if (!window.__TAURI__) await loadScript("preview.js");
    S.invoke = window.__TAURI__.core.invoke;
    // Android web views that draw edge to edge without reporting a safe area
    // get a fixed inset for the status and navigation bars.
    if (/Android/.test(navigator.userAgent)) {
      document.documentElement.style.setProperty("--inset-top", "28px");
      document.documentElement.style.setProperty("--inset-bottom", "16px");
    }
    apply();
    buildNav();
    wire();
    refreshChartToggle();
    go(viewFromHash(), { silent: true });
    try {
      const info = await loadInfo();
      if (info.core) startRefresh();
      else openWizard();
    } catch (err) {
      toast(friendlyError(err), "error");
      openWizard();
    } finally {
      syncSegments();
      document.body.classList.remove("booting");
    }
  }

  boot();
})();
