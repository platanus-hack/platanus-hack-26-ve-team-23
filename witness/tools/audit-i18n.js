#!/usr/bin/env node
// Audit of the app's text: every key the HTML and the scripts use exists in
// Spanish and English, both dictionaries have the same keys, and the same
// {placeholders}. Run from anywhere: node witness/tools/audit-i18n.js
"use strict";
const fs = require("fs");
const path = require("path");
const dir = path.join(__dirname, "..", "ui");
const read = (f) => fs.readFileSync(path.join(dir, f), "utf8");

// Load the dictionaries by running the i18n file against a small fake window.
const store = {};
global.window = { HAWK: {}, matchMedia: () => ({ matches: false }), addEventListener() {} };
global.localStorage = { getItem: (k) => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = v; } };
Object.defineProperty(global, "navigator", { value: { language: "es-VE", languages: ["es-VE"] }, configurable: true });
global.document = { documentElement: { lang: "", dataset: {} }, querySelectorAll: () => [], title: "" };
const src = read("i18n.js").replace("const dicts = { es, en };", "const dicts = { es, en }; window.HAWK.__dicts = dicts;");
new Function(src).call(global);
const { es, en } = window.HAWK.__dicts;

let failures = 0;
const fail = (msg) => { failures++; console.log("FAIL " + msg); };

const esKeys = new Set(Object.keys(es));
const enKeys = new Set(Object.keys(en));
for (const k of esKeys) if (!enKeys.has(k)) fail(`missing in EN: ${k}`);
for (const k of enKeys) if (!esKeys.has(k)) fail(`missing in ES: ${k}`);

const holders = (text) => [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(",");
for (const k of esKeys) if (enKeys.has(k) && holders(es[k]) !== holders(en[k])) fail(`placeholders differ: ${k}  es[${holders(es[k])}] en[${holders(en[k])}]`);
for (const [lang, dict] of [["es", es], ["en", en]]) for (const [k, v] of Object.entries(dict)) if (!String(v).trim()) fail(`empty ${lang}: ${k}`);

// Keys used in the HTML
const html = read("index.html");
const used = new Map();
const add = (key, where) => { if (!used.has(key)) used.set(key, new Set()); used.get(key).add(where); };
for (const m of html.matchAll(/data-i18n(?:-ph|-label)?="([^"]+)"/g)) add(m[1], "index.html");

// Keys used in the scripts: t("a.b"), tn("a.b", ...) (needs .one and .other)
const plural = new Set();
for (const f of ["app.js", "kit.js", "chart.js", "preview.js"]) {
  const js = read(f);
  for (const m of js.matchAll(/\bt\(\s*"([\w.\-]+)"/g)) add(m[1], f);
  for (const m of js.matchAll(/\btn\(\s*"([\w.\-]+)"/g)) { plural.add(m[1]); add(`${m[1]}.one`, f); add(`${m[1]}.other`, f); }
  for (const m of js.matchAll(/\bt\(\s*`([^`]+)`/g)) {
    // dynamic key: check that at least one key has the prefix, and list it
    const prefix = m[1].split("${")[0];
    const hit = [...esKeys].filter((k) => k.startsWith(prefix));
    if (!hit.length) fail(`dynamic key without any match: ${m[1]} (${f})`);
    else console.log(`note dynamic ${f}: ${m[1]} -> ${hit.length} keys`);
  }
}
for (const [key, where] of used) {
  if (!esKeys.has(key)) fail(`used but not in ES: ${key}  (${[...where].join(", ")})`);
  if (!enKeys.has(key)) fail(`used but not in EN: ${key}  (${[...where].join(", ")})`);
}

// Keys defined but never used (a hint, not a failure): dynamic prefixes are skipped.
const dynamicPrefixes = [...["app.js", "kit.js", "chart.js", "preview.js"].flatMap((f) => [...read(f).matchAll(/\bt\(\s*`([^`]+)`/g)].map((m) => m[1].split("${")[0]))];
const unused = [...esKeys].filter((k) => !used.has(k) && !dynamicPrefixes.some((p) => k.startsWith(p)));
if (unused.length) console.log(`hint: ${unused.length} keys not referenced literally: ${unused.slice(0, 40).join(", ")}${unused.length > 40 ? " …" : ""}`);

console.log(`${esKeys.size} keys ES, ${enKeys.size} keys EN, ${used.size} used literally, ${failures} problems`);
process.exit(failures ? 1 : 0);
