// HAWK Pi: a Raspberry Pi 4 Model B built in code, in HAWK's greys.
//
// Dimensions follow the public mechanical drawing (85 x 56 mm board, holes
// at 3.5 / 61.5 by 3.5 / 52.5, GPIO 2x20 at 2.54 mm, USB stacks and RJ45 on
// the right edge, USB-C, two micro HDMI and the audio jack on the bottom
// edge, microSD under the board). Nothing here is copied from a CAD file.
// No logos of third parties: the board carries the HAWK mark.
//
// Coordinates in this file are millimetres on the board: x runs along the
// long side (0 left, 85 right), z across it (0 on the GPIO side, 56 on the
// front edge), y up from the board's top face.

import * as THREE from "three";
import { RoundedBoxGeometry } from "./vendor/addons/RoundedBoxGeometry.js";
import { RoomEnvironment } from "./vendor/addons/RoomEnvironment.js";

export const W = 85, D = 56, T = 1.4;

// A small seeded generator, so the board is the same every time.
function rng(seed) {
  let a = seed >>> 0;
  return function () {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Materials: grey and black only ---------------------------------------------
function materials() {
  const std = (o) => new THREE.MeshStandardMaterial(o);
  return {
    pcbEdge: std({ color: 0x1f2124, roughness: 0.7 }),
    black: std({ color: 0x131415, roughness: 0.55 }),
    chip: std({ color: 0x17181a, roughness: 0.38, metalness: 0.05 }),
    metal: std({ color: 0xcfd2d5, roughness: 0.34, metalness: 0.9, envMapIntensity: 2.1 }),
    metalDark: std({ color: 0xa5a8ac, roughness: 0.4, metalness: 0.9, envMapIntensity: 1.9 }),
    pin: std({ color: 0xe4e5e7, roughness: 0.25, metalness: 0.95, envMapIntensity: 1.8 }),
    latch: std({ color: 0xc9cbcd, roughness: 0.5 }),
    tongueLight: std({ color: 0xd9dbdd, roughness: 0.45, emissive: 0x2a2b2c }),
    tongueDark: std({ color: 0x4a4c50, roughness: 0.5, emissive: 0x1c1d1e }),
    card: std({ color: 0x232426, roughness: 0.45 }),
    led: std({ color: 0xe6e7e8, roughness: 0.3, emissive: 0x4a4b4d }),
    cavity: std({ color: 0x090909, roughness: 0.9 }),
  };
}

// Board texture: traces, pads, silkscreen --------------------------------------
function boardTexture(maxAniso) {
  const s = 20; // pixels per millimetre
  const c = document.createElement("canvas");
  c.width = W * s;
  c.height = D * s;
  const g = c.getContext("2d");
  const rand = rng(7);

  g.fillStyle = "#2b2e31";
  g.fillRect(0, 0, c.width, c.height);
  // fine speckle, so the mask is not a flat colour
  for (let i = 0; i < 9000; i++) {
    g.fillStyle = rand() > 0.5 ? "rgba(255,255,255,0.035)" : "rgba(0,0,0,0.06)";
    g.fillRect(rand() * c.width, rand() * c.height, 2, 2);
  }

  const P = (v) => v * s;
  g.lineCap = "round";
  g.lineJoin = "round";

  // Buses: parallel traces with a 45 degree jog between two runs
  function bus(x0, z0, x1, z1, n, gap, horizFirst) {
    g.strokeStyle = "#464a4f";
    g.lineWidth = P(0.2);
    for (let i = 0; i < n; i++) {
      const o = i * gap;
      g.beginPath();
      if (horizFirst) {
        const mid = (x0 + x1) / 2;
        g.moveTo(P(x0), P(z0 + o));
        g.lineTo(P(mid - Math.abs(z1 - z0) / 2), P(z0 + o));
        g.lineTo(P(mid + Math.abs(z1 - z0) / 2), P(z1 + o));
        g.lineTo(P(x1), P(z1 + o));
      } else {
        const mid = (z0 + z1) / 2;
        g.moveTo(P(x0 + o), P(z0));
        g.lineTo(P(x0 + o), P(mid - Math.abs(x1 - x0) / 2));
        g.lineTo(P(x1 + o), P(mid + Math.abs(x1 - x0) / 2));
        g.lineTo(P(x1 + o), P(z1));
      }
      g.stroke();
    }
  }
  bus(36, 26, 40, 28, 14, 0.45, true); // SoC to memory
  bus(22, 28, 30, 18, 10, 0.42, true); // SoC to radio
  bus(28, 36, 18, 44, 9, 0.42, false); // SoC to power
  bus(22, 29, 6, 29, 8, 0.4, true); // SoC to microSD
  bus(35, 22, 42, 7, 12, 0.5, false); // SoC to GPIO
  bus(50, 30, 66, 22, 10, 0.4, true); // SoC to USB hub
  bus(50, 36, 62, 44, 8, 0.4, true); // SoC to Ethernet PHY
  bus(66, 45, 66, 48, 8, 0.3, true);
  g.lineWidth = P(0.5);
  g.strokeStyle = "#4d5257";
  g.beginPath(); g.moveTo(P(9), P(46)); g.lineTo(P(13), P(46)); g.lineTo(P(17), P(42)); g.lineTo(P(21), P(42)); g.stroke();

  // Vias
  for (let i = 0; i < 380; i++) {
    const x = 5 + rand() * 75, z = 5 + rand() * 46;
    g.fillStyle = "#5a5f64";
    g.beginPath(); g.arc(P(x), P(z), P(0.34), 0, 6.283); g.fill();
    g.fillStyle = "#1c1e20";
    g.beginPath(); g.arc(P(x), P(z), P(0.14), 0, 6.283); g.fill();
  }

  // GPIO pads: 2 x 20 plated holes
  for (let r = 0; r < 2; r++) for (let k = 0; k < 20; k++) {
    const x = 32.5 - 24.13 + k * 2.54, z = 3.5 - 1.27 + r * 2.54;
    g.fillStyle = "#9da0a4";
    g.beginPath(); g.arc(P(x), P(z), P(0.95), 0, 6.283); g.fill();
    g.fillStyle = "#16181a";
    g.beginPath(); g.arc(P(x), P(z), P(0.42), 0, 6.283); g.fill();
  }
  // Mounting holes: ring pads
  for (const [x, z] of [[3.5, 3.5], [61.5, 3.5], [3.5, 52.5], [61.5, 52.5]]) {
    g.strokeStyle = "#8f9296"; g.lineWidth = P(0.5);
    g.beginPath(); g.arc(P(x), P(z), P(3.2), 0, 6.283); g.stroke();
  }

  // Pads under the big chips and connectors
  function padsRow(x, z, n, pitch, vertical, w, h) {
    g.fillStyle = "#8a8d91";
    for (let i = 0; i < n; i++) {
      const px = vertical ? x : x + i * pitch, pz = vertical ? z + i * pitch : z;
      g.fillRect(P(px - w / 2), P(pz - h / 2), P(w), P(h));
    }
  }
  padsRow(33.5, 40.2, 30, 0.5, false, 0.28, 0.9); // crystal and passives
  padsRow(15.2, 46, 12, 0.5, false, 0.25, 0.8);
  padsRow(38.5, 14.6, 22, 0.5, false, 0.25, 0.8);

  // Silkscreen
  g.strokeStyle = "#c4c6c8"; g.fillStyle = "#c4c6c8"; g.lineWidth = P(0.15);
  g.strokeRect(P(6.4), P(1.1), P(52.2), P(5.8)); // GPIO outline
  g.beginPath(); g.moveTo(P(6.4), P(3.2)); g.lineTo(P(5.2), P(3.2)); g.stroke();
  g.font = "600 " + P(1.3) + "px 'JetBrains Mono', monospace";
  g.fillText("1", P(5.4), P(1.1)); g.fillText("2", P(6.6), P(8.4));
  g.fillText("39", P(55.6), P(8.4)); g.fillText("40", P(55.4), P(0.9));
  g.font = "500 " + P(1.25) + "px 'JetBrains Mono', monospace";
  g.fillText("J8", P(60), P(2.2));
  g.fillText("POWER", P(7.2), P(54.6));
  g.fillText("HDMI0", P(22.4), P(54.6));
  g.fillText("HDMI1", P(35.9), P(54.6));
  g.fillText("AUDIO", P(49.3), P(54.6));
  g.fillText("CSI", P(41.6), P(38.2));
  g.fillText("DSI", P(8.4), P(15.8));
  g.fillText("ETH", P(71), P(53.6));
  g.fillText("USB 3.0", P(66), P(35));
  g.fillText("USB 2.0", P(66), P(17.4));
  g.font = "500 " + P(0.9) + "px 'JetBrains Mono', monospace";
  for (let i = 0; i < 90; i++) {
    const x = 4 + rand() * 78, z = 8 + rand() * 40;
    g.fillStyle = "rgba(196,198,200,0.55)";
    g.fillText((rand() > 0.5 ? "C" : "R") + Math.floor(rand() * 900 + 100), P(x), P(z));
  }
  // The HAWK mark and name: where a maker puts its own
  g.fillStyle = "#c4c6c8";
  g.save(); g.translate(P(63.2), P(50.2)); g.scale(P(0.115), P(0.115));
  g.beginPath(); g.moveTo(0, 0); g.lineTo(24, 5); g.lineTo(30, 22); g.lineTo(36, 5); g.lineTo(60, 0); g.lineTo(30, 36); g.closePath(); g.fill();
  g.restore();
  g.font = "700 " + P(2.6) + "px Saira, system-ui, sans-serif";
  g.fillText("HAWK", P(71.2), P(54));
  g.font = "500 " + P(1.25) + "px 'JetBrains Mono', monospace";
  g.fillText("CORE  v0.1  REV A", P(18), P(49.6));
  g.fillText("MADE IN CARACAS", P(18), P(51.4));

  const tex = new THREE.CanvasTexture(c);
  tex.flipY = false;
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.anisotropy = maxAniso;
  tex.repeat.set(1 / W, 1 / D);
  tex.wrapS = tex.wrapT = THREE.ClampToEdgeWrapping;
  return tex;
}


// The underside: pads, test points and the microSD footprint, drawn the right
// way round for someone who flips the board over.
function bottomTexture(maxAniso) {
  const s = 14;
  const c = document.createElement("canvas");
  c.width = W * s; c.height = D * s;
  const g = c.getContext("2d");
  const rand = rng(21);
  const P = (v) => v * s;
  g.fillStyle = "#3a3e42"; g.fillRect(0, 0, c.width, c.height);
  for (let i = 0; i < 6000; i++) {
    g.fillStyle = rand() > 0.5 ? "rgba(255,255,255,0.03)" : "rgba(0,0,0,0.06)";
    g.fillRect(rand() * c.width, rand() * c.height, 2, 2);
  }
  g.strokeStyle = "#3e4246"; g.lineWidth = P(0.2); g.lineCap = "round";
  for (let i = 0; i < 60; i++) {
    const x = 6 + rand() * 70, z = 6 + rand() * 44;
    g.beginPath(); g.moveTo(P(x), P(z)); g.lineTo(P(x + (rand() - 0.5) * 14), P(z)); g.lineTo(P(x + (rand() - 0.5) * 14), P(z + (rand() - 0.5) * 10)); g.stroke();
  }
  for (let i = 0; i < 260; i++) {
    g.fillStyle = "#5a5f64"; g.beginPath(); g.arc(P(5 + rand() * 75), P(5 + rand() * 46), P(0.32), 0, 6.283); g.fill();
  }
  // microSD footprint at the left edge
  g.strokeStyle = "#c4c6c8"; g.lineWidth = P(0.16);
  g.strokeRect(P(0.8), P(22), P(12.8), P(12));
  g.fillStyle = "#8a8d91";
  for (let i = 0; i < 8; i++) g.fillRect(P(1.6 + i * 1.25), P(24.4), P(0.8), P(2.6));
  g.fillStyle = "#c4c6c8";
  g.font = "600 " + P(1.4) + "px 'JetBrains Mono', monospace";
  g.fillText("microSD", P(2), P(36.4));
  g.font = "500 " + P(1.15) + "px 'JetBrains Mono', monospace";
  g.fillText("HAWK CORE  REV A", P(30), P(52.6));
  g.fillText("record.sealed lives here", P(30), P(50.6));
  g.save(); g.translate(P(60), P(26)); g.scale(P(0.2), P(0.2));
  g.beginPath(); g.moveTo(0, 0); g.lineTo(24, 5); g.lineTo(30, 22); g.lineTo(36, 5); g.lineTo(60, 0); g.lineTo(30, 36); g.closePath(); g.fill();
  g.restore();
  for (let r = 0; r < 2; r++) for (let k = 0; k < 20; k++) { // pin tails
    g.fillStyle = "#8a8d91";
    g.beginPath(); g.arc(P(32.5 - 24.13 + k * 2.54), P(3.5 - 1.27 + r * 2.54), P(0.85), 0, 6.283); g.fill();
  }
  const tex = new THREE.CanvasTexture(c);
  tex.flipY = false;
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.anisotropy = maxAniso;
  tex.repeat.set(1 / W, 1 / D);
  tex.wrapS = tex.wrapT = THREE.ClampToEdgeWrapping;
  return tex;
}

function lidTexture(maxAniso) {
  const c = document.createElement("canvas");
  c.width = c.height = 512;
  const g = c.getContext("2d");
  const grad = g.createLinearGradient(0, 0, 512, 512);
  grad.addColorStop(0, "#c9cbce"); grad.addColorStop(0.5, "#aeb1b5"); grad.addColorStop(1, "#bfc2c5");
  g.fillStyle = grad; g.fillRect(0, 0, 512, 512);
  for (let i = 0; i < 700; i++) { // brushed
    g.fillStyle = "rgba(255,255,255," + (0.02 + Math.random() * 0.04) + ")";
    g.fillRect(0, Math.random() * 512, 512, 1);
  }
  g.fillStyle = "#3b3e42";
  g.save(); g.translate(150, 150); g.scale(3.5, 3.5);
  g.beginPath(); g.moveTo(0, 0); g.lineTo(24, 5); g.lineTo(30, 22); g.lineTo(36, 5); g.lineTo(60, 0); g.lineTo(30, 36); g.closePath(); g.fill();
  g.restore();
  g.font = "600 34px 'JetBrains Mono', monospace";
  g.fillText("HAWK-SoC", 70, 380);
  g.font = "500 26px 'JetBrains Mono', monospace";
  g.fillText("Q4 4 x A72  2026", 70, 424);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  t.anisotropy = maxAniso;
  return t;
}

function shieldTexture(maxAniso) {
  const c = document.createElement("canvas");
  c.width = 512; c.height = 400;
  const g = c.getContext("2d");
  g.fillStyle = "#9a9da1"; g.fillRect(0, 0, 512, 400);
  g.strokeStyle = "#6f7276"; g.lineWidth = 6;
  g.strokeRect(14, 14, 484, 372);
  g.beginPath(); g.moveTo(256, 14); g.lineTo(256, 386); g.moveTo(14, 200); g.lineTo(498, 200); g.stroke();
  g.fillStyle = "#4a4d51";
  for (let r = 0; r < 4; r++) for (let k = 0; k < 8; k++) {
    g.beginPath(); g.arc(46 + k * 60, 54 + r * 100, 7, 0, 6.283); g.fill();
  }
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  t.anisotropy = maxAniso;
  return t;
}

// Geometry helpers --------------------------------------------------------------
function mesh(geo, mat, shadow = true) {
  const m = new THREE.Mesh(geo, mat);
  m.castShadow = shadow; m.receiveShadow = shadow;
  return m;
}
function box(w, h, d, mat, r = 0) {
  const geo = r > 0
    ? new RoundedBoxGeometry(w, h, d, 3, Math.min(r, w / 2 - 1e-3, h / 2 - 1e-3, d / 2 - 1e-3))
    : new THREE.BoxGeometry(w, h, d);
  return mesh(geo, mat);
}
function at(m, x, y, z) { m.position.set(x, y, z); return m; }

// A connector shell: a front profile with openings, extruded along +x.
// `width` runs along z, `height` along y (from 0 up). Holes are arrays of
// [z, y] points in the same frame, centred on z = 0.
function shell(width, height, depth, holes, mat) {
  const s = new THREE.Shape();
  s.moveTo(-width / 2, 0); s.lineTo(width / 2, 0); s.lineTo(width / 2, height); s.lineTo(-width / 2, height); s.lineTo(-width / 2, 0);
  for (const pts of holes) {
    const h = new THREE.Path();
    h.moveTo(pts[0][0], pts[0][1]);
    for (let i = 1; i < pts.length; i++) h.lineTo(pts[i][0], pts[i][1]);
    h.closePath();
    s.holes.push(h);
  }
  const geo = new THREE.ExtrudeGeometry(s, { depth, bevelEnabled: false });
  geo.rotateY(Math.PI / 2); // extrusion now runs along +x, profile x became -z
  geo.translate(-depth / 2, 0, 0);
  return mesh(geo, mat);
}
function rectHole(zc, y0, w, h) {
  return [[zc - w / 2, y0], [zc + w / 2, y0], [zc + w / 2, y0 + h], [zc - w / 2, y0 + h]];
}
function roundHole(zc, y0, w, h, r, n = 5) {
  const pts = [];
  const arc = (cx, cy, a0, a1) => { for (let i = 0; i <= n; i++) { const a = a0 + (a1 - a0) * i / n; pts.push([cx + r * Math.cos(a), cy + r * Math.sin(a)]); } };
  arc(zc + w / 2 - r, y0 + r, -Math.PI / 2, 0);
  arc(zc + w / 2 - r, y0 + h - r, 0, Math.PI / 2);
  arc(zc - w / 2 + r, y0 + h - r, Math.PI / 2, Math.PI);
  arc(zc - w / 2 + r, y0 + r, Math.PI, Math.PI * 1.5);
  return pts;
}

// The model ------------------------------------------------------------------------
export function buildPi({ renderer, shadows = false } = {}) {
  const M = materials();
  const aniso = renderer ? renderer.capabilities.getMaxAnisotropy() : 4;
  const root = new THREE.Group();
  const parts = [];
  const keyed = {};
  const occupied = []; // [x0, z0, x1, z1] where small parts must not land

  function reserve(x, z, w, d, pad = 0.8) { occupied.push([x - w / 2 - pad, z - d / 2 - pad, x + w / 2 + pad, z + d / 2 + pad]); }
  function put(obj, x, z, o = {}) {
    const g = new THREE.Group();
    g.add(obj);
    g.position.set(x - W / 2, o.lift || 0, z - D / 2);
    if (o.rotY) g.rotation.y = o.rotY;
    g.userData = { home: g.position.y, out: o.out || 0, key: o.key || null };
    root.add(g);
    parts.push(g);
    if (o.key) keyed[o.key] = g;
    if (o.size) reserve(x, z, o.size[0], o.size[1]);
    return g;
  }

  // The board ---------------------------------------------------------------------
  {
    const r = 3, sh = new THREE.Shape();
    sh.moveTo(r, 0); sh.lineTo(W - r, 0); sh.quadraticCurveTo(W, 0, W, r);
    sh.lineTo(W, D - r); sh.quadraticCurveTo(W, D, W - r, D);
    sh.lineTo(r, D); sh.quadraticCurveTo(0, D, 0, D - r);
    sh.lineTo(0, r); sh.quadraticCurveTo(0, 0, r, 0);
    for (const [x, z] of [[3.5, 3.5], [61.5, 3.5], [3.5, 52.5], [61.5, 52.5]]) {
      const p = new THREE.Path(); p.absarc(x, z, 1.35, 0, Math.PI * 2, true); sh.holes.push(p);
    }
    const geo = new THREE.ExtrudeGeometry(sh, { depth: T, bevelEnabled: false, curveSegments: 20 });
    const tex = boardTexture(aniso);
    const pcb = new THREE.MeshStandardMaterial({ map: tex, roughness: 0.72, metalness: 0.05, bumpMap: tex, bumpScale: 0.4 });
    const m = mesh(geo, [pcb, M.pcbEdge]);
    m.rotation.x = Math.PI / 2;
    m.position.set(-W / 2, T, -D / 2);
    root.add(m);
    const under = new THREE.Mesh(new THREE.ShapeGeometry(sh, 18), new THREE.MeshStandardMaterial({ map: bottomTexture(aniso), roughness: 0.75, metalness: 0.05 }));
    under.rotation.x = Math.PI / 2;
    under.position.set(-W / 2, -0.02, -D / 2);
    root.add(under);
  }
  // Everything below sits on the board's top face; the board spans y 0..T.
  function onBoard(obj, x, z, o = {}) {
    return put(obj, x, z, Object.assign({}, o, { lift: T + (o.lift || 0) }));
  }

  // SoC: dark substrate under a brushed metal lid
  {
    const g = new THREE.Group();
    const sub = box(15, 0.7, 15, M.chip, 0.3); sub.position.y = 0.35; g.add(sub);
    const lidMat = new THREE.MeshStandardMaterial({ color: 0xffffff, map: lidTexture(aniso), roughness: 0.3, metalness: 0.95, envMapIntensity: 1.1 });
    const lid = box(12.4, 1.05, 12.4, [M.metal, M.metal, lidMat, M.metal, M.metal, M.metal], 0.35);
    lid.position.y = 1.2; g.add(lid);
    onBoard(g, 29.5, 30.5, { out: 28, key: "soc", size: [15, 15] });
  }
  // Memory: black package with a tiny index dot
  {
    const g = new THREE.Group();
    const ram = box(11.2, 1.0, 10.2, M.chip, 0.25); ram.position.y = 0.5; g.add(ram);
    const dot = mesh(new THREE.CylinderGeometry(0.4, 0.4, 0.05, 14), M.tongueLight, false); dot.position.set(-4.6, 1.02, -4); g.add(dot);
    onBoard(g, 46.5, 30.5, { out: 20, size: [11.2, 10.2] });
  }
  // Radio: shielded can, brushed, with its frame lines
  {
    const g = new THREE.Group();
    const frame = box(13.4, 0.35, 10.6, M.metalDark, 0.15); frame.position.y = 0.175; g.add(frame);
    const lidMat = new THREE.MeshStandardMaterial({ color: 0xffffff, map: shieldTexture(aniso), roughness: 0.38, metalness: 0.9, envMapIntensity: 1.05 });
    const can = box(12.8, 1.5, 10.0, [M.metalDark, M.metalDark, lidMat, M.metalDark, M.metalDark, M.metalDark], 0.12);
    can.position.y = 1.1; g.add(can);
    onBoard(g, 17.5, 14.5, { out: 24, key: "radio", size: [13.4, 10.6] });
  }
  // Small chips: power management, USB hub, Ethernet PHY
  for (const [x, z, w, d, out] of [[21.5, 39.5, 5.4, 5.4, 12], [66, 21.5, 5, 5, 14], [61.5, 44, 7.2, 7.2, 16], [10.5, 36, 4, 4, 10]]) {
    const c = box(w, 0.8, d, M.chip, 0.2); c.position.y = 0.4;
    const dot = mesh(new THREE.CylinderGeometry(0.28, 0.28, 0.04, 12), M.tongueLight, false); dot.position.set(-w / 2 + 0.7, 0.81, -d / 2 + 0.7); c.add(dot);
    onBoard(c, x, z, { out, size: [w, d] });
  }
  // Crystals: two small metal cans
  for (const [x, z] of [[36.5, 41.5], [41, 17.6]]) {
    const c = box(3.2, 0.9, 2.5, M.metal, 0.2); c.position.y = 0.45;
    onBoard(c, x, z, { out: 8, size: [3.2, 2.5] });
  }
  // Status LEDs
  for (const [x, z] of [[6.2, 46.8], [6.2, 48.8]]) {
    const l = box(1.6, 0.5, 0.8, M.led); l.position.y = 0.25;
    onBoard(l, x, z, { size: [1.6, 0.8], out: 4 });
  }

  // GPIO header: housing plus 40 pins, instanced
  {
    const g = new THREE.Group();
    const housing = box(50.8, 2.5, 5.08, M.black, 0.12); housing.position.y = 1.25; g.add(housing);
    const pinGeo = new THREE.BoxGeometry(0.64, 11.5, 0.64);
    const pins = new THREE.InstancedMesh(pinGeo, M.pin, 40);
    const m4 = new THREE.Matrix4();
    let i = 0;
    for (let c = 0; c < 20; c++) for (let r = 0; r < 2; r++) {
      m4.makeTranslation(-24.13 + c * 2.54, 2.75, -1.27 + r * 2.54);
      pins.setMatrixAt(i++, m4);
    }
    pins.castShadow = true;
    g.add(pins);
    // little chamfer caps on the pin tips
    const cap = new THREE.InstancedMesh(new THREE.ConeGeometry(0.42, 0.5, 4), M.pin, 40);
    i = 0;
    for (let c = 0; c < 20; c++) for (let r = 0; r < 2; r++) {
      m4.makeRotationY(Math.PI / 4); m4.setPosition(-24.13 + c * 2.54, 8.7, -1.27 + r * 2.54);
      cap.setMatrixAt(i++, m4);
    }
    g.add(cap);
    onBoard(g, 32.5, 3.5, { out: 18, size: [51, 5.2] });
  }

  // Right edge: two USB stacks and the RJ45 ----------------------------------------
  function usbStack(tongueA, tongueB) {
    const g = new THREE.Group();
    const holes = [rectHole(0, 1.3, 13.2, 5.6), rectHole(0, 9.3, 13.2, 5.6)];
    const sh = shell(15.6, 16, 17.5, holes, M.metal);
    g.add(sh);
    const back = box(0.9, 16, 15.2, M.cavity); back.position.set(-(17.5 / 2 - 1.2), 8, 0); g.add(back);
    [[4.1, tongueA], [12.1, tongueB]].forEach(([y, mat]) => {
      const t = box(11.5, 1.9, 12, mat === "light" ? M.tongueLight : M.tongueDark, 0.1);
      t.rotation.y = Math.PI / 2; t.position.set(-1.1, y - 0.3, 0); g.add(t);
    });
    return g;
  }
  onBoard(usbStack("dark", "dark"), 78.4, 9, { out: 16, size: [17.5, 15.6] });
  onBoard(usbStack("light", "light"), 78.4, 27, { out: 16, size: [17.5, 15.6] });
  {
    const g = new THREE.Group();
    const hole = [[-5.9, 1.3], [5.9, 1.3], [5.9, 9.2], [2.6, 9.2], [2.6, 11.4], [-2.6, 11.4], [-2.6, 9.2], [-5.9, 9.2]];
    const sh = shell(16, 13.5, 21.2, [hole], M.metal);
    g.add(sh);
    const back = box(0.9, 13.5, 15.2, M.cavity); back.position.set(-(21.2 / 2 - 1.2), 6.75, 0); g.add(back);
    for (let i = 0; i < 8; i++) { // contacts along the roof of the socket
      const c = box(0.32, 0.25, 11, M.pin);
      c.position.set(-9.4 + 0.45 + 5.8, 8.95, -4.2 + i * 1.2); g.add(c);
    }
    const bar = box(11, 0.5, 11, M.tongueDark, 0.1); bar.position.set(-9.4 + 0.45 + 5.5, 2.0, 0); g.add(bar);
    [-6.2, 6.2].forEach((zz) => { const l = box(0.3, 0.9, 2.2, M.led); l.position.set(21.2 / 2 + 0.05, 0.55, zz); g.add(l); });
    onBoard(g, 75.4, 45.75, { out: 22, key: "eth", size: [21.2, 16] });
  }

  // Bottom edge: USB-C, two micro HDMI, audio jack -------------------------------------
  function front(obj, x, depth, o) { // a +x connector turned to face the front edge
    obj.rotation.y = -Math.PI / 2;
    const wrap = new THREE.Group(); wrap.add(obj);
    return onBoard(wrap, x, D - depth / 2 + 0.8, o);
  }
  {
    const g = new THREE.Group();
    const sh = shell(9, 3.2, 7.4, [roundHole(0, 0.38, 8.3, 2.46, 1.1)], M.metal);
    g.add(sh);
    const back = box(0.6, 3.2, 8.6, M.cavity); back.position.set(-(7.4 / 2 - 0.8), 1.6, 0); g.add(back);
    const t = box(6.6, 0.7, 4.6, M.tongueDark, 0.1); t.rotation.y = Math.PI / 2; t.position.set(-0.3, 1.6, 0); g.add(t);
    front(g, 11.2, 7.4, { out: 12, size: [9, 7.4] });
  }
  for (const x of [26, 39.5]) {
    const g = new THREE.Group();
    const hole = [[-2.8, 0.35], [2.8, 0.35], [2.8, 1.35], [2.15, 2.2], [-2.15, 2.2], [-2.8, 1.35]];
    const sh = shell(6.6, 2.9, 5.9, [hole], M.metal);
    g.add(sh);
    const back = box(0.6, 2.9, 6.0, M.cavity); back.position.set(-(5.9 / 2 - 0.8), 1.45, 0); g.add(back);
    const t = box(4.8, 0.45, 3.4, M.tongueDark, 0.05); t.rotation.y = Math.PI / 2; t.position.set(-0.2, 1.0, 0); g.add(t);
    front(g, x, 5.9, { out: 12, size: [6.6, 5.9] });
  }
  {
    const g = new THREE.Group();
    const body = box(6.8, 5.6, 12, M.black, 0.4); body.position.set(0, 2.8, 0); g.add(body);
    const ring = mesh(new THREE.CylinderGeometry(3.0, 3.0, 2.6, 28), M.black); ring.rotation.x = Math.PI / 2; ring.position.set(0, 3.0, 7.0); g.add(ring);
    const rim = mesh(new THREE.TorusGeometry(1.9, 0.35, 8, 28), M.metal); rim.position.set(0, 3.0, 8.35); g.add(rim);
    const hole = mesh(new THREE.CircleGeometry(1.65, 24), M.cavity, false); hole.position.set(0, 3.0, 8.31); g.add(hole);
    onBoard(g, 53.5, D - 6 + 1.6, { out: 14, size: [6.8, 12] });
  }

  // Ribbon connectors: camera (bottom, right of the HDMI ports) and display
  function zif(len, vertical, x, z, out) {
    const g = new THREE.Group();
    const body = box(len, 2.4, 3.6, M.black, 0.15); body.position.y = 1.2; g.add(body);
    const latch = box(len - 0.8, 1.0, 1.5, M.latch, 0.1); latch.position.set(0, 2.6, -0.5); g.add(latch);
    const slot = box(len - 2, 0.4, 0.5, M.cavity); slot.position.set(0, 1.8, 1.7); g.add(slot);
    if (vertical) g.rotation.y = Math.PI / 2;
    return onBoard(g, x, z, { out, size: vertical ? [3.6, len] : [len, 3.6] });
  }
  zif(22, false, 45.5, 46.6, 14);
  zif(22, true, 3.4, 29, 14);

  // microSD: metal slot and a card on the underside of the left edge
  {
    const g = new THREE.Group();
    const slot = box(12.4, 1.35, 12, M.metalDark, 0.15); slot.position.set(6.6, -0.675, 0); g.add(slot);
    const card = box(15.2, 0.85, 11, M.card, 0.2); card.position.set(0.9, -0.9, 0); g.add(card);
    const notch = box(1.3, 0.12, 0.9, M.cavity); notch.position.set(5.4, -1.35, 4.5); g.add(notch);
    const s = put(g, 0, 28, { lift: 0, out: -16, key: "sd" });
    s.position.x = -W / 2; s.userData.home = 0;
  }

  // Small parts: resistors, capacitors, inductors; instanced and seeded ----------------
  {
    const rand = rng(11);
    function free(x, z, w, d) {
      for (const o of occupied) if (x + w / 2 > o[0] && x - w / 2 < o[2] && z + d / 2 > o[1] && z - d / 2 < o[3]) return false;
      for (const h of [[3.5, 3.5], [61.5, 3.5], [3.5, 52.5], [61.5, 52.5]]) if (Math.hypot(x - h[0], z - h[1]) < 4.3) return false;
      return x > 2 && x < W - 2 && z > 2 && z < D - 2;
    }
    function scatter(count, w, h, d, mat, seedTilt) {
      const im = new THREE.InstancedMesh(new THREE.BoxGeometry(w, h, d), mat, count);
      const m4 = new THREE.Matrix4(), q = new THREE.Quaternion(), e = new THREE.Euler(), one = new THREE.Vector3(1, 1, 1);
      let n = 0, tries = 0;
      while (n < count && tries < count * 40) {
        tries++;
        const x = 3 + rand() * (W - 6), z = 3 + rand() * (D - 6);
        const rot = rand() > 0.5 ? 0 : Math.PI / 2;
        const ww = rot ? d : w, dd = rot ? w : d;
        if (!free(x, z, ww, dd)) continue;
        // keep them in loose clusters near chips, like a real layout
        if (rand() > 0.35 && Math.hypot(x - 30, z - 30) > 30) continue;
        occupied.push([x - ww / 2 - 0.15, z - dd / 2 - 0.15, x + ww / 2 + 0.15, z + dd / 2 + 0.15]);
        e.set(0, rot, 0); q.setFromEuler(e);
        m4.compose(new THREE.Vector3(x - W / 2, T + h / 2, z - D / 2), q, one);
        im.setMatrixAt(n++, m4);
      }
      im.count = n;
      im.castShadow = true;
      root.add(im);
      return im;
    }
    scatter(180, 1.0, 0.35, 0.5, M.chip);
    scatter(140, 1.0, 0.45, 0.5, new THREE.MeshStandardMaterial({ color: 0x8e9195, roughness: 0.5, metalness: 0.2 }));
    scatter(40, 1.6, 0.8, 0.8, M.chip);
    scatter(16, 2.5, 1.2, 2.0, new THREE.MeshStandardMaterial({ color: 0x2c2d2f, roughness: 0.4, metalness: 0.3 }));
    // a few on the underside, so the belly is not bare
    const im = new THREE.InstancedMesh(new THREE.BoxGeometry(1.0, 0.35, 0.5), M.chip, 120);
    const m4 = new THREE.Matrix4(); let n = 0;
    for (let i = 0; i < 240 && n < 120; i++) {
      const x = 14 + rand() * 52, z = 6 + rand() * 44;
      if (x < 14.5 && z > 20 && z < 36) continue;
      m4.makeTranslation(x - W / 2, -0.175, z - D / 2); im.setMatrixAt(n++, m4);
    }
    im.count = n; root.add(im);
  }

  // Explode, selection glow ------------------------------------------------------
  const base = new Map();
  parts.forEach((p) => p.traverse((o) => {
    if (o.isMesh) { o.material = Array.isArray(o.material) ? o.material.map((x) => x.clone()) : o.material.clone(); }
  }));
  function setExplode(a) {
    parts.forEach((p) => { p.position.y = p.userData.home + p.userData.out * a; });
  }
  function glow(key, on) {
    const g = keyed[key];
    if (!g) return;
    g.traverse((o) => {
      if (!o.isMesh) return;
      (Array.isArray(o.material) ? o.material : [o.material]).forEach((m) => {
        if (!m.emissive) return;
        if (!base.has(m)) base.set(m, m.emissive.clone());
        m.emissive.copy(on ? new THREE.Color(0x5b5e62) : base.get(m));
      });
    });
  }

  return { root, parts, keyed, setExplode, glow, size: { W, D, T } };
}

// Light and environment -------------------------------------------------------------
export function lights(scene, renderer, { shadows = false, soft = false } = {}) {
  const pm = new THREE.PMREMGenerator(renderer);
  scene.environment = pm.fromScene(new RoomEnvironment(), 0.04).texture;
  scene.add(new THREE.HemisphereLight(0xffffff, 0x8f918d, soft ? 0.9 : 0.6));
  const sun = new THREE.DirectionalLight(0xffffff, soft ? 1.6 : 2.4);
  sun.position.set(-60, 140, 80);
  if (shadows) {
    sun.castShadow = true;
    sun.shadow.mapSize.set(2048, 2048);
    const c = sun.shadow.camera; c.left = -95; c.right = 95; c.top = 95; c.bottom = -95; c.near = 10; c.far = 420;
    sun.shadow.radius = 6; sun.shadow.bias = -0.0004; sun.shadow.normalBias = 0.35;
  }
  scene.add(sun);
  const rim = new THREE.DirectionalLight(0xffffff, soft ? 0.5 : 0.9);
  rim.position.set(90, 60, -80);
  scene.add(rim);
  const under = new THREE.DirectionalLight(0xffffff, soft ? 0.7 : 1.1);
  under.position.set(-40, -120, 60);
  scene.add(under);
  return { sun, rim, under };
}

export { THREE };
