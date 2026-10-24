// The board as the page's background: one fixed canvas behind the content.
// In the hero it sits in a slot and is clearly there; further down it drifts
// to the side of each section, faint, and turns to show another face. It
// never takes a click or a scroll.
//
// The page marks its sections:
//   data-pi-slot            the hero slot: the board is drawn inside it
//   data-pi-pose="top"      which camera pose to use while this section is
//                           the one at the middle of the screen
//   data-pi-side="left"     which side it drifts to (default: right)
//   data-pi-o=".2"          how visible it is there (0 hides and pauses)

import { THREE, buildPi, lights, W } from "./hawk-pi.js";

const POSES = {
  hero:  { pos: [56, 84, 120], target: [4, 2, 0], yaw: -0.22 },
  top:   { pos: [8, 140, 58], target: [0, 0, 0], yaw: 0 },
  ports: { pos: [124, 48, 82], target: [12, 5, 6], yaw: 0 },
  front: { pos: [-72, 68, 114], target: [0, 2, 0], yaw: 0 },
  soc:   { pos: [-46, 92, 84], target: [0, 0, 0], yaw: 0 }
};
const TAG_LIFT = { soc: 7, radio: 5, eth: 17, sd: 3 };
const FOV = 30;
const STAND_BACK = 1.55; // the camera stands back from each pose: flat perspective, zoom restores the size

export function start({ canvas, tags }) {
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const coarse = matchMedia("(pointer: coarse)").matches;

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true, powerPreference: "low-power" });
  } catch (e) {
    return null;
  }
  renderer.setClearColor(0x000000, 0);
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.05;

  const scene = new THREE.Scene();
  lights(scene, renderer, { soft: true });
  const pi = buildPi({ renderer });
  scene.add(pi.root);
  const camera = new THREE.PerspectiveCamera(FOV, 1, 1, 2000);

  const slot = document.querySelector("[data-pi-slot]");
  const sections = [...document.querySelectorAll("[data-pi-pose]")];
  const tagEls = {};
  if (tags) tags.querySelectorAll("[data-part]").forEach((a) => { tagEls[a.dataset.part] = a; });

  let vw = 0, vh = 0, dpr = 1;
  function resize() {
    vw = innerWidth; vh = innerHeight;
    dpr = Math.min(devicePixelRatio || 1, coarse ? 1.25 : 1.5);
    renderer.setPixelRatio(dpr);
    renderer.setSize(vw, vh, false);
    camera.aspect = vw / vh;
    camera.updateProjectionMatrix();
  }
  addEventListener("resize", resize);
  resize();

  // Smoothed state: what is on screen right now.
  const cur = { cx: vw * 0.7, cy: vh * 0.6, len: vw * 0.5, o: 0, pos: new THREE.Vector3(...POSES.hero.pos), target: new THREE.Vector3(...POSES.hero.target), yaw: POSES.hero.yaw };
  cur.pos.sub(cur.target).multiplyScalar(STAND_BACK).add(cur.target);
  const goal = { cx: cur.cx, cy: cur.cy, len: cur.len, o: 0, pos: cur.pos.clone(), target: cur.target.clone(), yaw: cur.yaw };

  // Pointer parallax in the hero (mouse only)
  const mouse = { x: 0, y: 0, tx: 0, ty: 0 };
  if (!coarse && !reduce) addEventListener("pointermove", (e) => { mouse.tx = e.clientX / innerWidth - 0.5; mouse.ty = e.clientY / innerHeight - 0.5; }, { passive: true });

  function pickGoal() {
    const mid = vh * 0.5;
    // The hero slot wins while it is on screen
    if (slot) {
      const r = slot.getBoundingClientRect();
      if (r.bottom > vh * 0.12 && r.top < vh * 0.82 && r.width > 0) {
        const narrow = vw < 760;
        // The board sits in the right of the slot, smaller than the slot, so it
        // never runs under the copy on the left.
        goal.cx = r.left + r.width * (narrow ? 0.5 : 0.6);
        goal.cy = r.top + r.height * (narrow ? 0.5 : 0.46);
        goal.len = r.width * (narrow ? 0.86 : 0.78);
        goal.o = narrow ? 0.5 : 0.56;
        setPose(POSES.hero);
        return "hero";
      }
    }
    let best = null, bestD = Infinity;
    for (const s of sections) {
      const r = s.getBoundingClientRect();
      const d = r.top <= mid && r.bottom >= mid ? 0 : Math.min(Math.abs(r.top - mid), Math.abs(r.bottom - mid));
      if (d < bestD) { bestD = d; best = s; }
    }
    if (!best) { goal.o = 0; return "none"; }
    const o = parseFloat(best.dataset.piO || "0.2");
    const left = best.dataset.piSide === "left";
    const narrow = vw < 760;
    goal.o = narrow ? o * 0.7 : o;
    goal.len = narrow ? vw * 1.1 : Math.min(vw * 0.46, 760);
    goal.cx = narrow ? vw * 0.5 : vw * (left ? 0.2 : 0.8);
    goal.cy = vh * (narrow ? 0.62 : 0.56);
    setPose(POSES[best.dataset.piPose] || POSES.top);
    return best.id || "section";
  }
  function setPose(p) {
    goal.target.set(...p.target);
    goal.pos.set(...p.pos).sub(goal.target).multiplyScalar(STAND_BACK).add(goal.target);
    goal.yaw = p.yaw;
  }

  const v = new THREE.Vector3();
  let last = performance.now(), t0 = last, frameN = 0, ready = false, mode = "hero";
  function frame(now) {
    requestAnimationFrame(frame);
    const dt = Math.min((now - last) / 1000, 0.05);
    last = now;
    if (document.hidden) return;
    frameN++;
    if (coarse && frameN % 2) return; // 30 fps on phones

    mode = pickGoal();
    const k = reduce ? 1 : 1 - Math.exp(-dt * 3.6);
    cur.cx += (goal.cx - cur.cx) * k;
    cur.cy += (goal.cy - cur.cy) * k;
    cur.len += (goal.len - cur.len) * k;
    cur.o += (goal.o - cur.o) * (reduce ? 1 : 1 - Math.exp(-dt * 2.4));
    cur.pos.lerp(goal.pos, k);
    cur.target.lerp(goal.target, k);
    cur.yaw += (goal.yaw - cur.yaw) * k;

    canvas.style.opacity = cur.o.toFixed(3);
    if (!ready && cur.o > 0.02) { ready = true; document.documentElement.classList.add("pi-on"); }
    const showing = cur.o > 0.015;
    if (tags) tags.style.opacity = mode === "hero" ? String(Math.max(0, Math.min(1, (cur.o - 0.3) / 0.3))) : "0";
    if (!showing) return;

    mouse.x += (mouse.tx - mouse.x) * 0.06; mouse.y += (mouse.ty - mouse.y) * 0.06;
    const px = mode === "hero" ? mouse.x * 14 : 0, py = mode === "hero" ? mouse.y * 9 : 0;
    camera.position.set(cur.pos.x + px, cur.pos.y - py, cur.pos.z);
    camera.lookAt(cur.target);
    pi.root.rotation.y = cur.yaw + (reduce ? 0 : (now - t0) / 1000 * 0.05);

    // Scale so the board's length on screen is cur.len pixels; then slide the
    // image so the board's centre lands on (cx, cy).
    const dist = camera.position.distanceTo(cur.target);
    const pxPerMM = vh / (2 * dist * Math.tan(THREE.MathUtils.degToRad(FOV / 2)));
    camera.zoom = Math.max(0.2, cur.len / (W * pxPerMM));
    camera.setViewOffset(vw, vh, -(cur.cx - vw / 2), -(cur.cy - vh / 2), vw, vh);
    camera.updateProjectionMatrix();
    renderer.render(scene, camera);

    if (tags && mode === "hero") {
      for (const k2 of Object.keys(tagEls)) {
        pi.keyed[k2].getWorldPosition(v);
        v.y += TAG_LIFT[k2];
        v.project(camera);
        tagEls[k2].style.transform = `translate(${(v.x + 1) / 2 * vw}px, ${(1 - v.y) / 2 * vh - 12}px) translate(-50%, -100%)`;
      }
    }
  }
  requestAnimationFrame(frame);
  return { renderer };
}
