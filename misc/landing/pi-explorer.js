// The board explorer: drag to turn, take it apart, tap one of the four parts
// HAWK uses. Used by pi-3d.html and by the "Cabe en una mano" section of the
// landing. The page supplies the markup (see mount()); this file supplies the
// behaviour. Nothing in here touches the network.

import { THREE, buildPi, lights } from "./hawk-pi.js";
import { OrbitControls } from "./vendor/addons/OrbitControls.js";

const HOME_POS = new THREE.Vector3(70, 92, 118);
const HOME_TARGET = new THREE.Vector3(2, 4, 0);

// Views: [camera position, target] in millimetres around the board.
const VIEWS = {
  soc: [new THREE.Vector3(-4, 56, 64), new THREE.Vector3(-13, 3, 3)],
  radio: [new THREE.Vector3(-76, 48, 26), new THREE.Vector3(-26, 2, -13)],
  eth: [new THREE.Vector3(118, 34, 70), new THREE.Vector3(34, 6, 18)],
  sd: [new THREE.Vector3(-104, -46, 58), new THREE.Vector3(-40, -1, 0)]
};
const TAG_LIFT = { soc: 7, radio: 5, eth: 17, sd: 3 };

/**
 * root must contain:
 *   .stage                       the box the canvas goes into (sized by CSS)
 *   .loading                     optional, removed when the model is ready
 *   .part[data-part]             one button per part: soc, radio, eth, sd
 *   [data-act="explode|spin|reset"]   optional control buttons
 * labels: { soc, radio, eth, sd, explode, join } strings for the tags/buttons.
 */
export async function mountExplorer(root, labels) {
  const stage = root.querySelector(".stage");
  const loading = root.querySelector(".loading");
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const L = Object.assign({ soc: "Procesador", radio: "Radio", eth: "Ethernet", sd: "microSD", explode: "Separar piezas", join: "Juntar piezas" }, labels || {});

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  } catch (e) {
    if (loading) loading.textContent = "Tu navegador no pudo abrir WebGL, así que no puedo mostrar la placa en 3D.";
    return null;
  }
  renderer.setPixelRatio(Math.min(devicePixelRatio || 1, 2));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.0;
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  stage.insertBefore(renderer.domElement, stage.firstChild);
  renderer.domElement.setAttribute("role", "img");
  renderer.domElement.setAttribute("aria-label", "Raspberry Pi 4 en 3D. Arrastra para girarla.");

  const scene = new THREE.Scene();
  lights(scene, renderer, { shadows: true });
  const floor = new THREE.Mesh(new THREE.PlaneGeometry(600, 600), new THREE.ShadowMaterial({ opacity: 0.16 }));
  floor.rotation.x = -Math.PI / 2; floor.position.y = -6; floor.receiveShadow = true;
  scene.add(floor);

  if (document.fonts && document.fonts.ready) await document.fonts.ready.catch(() => {});
  const pi = buildPi({ renderer, shadows: true });
  scene.add(pi.root);
  if (loading) loading.remove();

  const camera = new THREE.PerspectiveCamera(32, 1, 1, 2000);
  camera.position.copy(HOME_POS);
  const controls = new OrbitControls(camera, renderer.domElement);
  controls.target.copy(HOME_TARGET);
  controls.enableDamping = true;
  controls.dampingFactor = 0.08;
  controls.minDistance = 40;
  controls.maxDistance = 420;
  controls.autoRotate = !reduce;
  controls.autoRotateSpeed = 0.6;
  // Let the page scroll on touch devices until the finger is on the board
  controls.touches = { ONE: THREE.TOUCH.ROTATE, TWO: THREE.TOUCH.DOLLY_ROTATE };

  const tagEls = {};
  for (const k of Object.keys(TAG_LIFT)) {
    const b = document.createElement("button");
    b.type = "button"; b.className = "ptag"; b.textContent = L[k]; b.setAttribute("aria-pressed", "false");
    b.addEventListener("click", () => select(k));
    stage.appendChild(b); tagEls[k] = b;
  }
  const v = new THREE.Vector3();
  function placeTags() {
    const w = stage.clientWidth, h = stage.clientHeight;
    const dist0 = camera.position.distanceTo(controls.target);
    for (const k of Object.keys(tagEls)) {
      pi.keyed[k].getWorldPosition(v);
      v.y += TAG_LIFT[k];
      const d = v.distanceTo(camera.position);
      v.project(camera);
      const x = (v.x + 1) / 2 * w, y = (1 - v.y) / 2 * h - 14;
      tagEls[k].style.transform = `translate(${x}px, ${y}px) translate(-50%, -100%)`;
      tagEls[k].classList.toggle("far", d > dist0 + 34);
    }
  }

  let current = null, tween = null, exploded = false, explodeAmt = 0, touched = false;
  const buttons = [...root.querySelectorAll(".part")];
  const explodeBtn = root.querySelector('[data-act="explode"]');
  const spinBtn = root.querySelector('[data-act="spin"]');
  const resetBtn = root.querySelector('[data-act="reset"]');

  function homePos() {
    const k = Math.max(1, 1.25 / Math.max(camera.aspect, 0.3));
    return HOME_TARGET.clone().add(HOME_POS.clone().sub(HOME_TARGET).multiplyScalar(k));
  }
  function viewFor(key) {
    const k = Math.max(1, 1.15 / Math.max(camera.aspect, 0.3));
    const [p, t] = VIEWS[key];
    return [t.clone().add(p.clone().sub(t).multiplyScalar(k)), t];
  }
  function flyTo(pos, target) {
    if (reduce) { camera.position.copy(pos); controls.target.copy(target); return; }
    tween = { t: 0, fromP: camera.position.clone(), toP: pos.clone(), fromT: controls.target.clone(), toT: target.clone() };
  }
  function select(k) {
    if (current) pi.glow(current, false);
    current = current === k ? null : k;
    buttons.forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.part === current)));
    for (const t of Object.keys(tagEls)) tagEls[t].setAttribute("aria-pressed", String(t === current));
    stage.classList.toggle("picked", Boolean(current));
    if (current) {
      pi.glow(current, true);
      controls.autoRotate = false;
      if (spinBtn) spinBtn.setAttribute("aria-pressed", "false");
      const [p, t] = viewFor(current);
      flyTo(p, t);
    }
  }
  buttons.forEach((b) => b.addEventListener("click", () => select(b.dataset.part)));
  if (explodeBtn) explodeBtn.addEventListener("click", () => {
    exploded = !exploded;
    explodeBtn.setAttribute("aria-pressed", String(exploded));
    explodeBtn.textContent = exploded ? L.join : L.explode;
  });
  if (spinBtn) spinBtn.addEventListener("click", () => {
    controls.autoRotate = !controls.autoRotate;
    spinBtn.setAttribute("aria-pressed", String(controls.autoRotate));
  });
  if (resetBtn) resetBtn.addEventListener("click", () => {
    if (current) select(current);
    exploded = false;
    if (explodeBtn) { explodeBtn.setAttribute("aria-pressed", "false"); explodeBtn.textContent = L.explode; }
    flyTo(homePos(), HOME_TARGET);
  });
  renderer.domElement.addEventListener("pointerdown", () => { tween = null; touched = true; });

  function resize() {
    const w = stage.clientWidth, h = stage.clientHeight;
    if (!w || !h) return;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    if (!touched && !current && !tween) camera.position.copy(homePos());
  }
  new ResizeObserver(resize).observe(stage);
  resize();

  const ease = (t) => 1 - Math.pow(1 - t, 3);
  const clock = new THREE.Clock();
  let visible = true;
  new IntersectionObserver((e) => { visible = e[0].isIntersecting; }).observe(stage);
  (function frame() {
    requestAnimationFrame(frame);
    if (!visible || document.hidden) { clock.getDelta(); return; }
    const dt = Math.min(clock.getDelta(), 0.05);
    explodeAmt += ((exploded ? 1 : 0) - explodeAmt) * (reduce ? 1 : Math.min(1, dt * 6));
    pi.setExplode(explodeAmt);
    if (tween) {
      tween.t = Math.min(1, tween.t + dt / 1.1);
      const e = ease(tween.t);
      camera.position.lerpVectors(tween.fromP, tween.toP, e);
      controls.target.lerpVectors(tween.fromT, tween.toT, e);
      if (tween.t >= 1) tween = null;
    }
    controls.update();
    renderer.render(scene, camera);
    placeTags();
  })();

  return { select, pick: (k) => { if (current !== k) select(k); } };
}
