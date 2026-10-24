// Display only: every value comes from a Rust command.
const { invoke } = window.__TAURI__.core;

async function load() {
  const info = await invoke("app_info");
  document.getElementById("head").textContent = info.genesis_head;
  document.getElementById("version").textContent = `v${info.version}`;
}

load().catch((err) => {
  document.getElementById("head").textContent = `error: ${err}`;
});
