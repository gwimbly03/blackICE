const API_BASE = "http://127.0.0.1:8000";

/* ---------------- REST ---------------- */

export async function getModules() {
  const res = await fetch(`${API_BASE}/modules`);
  if (!res.ok) throw new Error("Failed to fetch modules");
  return res.json();
}

export async function runModule(name) {
  const res = await fetch(`${API_BASE}/modules/${name}/run`, {
    method: "POST",
  });
  if (!res.ok) throw new Error("Failed to start module");
  return res.json();
}

export async function stopModule(name) {
  return fetch(`${API_BASE}/modules/${name}/stop`, {
    method: "POST",
  });
}

/* ---------------- WebSocket ---------------- */

export function connectModuleWS(moduleName) {
  const wsUrl = `ws://127.0.0.1:8000/ws/modules/${moduleName}`;
  return new WebSocket(wsUrl);
}

