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

  if (!res.ok) {
    const data = await res.json();
    throw new Error(data.detail || "Failed to start module");
  }

  return res.json();
}

export async function stopModule(name) {
  const res = await fetch(`${API_BASE}/modules/${name}/stop`, {
    method: "POST",
  });

  if (!res.ok) {
    const data = await res.json();
    throw new Error(data.detail || "Failed to stop module");
  }

  return res.json();
}

/* ---------------- WebSocket ---------------- */

export function connectModuleWS(moduleName) {
  return new WebSocket(
    `ws://127.0.0.1:8000/ws/modules/${moduleName}`
  );
}

