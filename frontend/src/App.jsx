import { useEffect, useState } from "react";
import { getModules, runModule, stopModule } from "./api";
import Navbar from "./components/nav";
import Terminal from "./components/terminal";

import "./App.css";

export default function App() {
  const [modules, setModules] = useState([]);
  const [selectedModule, setSelectedModule] = useState(null);
  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState("");
  const [clearSignal, setClearSignal] = useState(0);
  const [wsReady, setWsReady] = useState(false);


  useEffect(() => {
    getModules().then((data) => {
      setModules(data.available ?? data.modules ?? []);
    });
  }, []);

  const handleRun = async () => {
    if (!selectedModule || running) return;

    setClearSignal((c) => c + 1);
    setRunning(true);
    setStatus(`Running ${selectedModule}…`);

    try {
      await runModule(selectedModule);
      setStatus(`Module ${selectedModule} started`);
    } catch {
      setStatus("Failed to start module");
      setRunning(false);
    }
  };

  const handleStop = async () => {
    if (!selectedModule) return;

    try {
      await stopModule(selectedModule);
      setStatus(`Module ${selectedModule} stopped`);
      setRunning(false);
      setClearSignal((c) => c + 1);
    } catch {
      setStatus("Failed to stop module");
    }
  };

  return (
    <>
      <Navbar
        modules={modules}
        selected={selectedModule}
        onSelect={setSelectedModule}
      />

      <main className="app-body">
        <div className="module-controls">
          {selectedModule ? (
            <>
              <h2>Selected: {selectedModule}</h2>

              <button
                className="run-button"
                onClick={handleRun}
                disabled={running || !wsReady}
              >
                  {running ? "Running…" : wsReady ? "Run Module" : "Connecting…"}
              </button>

              <button
                className="stop-button"
                onClick={handleStop}
                disabled={!running}
              >
                Stop
              </button>

              <Terminal
                module={selectedModule}
                clearSignal={clearSignal}
                onReady={setWsReady}
              />

              {status && <p className="status-text">{status}</p>}
            </>
          ) : (
            <p className="status-text">Select a module to begin</p>
          )}
        </div>
      </main>
    </>
  );
}
