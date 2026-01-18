import { useEffect, useState } from "react";
import { getModules, runModule } from "./api";
import Navbar from "./components/nav";
import Terminal from "./components/terminal";

import "./App.css";

export default function App() {
  const [modules, setModules] = useState([]);
  const [selectedModule, setSelectedModule] = useState(null);
  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState("");

  useEffect(() => {
    getModules().then((data) => {
      setModules(data.available ?? data.modules ?? []);
    });
  }, []);

  const handleRun = async () => {
    if (!selectedModule) return;

    setRunning(true);
    setStatus(`Running ${selectedModule}…`);

    try {
      await runModule(selectedModule);
      setStatus(`Module ${selectedModule} started`);
    } catch (err) {
      setStatus("Failed to start module");
    } finally {
      setRunning(false);
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
                disabled={running}
              >
                {running ? "Running…" : "Run Module"}
              </button>
              <button
                className="stop-button"
                onClick={() => stopModule(selectedModule)}
              >
                Stop
              </button>

              <Terminal module={selectedModule} />
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

