import { useEffect, useState, useRef } from "react";

export default function ModuleConsole({ moduleName }) {
  const [logs, setLogs] = useState([]);
  const consoleRef = useRef();

  useEffect(() => {
    if (!moduleName) return;

    const socket = new WebSocket(`ws://127.0.0.1:8000/ws/modules/${moduleName}`);

    socket.onmessage = (event) => {
      setLogs((prev) => [...prev, event.data]);
    };

    socket.onclose = () => {
      console.log(`WebSocket for ${moduleName} closed`);
    };

    return () => socket.close();
  }, [moduleName]);

  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="console-container">
      <h2>Module: {moduleName}</h2>
      <div className="console-output" ref={consoleRef}>
        {logs.map((line, idx) => (
          <div key={idx}>{line}</div>
        ))}
      </div>
    </div>
  );
}

