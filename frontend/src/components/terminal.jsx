import "./terminal.css";

import { useEffect, useRef, useState } from "react";

export default function Terminal({ module }) {
  const [lines, setLines] = useState([]);
  const wsRef = useRef(null);
  const endRef = useRef(null);

  useEffect(() => {
    if (!module) return;

    setLines([]);

    const ws = new WebSocket(`ws://127.0.0.1:8000/ws/modules/${module}`);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      setLines((prev) => [...prev, event.data]);
    };

    ws.onerror = () => {
      setLines((prev) => [...prev, "[WebSocket error]"]);
    };

    return () => {
      ws.close();
    };
  }, [module]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [lines]);

  return (
    <div className="terminal">
      {lines.map((line, i) => (
        <div key={i} className="terminal-line">
          {line}
        </div>
      ))}
      <div ref={endRef} />
    </div>
  );
}

