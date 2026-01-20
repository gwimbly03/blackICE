import { useEffect, useRef, useState } from "react";
import AnsiToHtml from "ansi-to-html";

const ansi = new AnsiToHtml({
  fg: "#e5e7eb",
  bg: "#000000",
  newline: true,
  escapeXML: true,
});

export default function Terminal({ module, clearSignal, onReady }) {
  const [lines, setLines] = useState([]);
  const [input, setInput] = useState("");
  const wsRef = useRef(null);
  const bottomRef = useRef(null);

  useEffect(() => {
    setLines([]);
    onReady(false);

    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    if (!module) return;

    const ws = new WebSocket(`ws://127.0.0.1:8000/ws/modules/${module}`);
    wsRef.current = ws;

    ws.onopen = () => {
      onReady(true);   
    };

    ws.onmessage = (e) => {
      setLines((prev) => [...prev, e.data]);
    };

    ws.onerror = () => {
      setLines((prev) => [...prev, "[WebSocket error]"]);
    };

    ws.onclose = () => {
      onReady(false);
    };

    return () => {
      ws.close();
    };
  }, [module]);

  useEffect(() => {
    setLines([]);
  }, [clearSignal]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [lines]);

  const sendInput = (e) => {
    if (e.key === "Enter" && wsRef.current && input.trim()) {
      wsRef.current.send(input);
      setLines((prev) => [...prev, `> ${input}`]);
      setInput("");
    }
  };

  return (
    <div className="terminal">
      {lines.map((line, i) => (
        <div
          key={i}
          className="terminal-line"
          dangerouslySetInnerHTML={{
            __html: ansi.toHtml(line),
          }}
        />
      ))}

      <div className="terminal-input">
        <span>&gt;</span>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={sendInput}
          autoFocus
        />
      </div>

      <div ref={bottomRef} />
    </div>
  );
}

