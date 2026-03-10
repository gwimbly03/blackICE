import { useEffect, useRef } from "react";
import { Terminal as XTerm } from "xterm";
import { FitAddon } from "xterm-addon-fit";
import "xterm/css/xterm.css";

export default function Terminal({ module, clearSignal, onReady = () => {} }) {
  const terminalRef = useRef(null);
  const xtermRef = useRef(null);
  const fitAddonRef = useRef(null);
  const wsRef = useRef(null);

  // Terminal initialization
  useEffect(() => {
    if (!terminalRef.current) return;

    const term = new XTerm({
      cursorBlink: true,
      fontFamily: "JetBrains Mono, monospace",
      fontSize: 16, // increased for readability
      lineHeight: 1.2,

      theme: {
        background: "#000000",
        foreground: "#e5e7eb",
        cursor: "#00ff9d",
      },

      scrollback: 3000,
    });
    const fitAddon = new FitAddon();

    term.loadAddon(fitAddon);
    term.open(terminalRef.current);
    fitAddon.fit();

    xtermRef.current = term;
    fitAddonRef.current = fitAddon;

    const resizeHandler = () => {
      requestAnimationFrame(() => fitAddon.fit());
    };

    window.addEventListener("resize", resizeHandler);

    return () => {
      window.removeEventListener("resize", resizeHandler);
      term.dispose();
    };
  }, []);

  // WebSocket + module handling
  useEffect(() => {
    const term = xtermRef.current;
    if (!term) return;

    term.clear();
    onReady(false);

    // Cleanup previous websocket + listeners
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    if (!module) return;

    const ws = new WebSocket(`ws://127.0.0.1:8000/ws/modules/${module}`);
    wsRef.current = ws;

    const handleData = (data) => {
      const socket = wsRef.current;
      if (!socket || socket.readyState !== WebSocket.OPEN) return;

      if (data === "\r") {
        socket.send(inputBuffer);
        term.write("\r\n");
        inputBuffer = "";
        return;
      }

      if (data === "\u007f") {
        if (inputBuffer.length > 0) {
          inputBuffer = inputBuffer.slice(0, -1);
          term.write("\b \b");
        }
        return;
      }

      inputBuffer += data;
      term.write(data);
    };

    let inputBuffer = "";

    const disposable = term.onData(handleData);

    ws.onopen = () => onReady(true);

    ws.onmessage = (e) => {
      term.write(e.data + "\r\n");
    };

    ws.onerror = () => {
      term.write("\r\n[WebSocket error]\r\n");
    };

    ws.onclose = () => onReady(false);

    return () => {
      disposable.dispose();
      ws.close();
    };
  }, [module, onReady]);

  // Clear terminal when signal changes
  useEffect(() => {
    xtermRef.current?.clear();
  }, [clearSignal]);

  return <div className="terminal" ref={terminalRef} />;
}
