import asyncio
import queue

class InteractiveTTY:
    def __init__(self, module_name: str, ws_connections: dict):
        self.module_name = module_name
        self.ws_connections = ws_connections
        self.input_queue = queue.Queue()
        self.loop = asyncio.get_event_loop()
        self.closed = False

    # STDOUT
    def write(self, data: str):
        if not data or self.closed:
            return

        for ws in self.ws_connections.get(self.module_name, []):
            self.loop.call_soon_threadsafe(
                asyncio.create_task,
                ws.send_text(data)
            )

    def flush(self):
        pass

    # STDIN
    def readline(self):
        data = self.input_queue.get()
        if data is None:          # ← EOF SIGNAL
            return ""
        return data + "\n"

    def push_input(self, data: str):
        if not self.closed:
            self.input_queue.put(data)

    def close(self):
        self.closed = True
        self.input_queue.put(None)  # ← UNBLOCK readline()

