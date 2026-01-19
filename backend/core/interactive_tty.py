import asyncio
import queue

class InteractiveTTY:
    def __init__(self, module_name: str, ws_connections: dict):
        self.module_name = module_name
        self.ws_connections = ws_connections
        self.input_queue = queue.Queue()
        self.loop = asyncio.get_event_loop()

    # STDOUT
    def write(self, data: str):
        if not data:
            return

        for ws in self.ws_connections.get(self.module_name, []):
            # SAFE cross-thread scheduling
            self.loop.call_soon_threadsafe(
                asyncio.create_task,
                ws.send_text(data)
            )

    def flush(self):
        pass

    # STDIN
    def readline(self):
        return self.input_queue.get() + "\n"

    def push_input(self, data: str):
        self.input_queue.put(data)
