import asyncio

class WebSocketStreamer:
    def __init__(self, module_name, ws_connections):
        self.module_name = module_name
        self.ws_connections = ws_connections
        self.loop = asyncio.get_event_loop()

    def write(self, data):
        if not data.strip():
            return

        for ws in self.ws_connections.get(self.module_name, []):
            asyncio.run_coroutine_threadsafe(
                ws.send_text(data),
                self.loop
            )

    def flush(self):
        pass
