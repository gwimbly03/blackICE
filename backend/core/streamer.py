import sys
import asyncio

class WebSocketStreamer:
    """
    Redirects stdout to multiple websockets.
    Usage:
        streamer = WebSocketStreamer(module_name)
        sys.stdout = streamer
        print("This goes to frontend!")
    """
    def __init__(self, module_name, connections_dict):
        self.module_name = module_name
        self.connections_dict = connections_dict
        self.loop = asyncio.get_event_loop()

    def write(self, message):
        # ignore empty strings or just newlines
        if not message.strip():
            return
        for ws in self.connections_dict.get(self.module_name, []):
            try:
                # Schedule sending in the event loop
                asyncio.run_coroutine_threadsafe(ws.send_text(message), self.loop)
            except Exception:
                pass

    def flush(self):
        pass  # Needed for file-like compatibility

