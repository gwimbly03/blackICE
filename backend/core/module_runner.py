import sys
import asyncio
from backend.core.streamer import WebSocketStreamer

def run_module(module_name, module_instance, ws_connections):
    loop = asyncio.get_running_loop()

    old_stdout = sys.stdout
    sys.stdout = WebSocketStreamer(module_name, ws_connections, loop)

    try:
        module_instance.run()
    finally:
        sys.stdout = old_stdout

