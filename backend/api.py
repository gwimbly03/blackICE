from os import wait
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from backend.core.engine import PentestEngine
from backend.core.interactive_tty import InteractiveTTY
import sys
import asyncio

app = FastAPI(
    title="BlackICE API",
    description="Web interface for the BlackICE pentesting framework",
    version="0.3-alpha"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = PentestEngine()

module_ws_connections: dict[str, list[WebSocket]] = {}
module_ttys: dict[str, InteractiveTTY] = {}
running_tasks: dict[str, asyncio.Task] = {}


@app.websocket("/ws/modules/{module_name}")
async def module_ws(websocket: WebSocket, module_name: str):
    await websocket.accept()

    module_ws_connections.setdefault(module_name, []).append(websocket)

    try:
        while True:
            msg = await websocket.receive_text()
            tty = module_ttys.get(module_name)
            if tty:
                tty.push_input(msg)
    except WebSocketDisconnect:
        module_ws_connections[module_name].remove(websocket)


@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/modules")
def list_modules():
    return {
        "available": sorted(engine.available_modules),
        "loaded": sorted(engine.modules.keys()),
    }

@app.post("/modules/{module_name}/run")
async def run_module(module_name: str):

    if running_tasks:
        raise HTTPException(
            status_code=400,
            detail="Another module is already running"
        )

    if module_name not in engine.available_modules:
        raise HTTPException(status_code=404, detail="Unknown module")

    tty = module_ttys.setdefault(
        module_name,
        InteractiveTTY(module_name, module_ws_connections)
    )

    def runner():
        original_stdout = sys.stdout
        original_stdin = sys.stdin

        try:
            sys.stdout = tty
            sys.stdin = tty
            engine.run_module(module_name)
        except Exception as e:
            print(f"[ERROR] {e}")
        finally:
            sys.stdout = original_stdout
            sys.stdin = original_stdin
            running_tasks.pop(module_name, None)

    task = asyncio.create_task(asyncio.to_thread(runner))
    running_tasks[module_name] = task

    return {"status": "started", "module": module_name}

@app.post("/modules/{module_name}/stop")
async def stop_module(module_name: str):
    tty = module_ttys.pop(module_name, None)
    task = running_tasks.pop(module_name, None)

    if tty:
        tty.close()

    if task:
        task.cancel()

    return {
        "status": "stopped",
        "module": module_name,
    }


