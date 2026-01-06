from fastapi import APIRouter
from core.engine import PentestEngine

router = APIRouter()
engine = PentestEngine()
engine.discover_modules()

@router.get("/modules")
def list_modules():
    return {"modules": list(engine.modules.keys())}

@router.post("/modules/run/{name}")
def run_module(name: str):
    if name not in engine.modules:
        return {"error": "Module not found"}
    result = engine.run_module(name)
    return {"output": result}

