import importlib
import pkgutil
import backend.modules

registry = {}

for module_loader, name, ispkg in pkgutil.iter_modules(backend.modules.__path__):
    module = importlib.import_module(f"backend.modules.{name}")

    if hasattr(module, "run"):
        registry[name] = module.run

