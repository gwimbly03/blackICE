import importlib
import os
from backend.core.logger import logger

# Resolve modules directory robustly
BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)
MODULES_DIR = os.path.join(BASE_DIR, "modules")


class PentestEngine:
    """
    Lazy-loading pentest engine.
    Modules are discovered by filename and imported only when executed.
    """

    def __init__(self):
        self.modules = {}             # loaded module instances
        self.available_modules = []   # module filenames (no imports)
        self._discover_available_modules()

    def _discover_available_modules(self):
        """
        Discover available module filenames WITHOUT importing them
        """
        if not os.path.isdir(MODULES_DIR):
            print(f"Modules directory not found: {MODULES_DIR}")
            return

        for file in os.listdir(MODULES_DIR):
            if file.endswith(".py") and file != "__init__.py":
                self.available_modules.append(file[:-3])

        print(f"Discovered {len(self.available_modules)} modules")

    def _load_module(self, module_name: str):
        """
        Import and instantiate a module ON DEMAND
        """
        if module_name in self.modules:
            return self.modules[module_name]

        try:
            module = importlib.import_module(
                f"backend.modules.{module_name}"
            )

            module_class = None
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and hasattr(attr, "run")
                    and hasattr(attr, "description")
                ):
                    module_class = attr
                    break

            if not module_class:
                raise RuntimeError(
                    "No valid class with run() and description"
                )

            instance = module_class()
            self.modules[module_name] = instance
            return instance

        except Exception as e:
            raise RuntimeError(
                f"Failed to load module '{module_name}': {e}"
            )

    def run_module(self, module_name: str):
        """
        Run a module, loading it lazily if needed
        """
        if module_name not in self.available_modules:
            error_msg = f"Module {module_name} not found"
            print(error_msg)
            logger.log_error("engine", "system", error_msg)
            return

        try:
            module = self._load_module(module_name)

            print(f"Running module: {module_name}")
            logger.log_module_start(module_name, "pending_user_input")

            module.run()

        except Exception as e:
            error_msg = f"Error running {module_name}: {e}"
            print(error_msg)
            logger.log_error(module_name, "unknown_target", error_msg)

