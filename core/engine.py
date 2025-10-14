import importlib
import os
from core.logger import log_info, log_error

MODULES_DIR = "modules"

class PentestEngine:
    """
    This class allows me to load custom modules to use with my vulnerability scanner, if modules are put inside the ../modules/ folder then it can automatically grab the modules.
    Each module must be in it own class and implement a run() method and a description to explain what the module does 
    """
    def __init__(self):
        """
        Start the engine
        """
        self.modules = {}

    def discover_modules(self):
        """
        Discover all the modules in the ../modules/ folder then tries to import them
        """
        log_info("Discovering modules...")
        for file in os.listdir(MODULES_DIR):
            if file.endswith(".py") and file != "__init__.py":
                module_name = file[:-3]
                try:
                    module = importlib.import_module(f"modules.{module_name}")
                    
                    module_class = None
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and  
                            hasattr(attr, 'run') and 
                            hasattr(attr, 'description')):
                            module_class = attr
                            break
                    
                    if module_class:
                        module_instance = module_class()
                        self.modules[module_name] = module_instance
                        log_info(f"Loaded module: {module_name}")
                    else:
                        log_error(f"Module {module_name} has no valid class with 'run' method")
                        
                except Exception as e:
                    log_error(f"Failed to load {module_name}: {e}")

    def run_module(self, module_name):
        """
        Runs the specified module 
        """
        if module_name in self.modules:
            try:
                log_info(f"Running module: {module_name}")
                self.modules[module_name].run()
            except Exception as e:
                log_error(f"Error running {module_name}: {e}")
        else:
            log_error(f"Module {module_name} not found")
