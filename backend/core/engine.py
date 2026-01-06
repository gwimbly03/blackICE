import importlib
import os
from core.logger import logger

MODULES_DIR = "modules"

class PentestEngine:
    """
    This class allows me to load custom modules to use with my vulnerability scanner, 
    if modules are put inside the ../modules/ folder then it can automatically grab the modules.
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
        print("Discovering modules...")
        loaded_count = 0
        
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
                        loaded_count += 1
                    else:
                        print(f"Failed to load {module_name}: Module has no valid class with 'run' method and 'description'")
                        
                except Exception as e:
                    print(f"Failed to load {module_name}: {e}")

        print(f"Loaded {loaded_count} modules")

    def run_module(self, module_name):
        """
        Runs the specified module with logging integration
        """
        if module_name in self.modules:
            try:
                print(f"Running module: {module_name}")
                
                logger.log_module_start(module_name, "pending_user_input")
                
                self.modules[module_name].run()
                
            except Exception as e:
                error_msg = f"Error running {module_name}: {e}"
                print(f"Error: {error_msg}")
                logger.log_error(module_name, "unknown_target", error_msg)
        else:
            error_msg = f"Module {module_name} not found"
            print(f"Error: {error_msg}")
            logger.log_error("engine", "system", error_msg)
            print(f"Available modules: {list(self.modules.keys())}")
