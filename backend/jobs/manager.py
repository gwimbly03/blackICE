# backend/jobs/manager.py

import importlib
import pkgutil
import uuid
from typing import Dict, Any, Callable

from backend.jobs.jobs import Job, JobQueue


class ModuleManager:
    """
    Discovers pentest modules and starts them as background jobs.
    """

    def __init__(self):
        self.registry: Dict[str, Callable] = {}
        self.jobs: Dict[str, Job] = {}
        self.queue = JobQueue(workers=5)
        self.queue.start()

    # ------------------------------------------------------------
    # MODULE DISCOVERY
    # ------------------------------------------------------------

    def load_modules(self):
        """Auto-load classes with .run() inside backend.modules.*"""

        import backend.modules as module_root

        for _, module_name, _ in pkgutil.walk_packages(
            module_root.__path__, module_root.__name__ + "."
        ):
            try:
                module = importlib.import_module(module_name)

                # look for module classes with a run() method
                for attr in dir(module):
                    obj = getattr(module, attr)
                    if isinstance(obj, type) and hasattr(obj, "run"):
                        key = module_name.split(".")[-1]  # use filename as key
                        self.registry[key] = obj()
            except Exception as e:
                print(f"[ModuleManager] Failed to load {module_name}: {e}")

    # ------------------------------------------------------------
    # JOB EXECUTION
    # ------------------------------------------------------------

    def run_module(self, module_name: str, **params) -> str:
        """Run a module in background, return job_id."""
        if module_name not in self.registry:
            raise ValueError(f"Module '{module_name}' not found")

        module = self.registry[module_name]

        job_id = str(uuid.uuid4())
        job = Job(module.run, **params)

        self.jobs[job_id] = job
        self.queue.add(job)

        return job_id

    def get_status(self, job_id: str) -> Dict[str, Any]:
        """Return status/result for API."""
        job = self.jobs.get(job_id)
        if not job:
            return {"status": "not_found"}

        if not job.finished.is_set():
            return {"status": "running"}

        if job.error:
            return {"status": "error", "error": job.error}

        return {
            "status": "done",
            "result": job.result,
        }

