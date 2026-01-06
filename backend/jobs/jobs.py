# backend/jobs/jobs.py

import threading
from queue import Queue
from typing import Callable, Any, Optional


class Job:
    """
    Represents a background job executing a module's run() function.
    """

    def __init__(self, task: Callable, *args, **kwargs):
        self.task = task
        self.args = args
        self.kwargs = kwargs
        self.result: Optional[Any] = None
        self.error: Optional[str] = None
        self.finished = threading.Event()

    def run(self):
        try:
            self.result = self.task(*self.args, **self.kwargs)
        except Exception as e:
            self.error = str(e)
        finally:
            self.finished.set()


class JobQueue:
    """Simple but reliable worker pool."""

    def __init__(self, workers: int = 5):
        self.queue = Queue()
        self.workers = workers
        self.threads = []
        self._stop_flag = False

    def worker(self):
        while not self._stop_flag:
            job = self.queue.get()
            if job is None:   # shutdown signal
                self.queue.task_done()
                return

            job.run()
            self.queue.task_done()

    def start(self):
        for _ in range(self.workers):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            self.threads.append(t)

    def stop(self):
        self._stop_flag = True
        for _ in self.threads:
            self.queue.put(None)
        for t in self.threads:
            t.join()

    def add(self, job: Job):
        self.queue.put(job)

