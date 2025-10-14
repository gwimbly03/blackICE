# core/logger.py
import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

class Logging:
    def __init__(self):
        project_root = Path(__file__).resolve().parent.parent
        self.output_dir = project_root / "logs"
        self.output_dir.mkdir(exist_ok=True)

        self.entries = []
        self.start_time = datetime.now()
        self.output_format: Optional[str] = None
        self.initialized = False

    def initialize(self):
        """Initialize logging with user format choice"""
        if not self.initialized:
            self.output_format = self._choose_format()
            self.initialized = True

    def _choose_format(self) -> Optional[str]:
        """
        Ask the user what format to save logs in.
        """
        while True:
            print("\nChoose your log format:")
            print("0. No log")
            print("1. JSON")
            print("2. CSV")
            choice = input("> ").strip()

            if choice == "0":
                return None
            if choice == "1":
                return "json"
            if choice == "2":
                return "csv"

            print("Invalid choice. Please enter 0, 1 or 2.")

    def log_module_start(self, module_name: str, target: str):
        """Log when a module starts execution"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "module": module_name,
            "target": target,
            "event": "module_start",
            "result": {"status": "started"}
        }
        self.entries.append(entry)

    def log_module_result(self, module_name: str, target: str, result: Dict[str, Any]):
        """Log module results with metadata."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "module": module_name,
            "target": target,
            "event": "module_complete",
            "result": result
        }
        self.entries.append(entry)
        print(f"Logged results from {module_name}")

    def log_error(self, module_name: str, target: str, error: str):
        """Log module errors"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "module": module_name,
            "target": target,
            "event": "module_error",
            "result": {"error": error}
        }
        self.entries.append(entry)

    def finalize(self):
        """Finalize logging and write to file (unless user chose No log)."""
        if self.output_format is None:
            print("\nNo log chosen — skipping file write.")
            return

        end_time = datetime.now()
        metadata = {
            "scan_start": self.start_time.isoformat(),
            "scan_end": end_time.isoformat(),
            "duration": str(end_time - self.start_time),
            "total_modules": len(set(e["module"] for e in self.entries)),
            "total_entries": len(self.entries)
        }

        if self.output_format == "json":
            self._write_json(metadata)
        elif self.output_format == "csv":
            self._write_csv(metadata)
        else:
            raise ValueError("Unsupported format. Use 'json', 'csv', or None.")

    def _write_json(self, metadata):
        filename = self.output_dir / f"blackice_log_{self.start_time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump({"metadata": metadata, "entries": self.entries}, f, indent=4)
        print(f"\nJSON log saved to {filename}")

    def _write_csv(self, metadata):
        filename = self.output_dir / f"blackice_log_{self.start_time.strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([f"# scan_start: {metadata['scan_start']}"])
            writer.writerow([f"# scan_end:   {metadata['scan_end']}"])
            writer.writerow([f"# duration:   {metadata['duration']}"])
            writer.writerow([f"# total_modules: {metadata['total_modules']}"])
            writer.writerow([])
            writer.writerow(["timestamp", "module", "target", "event", "result_json"])
            for entry in self.entries:
                writer.writerow([
                    entry["timestamp"], 
                    entry["module"], 
                    entry["target"], 
                    entry["event"], 
                    json.dumps(entry["result"])
                ])
        print(f"\nCSV log saved to {filename}")

logger = Logging()
