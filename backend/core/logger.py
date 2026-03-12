import json
import csv
import yaml
import smtplib
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class Logging:
    """
    BlackICE Logging System
    Handles:
    - JSON / CSV logging
    - module tracking
    - vulnerability reporting
    - email notifications
    """

    def __init__(self):

        project_root = Path.cwd()

        self.config_path = project_root / "logger.yaml"
        self.config = self._load_config()

        self.output_dir = project_root / self.config.get("output_dir", "logs")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.entries: List[Dict[str, Any]] = []

        self.start_time = datetime.now()
        self.output_format = self.config.get("format", "json")

    # --------------------------------------------------
    # CONFIG LOADING
    # --------------------------------------------------

    def _load_config(self) -> Dict[str, Any]:

        config_path = self.config_path

        default_config = {
            "format": "json",
            "output_dir": "logs",
            "console": {
                "show_progress": True,
                "show_log_messages": False,
                "show_module_start": True,
                "show_module_completion": True,
            },
            "file": {
                "include_timestamp": True,
                "filename_pattern": "blackice_scan_{timestamp}",
                "max_file_size": 10,
                "backup_count": 5,
            },
            "include": {
                "module_results": True,
                "error_details": True,
                "scan_metadata": True,
                "timing_info": True,
            },
            "email": {
                "enabled": False,
                "smtp_server": "sandbox.smtp.mailtrap.io",
                "smtp_port": 2525,
                "sender_email": "",
                "sender_username": "",
                "sender_password": "",
                "recipient_emails": [],
                "notifications": {
                    "baseline_changes": True,
                    "critical_findings": True,
                    "scan_completion": True,
                },
            },
        }

        try:
            if config_path.exists():

                with open(config_path, "r") as f:
                    loaded_config = yaml.safe_load(f)

                    if "logging" in loaded_config:
                        return self._deep_merge(default_config, loaded_config["logging"])
                    else:
                        return default_config

            else:

                with open(config_path, "w") as f:
                    yaml.dump({"logging": default_config}, f)

                print(f"Created default configuration: {config_path}")

                return default_config

        except Exception as e:
            print(f"Config error: {e}")
            return default_config

    def _deep_merge(self, base: Dict, update: Dict) -> Dict:

        result = base.copy()

        for key, value in update.items():

            if isinstance(value, dict) and key in result and isinstance(result[key], dict):
                result[key] = self._deep_merge(result[key], value)

            else:
                result[key] = value

        return result

    # --------------------------------------------------
    # INITIALIZATION
    # --------------------------------------------------

    def initialize(self):

        if self.output_format is None or self.output_format == "none":
            print("Logging disabled")
        else:
            print(f"Logging initialized ({self.output_format.upper()})")

    # --------------------------------------------------
    # MODULE EVENTS
    # --------------------------------------------------

    def log_module_start(self, module_name: str, target: str):

        if self.config["console"]["show_module_start"]:
            print(f"[+] Starting module: {module_name} -> {target}")

        entry = {
            "timestamp": datetime.now().isoformat(),
            "module": module_name,
            "target": target,
            "event": "module_start",
            "result": {"status": "started"},
        }

        self.entries.append(entry)

    def log_module_result(self, module_name: str, target: str, result: Dict[str, Any]):

        if self.config["console"]["show_module_completion"]:
            print(f"[+] Module completed: {module_name}")

        filtered_result = self._filter_result_data(result)

        entry = {
            "timestamp": datetime.now().isoformat(),
            "module": module_name,
            "target": target,
            "event": "module_complete",
            "result": filtered_result,
        }

        self.entries.append(entry)

    # --------------------------------------------------
    # VULNERABILITY LOGGING
    # --------------------------------------------------

    def log_vulnerability(
        self,
        module_name: str,
        target: str,
        vulnerability_type: str,
        details: str,
        severity: str = "HIGH",
    ):
        """
        Used by scanners (XSS, SQLi, etc)
        """

        print(f"[!] Vulnerability Detected: {vulnerability_type}")

        entry = {
            "timestamp": datetime.now().isoformat(),
            "module": module_name,
            "target": target,
            "event": "vulnerability",
            "result": {
                "type": vulnerability_type,
                "severity": severity,
                "details": details,
            },
        }

        self.entries.append(entry)

    # --------------------------------------------------
    # ERROR LOGGING
    # --------------------------------------------------

    def log_error(self, module_name: str, target: str, error: str):

        print(f"[ERROR] {module_name}: {error}")

        entry = {
            "timestamp": datetime.now().isoformat(),
            "module": module_name,
            "target": target,
            "event": "error",
            "result": {"error": error},
        }

        self.entries.append(entry)

    # --------------------------------------------------
    # RESULT FILTER
    # --------------------------------------------------

    def _filter_result_data(self, result: Dict[str, Any]) -> Dict[str, Any]:

        filtered = result.copy()

        if not self.config["include"]["module_results"]:
            filtered = {"status": "completed"}

        if not self.config["include"]["timing_info"] and "scan_duration" in filtered:
            del filtered["scan_duration"]

        return filtered

    # --------------------------------------------------
    # FINALIZE
    # --------------------------------------------------

    def finalize(self):

        if self.output_format in [None, "none"]:
            return

        metadata = {}

        if self.config["include"]["scan_metadata"]:
            end_time = datetime.now()

            metadata = {
                "scan_start": self.start_time.isoformat(),
                "scan_end": end_time.isoformat(),
                "duration": str(end_time - self.start_time),
                "total_modules": len(set(e["module"] for e in self.entries)),
                "total_entries": len(self.entries),
            }

        if self.output_format == "json":
            self._write_json(metadata)

        elif self.output_format == "csv":
            self._write_csv(metadata)

    # --------------------------------------------------
    # FILE WRITERS
    # --------------------------------------------------

    def _write_json(self, metadata):

        filename = self._generate_filename("json")

        data = {"metadata": metadata, "entries": self.entries}

        with open(filename, "w") as f:
            json.dump(data, f, indent=4)

        print(f"[+] JSON log saved -> {filename}")

    def _write_csv(self, metadata):

        filename = self._generate_filename("csv")

        with open(filename, "w", newline="") as f:

            writer = csv.writer(f)

            if metadata:

                for key, value in metadata.items():
                    writer.writerow([f"# {key}: {value}"])

                writer.writerow([])

            writer.writerow(["timestamp", "module", "target", "event", "result"])

            for entry in self.entries:
                writer.writerow(
                    [
                        entry["timestamp"],
                        entry["module"],
                        entry["target"],
                        entry["event"],
                        json.dumps(entry["result"]),
                    ]
                )

        print(f"[+] CSV log saved -> {filename}")

    # --------------------------------------------------
    # FILENAME GENERATION
    # --------------------------------------------------

    def _generate_filename(self, extension: str) -> Path:

        if self.config["file"]["include_timestamp"]:

            timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")

            pattern = self.config["file"]["filename_pattern"].format(
                timestamp=timestamp
            )

            filename = f"{pattern}.{extension}"

        else:

            filename = f"blackice_scan.{extension}"

        return self.output_dir / filename

    # --------------------------------------------------
    # EMAIL NOTIFICATIONS
    # --------------------------------------------------

    def send_email_notification(self, subject: str, message: str, is_critical=False):

        email_config = self.config.get("email", {})

        if not email_config.get("enabled"):
            return False

        try:

            smtp_server = email_config["smtp_server"]
            smtp_port = email_config["smtp_port"]

            sender_email = email_config["sender_email"]
            sender_username = email_config.get("sender_username") or sender_email
            sender_password = email_config["sender_password"]

            recipients = email_config["recipient_emails"]

            if not recipients:
                return False

            msg = MIMEMultipart()

            msg["From"] = sender_email
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = f"BlackICE Alert: {subject}"

            msg.attach(MIMEText(message, "plain"))

            with smtplib.SMTP(smtp_server, smtp_port) as server:

                server.starttls()
                server.login(sender_username, sender_password)
                server.send_message(msg)

            print("Email notification sent")

            return True

        except Exception as e:

            print(f"Email failed: {e}")

            return False


logger = Logging()
