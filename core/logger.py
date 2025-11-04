import json
import csv
import yaml
import smtplib
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class Logging:
    def __init__(self):
        # Load configuration
        self.config = self._load_config()
        
        # Set up based on config
        project_root = Path(__file__).resolve().parent.parent  # Goes from core/logger.py to blackice root
        self.output_dir = project_root / self.config['output_dir']
        self.output_dir.mkdir(exist_ok=True)

        self.entries = []
        self.start_time = datetime.now()
        self.output_format = self.config['format']

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file in project root"""
        # Config file is in project root (blackice/logger.yaml)
        config_path = Path(__file__).resolve().parent.parent / "logger.yaml"
        
        # Default configuration
        default_config = {
            'format': 'json',
            'output_dir': 'logs',
            'console': {
                'show_progress': True,
                'show_log_messages': False,
                'show_module_start': True,
                'show_module_completion': True
            },
            'file': {
                'include_timestamp': True,
                'filename_pattern': 'blackice_scan_{timestamp}',
                'max_file_size': 10,
                'backup_count': 5
            },
            'include': {
                'module_results': True,
                'error_details': True,
                'scan_metadata': True,
                'timing_info': True
            },
            'email': {
                'enabled': False,
                'smtp_server': 'sandbox.smtp.mailtrap.io',  # Changed to Mailtrap default
                'smtp_port': 2525,  # Changed to Mailtrap port
                'sender_email': '',
                'sender_username': '',  # ADDED: Mailtrap username field
                'sender_password': '',
                'recipient_emails': [],
                'notifications': {
                    'baseline_changes': True,
                    'critical_findings': True,
                    'scan_completion': True  # Changed to true
                }
            }
        }
        
        try:
            if config_path.exists():
                print(f"Loading logger configuration from: {config_path}")
                with open(config_path, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                    # Merge with defaults (loaded config overrides defaults)
                    if 'logging' in loaded_config:
                        return self._deep_merge(default_config, loaded_config['logging'])
                    else:
                        return default_config
            else:
                # Create default config file if it doesn't exist
                with open(config_path, 'w') as f:
                    yaml.dump({'logging': default_config}, f, default_flow_style=False)
                print(f"Created default configuration file: {config_path}")
                return default_config
        except Exception as e:
            print(f"Error loading configuration: {e}. Using defaults.")
            return default_config

    def _deep_merge(self, base: Dict, update: Dict) -> Dict:
        """Recursively merge two dictionaries"""
        result = base.copy()
        for key, value in update.items():
            if isinstance(value, dict) and key in result and isinstance(result[key], dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def initialize(self):
        """Initialize logging system - now uses config instead of user input"""
        if self.output_format is None or self.output_format == "none":
            print("Logging disabled by configuration.")
        else:
            print(f"Logging initialized: {self.output_format.upper()} format")

    def log_module_start(self, module_name: str, target: str):
        """Log when a module starts execution"""
        if self.config['console']['show_module_start']:
            print(f"Starting module: {module_name} on {target}")
            
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
        if self.config['console']['show_module_completion']:
            print(f"Module {module_name} completed")
            
        if self.config['console']['show_log_messages']:
            print(f"Logged results from {module_name}")

        # Filter result data based on configuration
        filtered_result = self._filter_result_data(result)
        
        entry = {
            "timestamp": datetime.now().isoformat(),
            "module": module_name,
            "target": target,
            "event": "module_complete",
            "result": filtered_result
        }
        self.entries.append(entry)

    def log_error(self, module_name: str, target: str, error: str):
        """Log module errors"""
        print(f"Error in {module_name}: {error}")
        
        error_data = {"error": error}
        if self.config['include']['error_details']:
            error_data["details"] = f"Module: {module_name}, Target: {target}"
            
        entry = {
            "timestamp": datetime.now().isoformat(),
            "module": module_name,
            "target": target,
            "event": "module_error",
            "result": error_data
        }
        self.entries.append(entry)

    def _filter_result_data(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Filter result data based on configuration"""
        filtered = result.copy()
        
        if not self.config['include']['module_results']:
            filtered = {"status": "completed"}  # Only include basic status
            
        if not self.config['include']['timing_info'] and 'scan_duration' in filtered:
            del filtered['scan_duration']
            
        return filtered

    def finalize(self):
        """Finalize logging and write to file based on configuration"""
        if self.output_format is None or self.output_format == "none":
            return

        # Prepare metadata based on configuration
        metadata = {}
        if self.config['include']['scan_metadata']:
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

    def _write_json(self, metadata):
        """Write results to JSON file"""
        filename = self._generate_filename("json")
        data = {"metadata": metadata, "entries": self.entries} if metadata else {"entries": self.entries}
        
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        print(f"JSON log saved to {filename}")

    def _write_csv(self, metadata):
        """Write results to CSV file"""
        filename = self._generate_filename("csv")
        
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            
            # Write metadata as comments
            if metadata:
                for key, value in metadata.items():
                    writer.writerow([f"# {key}: {value}"])
                writer.writerow([])
            
            # Write headers and data
            writer.writerow(["timestamp", "module", "target", "event", "result_json"])
            for entry in self.entries:
                writer.writerow([
                    entry["timestamp"], 
                    entry["module"], 
                    entry["target"], 
                    entry["event"], 
                    json.dumps(entry["result"])
                ])
        print(f"CSV log saved to {filename}")

    def _generate_filename(self, extension: str) -> Path:
        """Generate filename based on configuration"""
        if self.config['file']['include_timestamp']:
            timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
            pattern = self.config['file']['filename_pattern'].format(timestamp=timestamp)
            filename = f"{pattern}.{extension}"
        else:
            filename = f"blackice_scan.{extension}"
            
        return self.output_dir / filename

    # Email notification methods
    def send_email_notification(self, subject: str, message: str, is_critical: bool = False):
        """Send email notification based on configuration"""
        email_config = self.config.get('email', {})
        
        # Check if email is enabled
        #if not email_config.get('enabled', False):
        #    print("DEBUG: Email notifications are disabled in configuration")
        #    return False
            
        # Check notification preferences
        #if is_critical and not email_config.get('notifications', {}).get('critical_findings', True):
        #    print("DEBUG: Critical notifications are disabled")
        #    return False
            
        try:
            # Email configuration
            smtp_server = email_config.get('smtp_server', 'sandbox.smtp.mailtrap.io')
            smtp_port = email_config.get('smtp_port', 2525)
            sender_email = email_config.get('sender_email')
            sender_username = email_config.get('sender_username')  # Get Mailtrap username
            sender_password = email_config.get('sender_password')
            recipient_emails = email_config.get('recipient_emails', [])
            
            print(f"DEBUG: Attempting to send email via {smtp_server}:{smtp_port}")
            print(f"DEBUG: Username: {sender_username}, Sender: {sender_email}")
            
            if not sender_email or not sender_password or not recipient_emails:
                print("Email configuration incomplete. Check logger.yaml")
                return False
            
            # Use username for login, fallback to sender_email if username not provided
            login_username = sender_username if sender_username else sender_email
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = ', '.join(recipient_emails)
            msg['Subject'] = f"BlackICE Alert: {subject}"

            # Add message body
            body = f"""
BlackICE Security Scanner Notification

{message}

---
Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
System: {self._get_system_info()}
            """
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
       #     print(f"DEBUG: Connecting to SMTP server...")
            with smtplib.SMTP(smtp_server, smtp_port) as server:
        #        print(f"DEBUG: Starting TLS...")
                server.starttls()
         #       print(f"DEBUG: Logging in with username: {login_username}")
                server.login(login_username, sender_password)
          #      print(f"DEBUG: Sending message...")
                server.send_message(msg)
            
            print(f"Email notification sent: {subject}")
            return True
            
        except Exception as e:
            print(f"Failed to send email notification: {e}")
            return False

    def _get_system_info(self):
        """Get basic system information for email notifications"""
        import platform
        return f"{platform.node()} ({platform.system()} {platform.release()})"

    def notify_baseline_changes(self, changes_count: int, scan_file: str, changes_summary: str = ""):
        """Send notification about baseline changes"""
        #print(f"DEBUG: notify_baseline_changes called - {changes_count} changes")
        email_config = self.config.get('email', {})
        if not email_config.get('notifications', {}).get('baseline_changes', True):
         #   print("DEBUG: Baseline change notifications disabled")
            return
            
        if changes_count > 0:
            subject = f"Baseline Changes Detected ({changes_count} changes)"
            message = f"""
ALERT: System baseline changes detected!

Scan File: {scan_file}
Changes Found: {changes_count}

Summary of Changes:
{changes_summary}

Review the comparison file for detailed information.
            """
            self.send_email_notification(subject, message, is_critical=True)
        else:
            subject = "Baseline Scan Completed - No Changes"
            message = f"""
Baseline scan completed successfully.

Scan File: {scan_file}
Status: No significant changes detected

System appears to be in expected state.
            """
            self.send_email_notification(subject, message, is_critical=False)

    def notify_baseline_scan_complete(self, scan_result: Dict[str, Any]):
        """Send notification when baseline scan completes"""
        #print(f"DEBUG: notify_baseline_scan_complete called")
        email_config = self.config.get('email', {})
        if not email_config.get('notifications', {}).get('scan_completion', True):
         #   print("DEBUG: Scan completion notifications disabled")
            return
            
        subject = "Baseline Scan Completed"
        summary = scan_result.get('data', {}).get('summary', {})
        
        message = f"""
Baseline scan completed successfully.

Scan ID: {scan_result.get('scan_id', 'Unknown')}
Output File: {scan_result.get('output_file', 'Unknown')}

Scan Summary:
- Total Checks: {summary.get('total_checks', 0)}
- Passed: {summary.get('passed', 0)}
- Warnings: {summary.get('warnings', 0)}
- Critical: {summary.get('critical', 0)}

System: {self._get_system_info()}
        """
        self.send_email_notification(subject, message, is_critical=False)

logger = Logging()
