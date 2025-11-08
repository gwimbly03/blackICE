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
    This is my logging class I made for each module, it allows a user to to customize how verbose they want the logs, it allows for json or csv logs.
    You can customize the logs through the logger.yaml file
    """

    def __init__(self):
        """
        This sets up the logging folder, object and loads configurations
        """
        self.config = self._load_config()
        
        project_root = Path(__file__).resolve().parent.parent  # Goes from core/logger.py to blackice root
        self.output_dir = project_root / self.config['output_dir']
        self.output_dir.mkdir(exist_ok=True)

        self.entries = []
        self.start_time = datetime.now()
        self.output_format = self.config['format']

    def _load_config(self) -> Dict[str, Any]:
        """
        Loads the config from the logger.yaml if the file is not found then it will create on in the root of the project
        """
        config_path = Path(__file__).resolve().parent.parent / "logger.yaml"
        
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
                'smtp_server': 'sandbox.smtp.mailtrap.io',
                'smtp_port': 2525,
                'sender_email': 'security@blackICE.com',
                'sender_username': 'da294f52f2fa19',
                'sender_password': '1fb4bacababd86',
                'recipient_emails': [],
                'notifications': {
                    'baseline_changes': True,
                    'critical_findings': True,
                    'scan_completion': True
                }
            }
        }
        
        try:
            if config_path.exists():
                print(f"Loading logger configuration from: {config_path}")
                with open(config_path, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                    if 'logging' in loaded_config:
                        return self._deep_merge(default_config, loaded_config['logging'])
                    else:
                        return default_config
            else:
                with open(config_path, 'w') as f:
                    yaml.dump({'logging': default_config}, f, default_flow_style=False)
                print(f"Created default configuration file: {config_path}")
                return default_config
        except Exception as e:
            print(f"Error loading configuration: {e}. Using defaults.")
            return default_config

    def _deep_merge(self, base: Dict, update: Dict) -> Dict:
        """
        recursively merge two dictionaries
        """
        result = base.copy()
        for key, value in update.items():
            if isinstance(value, dict) and key in result and isinstance(result[key], dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def initialize(self):
        """
        Initialize logging system which uses config in the logger.yaml 
        """
        if self.output_format is None or self.output_format == "none":
            print("Logging disabled by configuration.")
        else:
            print(f"Logging initialized: {self.output_format.upper()} format")

    def log_module_start(self, module_name: str, target: str):
        """
        When a module starts to run it will be logged
        """
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
        """
        Log module results with metadata
        """
        if self.config['console']['show_module_completion']:
            print(f"Module {module_name} completed")
            
        if self.config['console']['show_log_messages']:
            print(f"Logged results from {module_name}")

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
        """
        Log module errors
        """
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
        """
        Filter result data based on config
        """
        filtered = result.copy()
        
        if not self.config['include']['module_results']:
            filtered = {"status": "completed"}  # Only include basic status
            
        if not self.config['include']['timing_info'] and 'scan_duration' in filtered:
            del filtered['scan_duration']
            
        return filtered

    def finalize(self):
        """
        Finalize the logging then write to file based on the config in the logger.yaml
        """
        if self.output_format is None or self.output_format == "none":
            return

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
        """
        Save the results to json file
        """
        filename = self._generate_filename("json")
        data = {"metadata": metadata, "entries": self.entries} if metadata else {"entries": self.entries}
        
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        print(f"JSON log saved to {filename}")

    def _write_csv(self, metadata):
        """
        Save the results to csv file
        """
        filename = self._generate_filename("csv")
        
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            
            if metadata:
                for key, value in metadata.items():
                    writer.writerow([f"# {key}: {value}"])
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
        print(f"CSV log saved to {filename}")

    def _generate_filename(self, extension: str) -> Path:
        """
        Generate filename based on config in logger.yaml
        """
        if self.config['file']['include_timestamp']:
            timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
            pattern = self.config['file']['filename_pattern'].format(timestamp=timestamp)
            filename = f"{pattern}.{extension}"
        else:
            filename = f"blackice_scan.{extension}"
            
        return self.output_dir / filename

    def _calculate_scan_summary(self, findings):
        """
        Calculate summary statistics from scan findings
        """
        if not findings:
            return {}
        
        status_counts = {}
        for finding in findings:
            status = finding.get('status', 'UNKNOWN')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            'total_checks': len(findings),
            'passed': status_counts.get('PASS', 0),
            'warnings': status_counts.get('WARNING', 0),
            'critical': status_counts.get('CRITICAL', 0),
            'unknown': status_counts.get('UNKNOWN', 0)
        }

    def _get_system_info(self):
        """
        Get basic system information for email notifications
        """
        import platform
        return f"{platform.node()} ({platform.system()} {platform.release()})"

    def _format_changes_for_email(self, changes: List[Dict[str, Any]]) -> str:
        """Format changes in a readable way for email"""
        if not changes:
            return "No changes detected since last scan"
        
        changes_by_type = {}
        for change in changes:
            change_type = change.get('type', 'UNKNOWN')
            if change_type not in changes_by_type:
                changes_by_type[change_type] = []
            changes_by_type[change_type].append(change)
        
        formatted_output = []
        
        for change_type, type_changes in changes_by_type.items():
            formatted_output.append(f"\n{change_type} CHANGES ({len(type_changes)}):")
            formatted_output.append("=" * 50)
            
            for i, change in enumerate(type_changes, 1):
                formatted_output.append(f"\n{i}. Module: {change.get('module', 'Unknown')}")
                formatted_output.append(f"   Description: {change.get('description', 'No description')}")
                
                if change_type == "CHANGED":
                    prev = change.get('previous', {})
                    curr = change.get('current', {})
                    
                    if prev.get('status') != curr.get('status'):
                        formatted_output.append(f"   Status: {prev.get('status')} → {curr.get('status')}")
                    
                    if prev.get('hash') and curr.get('hash') and prev.get('hash') != curr.get('hash'):
                        formatted_output.append(f"   File Hash: {prev.get('hash')[:16]}... → {curr.get('hash')[:16]}...")
                    
                    count_fields = ['process_count', 'package_count', 'users_count', 'groups_count', 'interface_count', 'cron_entries']
                    for field in count_fields:
                        if prev.get(field) != curr.get(field):
                            formatted_output.append(f"   {field}: {prev.get(field)} → {curr.get(field)}")
                
                elif change_type == "NEW":
                    new_finding = change.get('finding', {})
                    if new_finding.get('check'):
                        formatted_output.append(f"   File: {new_finding.get('check')}")
                    if new_finding.get('hash'):
                        formatted_output.append(f"   Hash: {new_finding.get('hash')[:16]}...")
                
                elif change_type == "REMOVED":
                    removed_finding = change.get('finding', {})
                    if removed_finding.get('check'):
                        formatted_output.append(f"   File: {removed_finding.get('check')}")
        
        return "\n".join(formatted_output)

    def send_email_notification(self, subject: str, message: str, is_critical: bool = False):
        """
        Send email notification based on configuration
        """
        email_config = self.config.get('email', {})
        
        # Debug: Check email configuration
        #print(f"DEBUG: Email enabled: {email_config.get('enabled', False)}")
        #print(f"DEBUG: SMTP Server: {email_config.get('smtp_server')}")
        #print(f"DEBUG: Sender: {email_config.get('sender_email')}")
        #print(f"DEBUG: Recipients: {email_config.get('recipient_emails', [])}")
        
        if not email_config.get('enabled', False):
            #print("DEBUG: Email notifications are disabled in configuration")
            return False
            
        if is_critical and not email_config.get('notifications', {}).get('critical_findings', True):
            #print("DEBUG: Critical notifications are disabled")
            return False
            
        try:
            smtp_server = email_config.get('smtp_server', 'sandbox.smtp.mailtrap.io')
            smtp_port = email_config.get('smtp_port', 2525)
            sender_email = email_config.get('sender_email')
            sender_username = email_config.get('sender_username')
            sender_password = email_config.get('sender_password')
            recipient_emails = email_config.get('recipient_emails', [])
            
            if not sender_email:
                #print("DEBUG: No sender_email configured")
                return False
            if not sender_password:
                #print("DEBUG: No sender_password configured")
                return False
            if not recipient_emails:
                #print("DEBUG: No recipient_emails configured")
                return False
            
            # Use username for login, fallback to sender_email if username not provided
            login_username = sender_username if sender_username else sender_email
            
            #print(f"DEBUG: Attempting to send email via {smtp_server}:{smtp_port}")
            #print(f"DEBUG: Login username: {login_username}")
            
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = ', '.join(recipient_emails)
            msg['Subject'] = f"BlackICE Alert: {subject}"

            body = f"""
BlackICE Security Scanner Notification

{message}

---
Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
System: {self._get_system_info()}
            """
            msg.attach(MIMEText(body, 'plain'))
            
            #print(f"DEBUG: Connecting to SMTP server...")
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                #print(f"DEBUG: Starting TLS...")
                server.starttls()
                #print(f"DEBUG: Logging in...")
                server.login(login_username, sender_password)
                #print(f"DEBUG: Sending message...")
                server.send_message(msg)
            
            print(f"Email notification sent successfully: {subject}")
            return True
            
        except Exception as e:
            print(f"Failed to send email notification: {e}")
            import traceback
            traceback.print_exc()
            return False

    def notify_baseline_scan_complete(self, scan_result: Dict[str, Any]):
        """
        Send single notification when baseline scan completes with comparison results
        """
        email_config = self.config.get('email', {})
        
        #print(f"DEBUG: Starting notify_baseline_scan_complete")
        #print(f"DEBUG: Email enabled: {email_config.get('enabled', False)}")
        #print(f"DEBUG: Scan completion notifications enabled: {email_config.get('notifications', {}).get('scan_completion', True)}")
        
        if not email_config.get('enabled', False):
            #print("DEBUG: Email is disabled, skipping notification")
            return
            
        if not email_config.get('notifications', {}).get('scan_completion', True):
            #print("DEBUG: Scan completion notifications are disabled")
            return
        
        findings = scan_result.get('findings', [])
        summary = self._calculate_scan_summary(findings)
        
        comparison_result = scan_result.get('comparison', {})
        changes_count = comparison_result.get('changes_count', 0)
        changes = comparison_result.get('changes', [])
        
        is_critical = summary.get('critical', 0) > 0 or changes_count > 0
        
        if changes_count > 0:
            subject = f"Baseline Scan Complete - {changes_count} Changes Detected"
        else:
            subject = "Baseline Scan Complete - No Changes"
        
        message_parts = []
        
        message_parts.append(f"""
Baseline scan completed successfully.

Scan ID: {scan_result.get('scan_id', 'Unknown')}
Timestamp: {scan_result.get('timestamp', 'Unknown')}

SCAN SUMMARY:
- Total Checks: {summary.get('total_checks', 0)}
- Passed: {summary.get('passed', 0)}
- Warnings: {summary.get('warnings', 0)}
- Critical: {summary.get('critical', 0)}
- Unknown: {summary.get('unknown', 0)}
""")
        
        if comparison_result:
            message_parts.append(f"""
COMPARISON RESULTS:
- Changes since last scan: {changes_count}
- Previous scan: {comparison_result.get('previous_scan_id', 'Unknown')}
- Current scan: {comparison_result.get('current_scan_id', 'Unknown')}
""")
            
            if changes_count > 0:
                detailed_changes = self._format_changes_for_email(changes)
                message_parts.append(f"\nDETAILED CHANGES:\n{detailed_changes}")
        
        if is_critical:
            critical_alerts = []
            if summary.get('critical', 0) > 0:
                critical_alerts.append(f"{summary.get('critical', 0)} critical findings")
            if changes_count > 0:
                critical_alerts.append(f"{changes_count} system changes")
            
            message_parts.append(f"\nCRITICAL ALERT: {', '.join(critical_alerts)} - IMMEDIATE ATTENTION REQUIRED")
        else:
            message_parts.append("\nNo critical issues detected")
        
        full_message = "".join(message_parts)
        
        #print(f"DEBUG: Sending email with subject: {subject}")
        #print(f"DEBUG: Is critical: {is_critical}")
        
        success = self.send_email_notification(subject, full_message, is_critical=is_critical)
        
        if success:
            print("DEBUG: Email sent successfully")
        else:
            print("DEBUG: Failed to send email")

logger = Logging()
