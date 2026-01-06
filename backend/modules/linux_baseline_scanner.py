import os
import hashlib
import datetime
import platform
import subprocess
from time import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Any, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TimeRemainingColumn

from core.logger import logger


class LinuxBaselineScanner:
    """
    Optimized Linux system baseline scanner for security monitoring and change detection.
    This version improves performance using parallel scanning, caching, faster JSON serialization,
    and reduced redundant syscalls — while maintaining compatibility with the existing engine/logger.
    """

    description = "Comprehensive Linux system baseline scanner for security monitoring and change detection"

    def __init__(self):
        self.module_name = "linux_baseline"
        self.console = Console()
        self.output_dir = Path("baseline")
        self.output_dir.mkdir(exist_ok=True)

    # ==============================
    # Core Scan Entry
    # ==============================

    def run(self, compare_with_previous: bool = True):
        scan_result = self._perform_baseline_scan()
        
        if compare_with_previous:
            comparison_result = self._compare_with_previous_scan(scan_result)
            if comparison_result:
                scan_result["comparison"] = comparison_result
                
                # Ask user if they want to view detailed comparison
                self._prompt_for_detailed_comparison(comparison_result)
        
        # Only call notify_baseline_scan_complete - it now handles everything
        logger.notify_baseline_scan_complete(scan_result)
        return scan_result

    # ==============================
    # Comparison Functionality
    # ==============================

    def _prompt_for_detailed_comparison(self, comparison_result: Dict[str, Any]):
        """Ask user if they want to view detailed comparison results"""
        if comparison_result["changes_count"] == 0:
            return
        
        self.console.print("\n[bold yellow]Comparison completed![/bold yellow]")
        self.console.print(f"[cyan]Found {comparison_result['changes_count']} changes since last scan[/cyan]")
        
        while True:
            response = input("\nDo you want to view detailed comparison results? (y/n): ").strip().lower()
            if response in ['y', 'yes']:
                self._show_detailed_comparison(comparison_result)
                break
            elif response in ['n', 'no']:
                self.console.print("[dim]Skipping detailed comparison view[/dim]")
                break
            else:
                self.console.print("[red]Please enter 'y' for yes or 'n' for no[/red]")

    def _show_detailed_comparison(self, comparison_result: Dict[str, Any]):
        """Show detailed comparison results with pagination"""
        changes = comparison_result["changes"]
        
        if not changes:
            self.console.print("[green]No changes to display[/green]")
            return
        
        # Group changes by type for better organization
        changes_by_type = {
            "NEW": [c for c in changes if c["type"] == "NEW"],
            "REMOVED": [c for c in changes if c["type"] == "REMOVED"],
            "CHANGED": [c for c in changes if c["type"] == "CHANGED"]
        }
        
        self.console.print(Panel.fit(
            f"[bold]Comparison Details[/bold]\n"
            f"Previous Scan: {comparison_result['previous_scan_id']}\n"
            f"Current Scan: {comparison_result['current_scan_id']}\n"
            f"Total Changes: {comparison_result['changes_count']}",
            style="blue"
        ))
        
        # Show changes by category
        for change_type, type_changes in changes_by_type.items():
            if type_changes:
                self._show_changes_by_type(change_type, type_changes)
        
        # Offer to show raw JSON data
        self._prompt_for_raw_data(comparison_result)

    def _show_changes_by_type(self, change_type: str, changes: List[Dict[str, Any]]):
        """Show changes organized by type"""
        color = {
            "NEW": "green",
            "REMOVED": "red", 
            "CHANGED": "yellow"
        }.get(change_type, "white")
        
        table = Table(title=f"{change_type} Changes ({len(changes)} items)", show_lines=True)
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Details", style="white")
        
        for change in changes:
            module = change["module"]
            description = change["description"]
            
            # Truncate very long descriptions for table display
            if len(description) > 80:
                description = description[:77] + "..."
            
            table.add_row(module, description)
        
        self.console.print(Panel(table, title=f"[bold {color}]{change_type} Changes[/bold {color}]"))

    def _prompt_for_raw_data(self, comparison_result: Dict[str, Any]):
        """Ask user if they want to see raw JSON data"""
        while True:
            response = input("\nDo you want to view raw comparison data? (y/n): ").strip().lower()
            if response in ['y', 'yes']:
                self.console.print("\n[bold cyan]Raw Comparison Data:[/bold cyan]")
                self.console.print_json(data=comparison_result)
                break
            elif response in ['n', 'no']:
                break
            else:
                self.console.print("[red]Please enter 'y' for yes or 'n' for no[/red]")

    def _get_previous_scan(self) -> Optional[Dict[str, Any]]:
        """Get the most recent previous scan for comparison"""
        try:
            baseline_files = list(self.output_dir.glob("linux_baseline_*.json"))
            if len(baseline_files) <= 1:
                return None
            
            # Sort by creation time and get the second most recent (most recent is current)
            baseline_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            previous_scan_file = baseline_files[1]  # Skip the current one
            
            self.console.print(f"[dim]Comparing with: {previous_scan_file.name}[/dim]")
            return self._load_json(previous_scan_file)
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not load previous scan: {e}[/yellow]")
            return None

    def _compare_with_previous_scan(self, current_scan: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Compare current scan with previous scan and return differences"""
        previous_scan = self._get_previous_scan()
        if not previous_scan:
            self.console.print("[yellow]No previous scan found for comparison[/yellow]")
            return None

        self.console.print("[dim]Analyzing changes...[/dim]")
        changes = self._find_changes(previous_scan, current_scan)
        
        comparison_result = {
            "previous_scan_id": previous_scan["scan_id"],
            "previous_timestamp": previous_scan["timestamp"],
            "current_scan_id": current_scan["scan_id"],
            "current_timestamp": current_scan["timestamp"],
            "changes_count": len(changes),
            "changes": changes
        }
        
        self._print_comparison_table(comparison_result)
        return comparison_result

    def _find_changes(self, previous: Dict[str, Any], current: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find changes between two scans"""
        changes = []
        
        # Convert findings to dictionaries for easier comparison
        prev_findings = {self._get_finding_key(f): f for f in previous["findings"]}
        curr_findings = {self._get_finding_key(f): f for f in current["findings"]}
        
        # Check for new findings
        for key in curr_findings:
            if key not in prev_findings:
                changes.append({
                    "type": "NEW",
                    "module": curr_findings[key]["module"],
                    "finding": curr_findings[key],
                    "description": f"New finding in {curr_findings[key]['module']}"
                })
        
        # Check for missing findings
        for key in prev_findings:
            if key not in curr_findings:
                changes.append({
                    "type": "REMOVED",
                    "module": prev_findings[key]["module"],
                    "finding": prev_findings[key],
                    "description": f"Finding removed from {prev_findings[key]['module']}"
                })
        
        # Check for changed findings
        for key in curr_findings:
            if key in prev_findings:
                change = self._compare_findings(prev_findings[key], curr_findings[key])
                if change:
                    changes.append(change)
        
        return changes

    def _get_finding_key(self, finding: Dict[str, Any]) -> str:
        """Create a unique key for a finding"""
        module = finding.get("module", "unknown")
        check = finding.get("check", "")
        return f"{module}:{check}"

    def _compare_findings(self, prev_finding: Dict[str, Any], curr_finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Compare two findings and return changes if any"""
        changes_found = []
        
        # Compare status
        if prev_finding.get("status") != curr_finding.get("status"):
            changes_found.append(f"Status changed from {prev_finding.get('status')} to {curr_finding.get('status')}")
        
        # Compare file hashes
        if prev_finding.get("hash") and curr_finding.get("hash"):
            if prev_finding["hash"] != curr_finding["hash"]:
                changes_found.append("File hash changed")
        
        # Compare counts
        for count_field in ["process_count", "package_count", "users_count", "groups_count", "interface_count", "cron_entries"]:
            if prev_finding.get(count_field) != curr_finding.get(count_field):
                changes_found.append(f"{count_field} changed from {prev_finding.get(count_field)} to {curr_finding.get(count_field)}")
        
        # Compare security tools
        if prev_finding.get("tools") and curr_finding.get("tools"):
            for tool in prev_finding["tools"]:
                if prev_finding["tools"].get(tool) != curr_finding["tools"].get(tool):
                    changes_found.append(f"Security tool {tool} availability changed")
        
        if changes_found:
            return {
                "type": "CHANGED",
                "module": curr_finding["module"],
                "previous": prev_finding,
                "current": curr_finding,
                "description": " | ".join(changes_found)
            }
        
        return None

    def _format_changes_summary(self, comparison_result: Dict[str, Any]) -> str:
        """Format changes for email notification"""
        if comparison_result["changes_count"] == 0:
            return "No changes detected"
        
        summary = []
        changes_by_type = {}
        
        for change in comparison_result["changes"]:
            change_type = change["type"]
            changes_by_type[change_type] = changes_by_type.get(change_type, 0) + 1
        
        for change_type, count in changes_by_type.items():
            summary.append(f"{change_type}: {count}")
        
        return f"Change Summary: {', '.join(summary)}"

    def _print_comparison_table(self, comparison_result: Dict[str, Any]):
        """Print a table showing comparison results"""
        if comparison_result["changes_count"] == 0:
            self.console.print(Panel("[green]✓ No changes detected since previous scan[/green]", 
                                   title="Baseline Comparison"))
            return
        
        table = Table(title=f"Baseline Changes ({comparison_result['changes_count']} changes)", show_lines=True)
        table.add_column("Type", style="bold")
        table.add_column("Module", style="cyan")
        table.add_column("Description", style="white")
        
        for change in comparison_result["changes"]:
            color = {
                "NEW": "green",
                "REMOVED": "red", 
                "CHANGED": "yellow"
            }.get(change["type"], "white")
            
            table.add_row(
                f"[{color}]{change['type']}[/{color}]",
                change["module"],
                change["description"]
            )
        
        self.console.print(Panel(table, title="[bold blue]Baseline Comparison Results[/bold blue]"))

    # ==============================
    # Baseline Scan Orchestrator
    # ==============================

    def _perform_baseline_scan(self):
        scan_modules = [
            self._scan_system_info,
            self._scan_network_config,
            self._scan_file_integrity,
            self._scan_users_groups,
            self._scan_processes_services,
            self._scan_packages,
            self._scan_cron_jobs,
            self._scan_security_config,
        ]

        scan_id = f"linux_baseline_{self._get_timestamp()}"
        baseline_data = {
            "scan_id": scan_id,
            "timestamp": datetime.datetime.utcfromtimestamp(time()).isoformat(),
            "findings": [],
        }

        self.console.print(Panel("[bold cyan]Performing baseline scan...[/bold cyan]"))

        # Parallel execution of modules
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {executor.submit(m): m.__name__ for m in scan_modules}

            with Progress(
                "[progress.description]{task.description}",
                BarColumn(),
                "{task.percentage:>3.0f}%",
                TimeRemainingColumn(),
                console=self.console,
            ) as progress:
                task = progress.add_task("[green]Scanning modules...", total=len(futures))

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        baseline_data["findings"].extend(result)
                    progress.advance(task)

        # Save baseline to disk
        file_path = self.output_dir / f"{scan_id}.json"
        self._save_json(file_path, baseline_data)

        # Print summary
        self._print_findings_table(baseline_data["findings"])

        return baseline_data

    # ==============================
    # Individual Scan Modules (Cached & Optimized)
    # ==============================

    @lru_cache(maxsize=1)
    def _cached_system_info(self):
        return {
            "hostname": platform.node(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "boot_time": self._cached_boot_time(),
            "load_average": self._cached_load_avg(),
            "distro": self._cached_linux_distro(),
        }

    def _scan_system_info(self):
        info = self._cached_system_info()
        uptime = datetime.datetime.now() - datetime.datetime.fromtimestamp(info["boot_time"])

        return [{
            "module": "system_info",
            "hostname": info["hostname"],
            "kernel": info["kernel"],
            "arch": info["architecture"],
            "uptime": str(uptime),
            "load_avg": info["load_average"],
            "distro": info["distro"],
            "status": "PASS",
        }]

    def _scan_network_config(self):
        try:
            interfaces = self._cached_net_if_addrs()
            return [{
                "module": "network_config", 
                "interface_count": len(interfaces),
                "status": "PASS"
            }]
        except Exception as e:
            return [{"module": "network_config", "status": "CRITICAL", "error": str(e)}]

    def _scan_file_integrity(self):
        important_paths = [
            "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/etc/hosts", "/etc/hostname",
            "/bin/bash", "/bin/sh", "/usr/bin/sudo"
        ]
        results = []

        for path in important_paths:
            if not self._cached_path_exists(path):
                results.append({
                    "module": "file_integrity", 
                    "check": path, 
                    "status": "CRITICAL", 
                    "message": "Missing file"
                })
                continue
            try:
                file_hash = self._cached_file_hash(path)
                results.append({
                    "module": "file_integrity", 
                    "check": path, 
                    "hash": file_hash, 
                    "status": "PASS"
                })
            except PermissionError:
                results.append({
                    "module": "file_integrity", 
                    "check": path, 
                    "status": "WARNING", 
                    "message": "Permission denied"
                })
            except Exception as e:
                results.append({
                    "module": "file_integrity", 
                    "check": path, 
                    "status": "WARNING", 
                    "message": str(e)
                })

        return results

    def _scan_users_groups(self):
        try:
            users = self._cached_getpwall()
            groups = self._cached_getgrall()
            return [{
                "module": "users_groups", 
                "users_count": len(users), 
                "groups_count": len(groups), 
                "status": "PASS"
            }]
        except Exception as e:
            return [{"module": "users_groups", "status": "CRITICAL", "error": str(e)}]

    def _scan_processes_services(self):
        processes = self._cached_process_iter()
        return [{
            "module": "processes_services",
            "process_count": len(processes),
            "status": "PASS",
        }]

    def _scan_packages(self):
        try:
            for cmd in ["dpkg -l | wc -l", "rpm -qa | wc -l"]:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    return [{
                        "module": "packages",
                        "package_count": int(result.stdout.strip()),
                        "status": "PASS"
                    }]
            return [{"module": "packages", "status": "WARNING", "message": "No package manager detected"}]
        except Exception as e:
            return [{"module": "packages", "status": "WARNING", "message": str(e)}]

    def _scan_cron_jobs(self):
        try:
            cron_count = 0
            if self._cached_path_exists("/etc/crontab"):
                with open("/etc/crontab", 'r') as f:
                    cron_count = len([l for l in f if l.strip() and not l.startswith('#')])
            return [{
                "module": "cron_jobs",
                "cron_entries": cron_count,
                "status": "PASS"
            }]
        except Exception as e:
            return [{"module": "cron_jobs", "status": "WARNING", "message": str(e)}]

    def _scan_security_config(self):
        try:
            security_tools = {}
            for tool in ["apparmor", "selinux", "ufw"]:
                result = subprocess.run(f"which {tool}", shell=True, capture_output=True)
                security_tools[tool] = result.returncode == 0
            return [{
                "module": "security_config",
                "tools": security_tools,
                "status": "PASS"
            }]
        except Exception as e:
            return [{"module": "security_config", "status": "WARNING", "message": str(e)}]

    # ==============================
    # Cached System Calls
    # ==============================

    @lru_cache(maxsize=1)
    def _cached_boot_time(self):
        import psutil
        return psutil.boot_time()

    @lru_cache(maxsize=1)
    def _cached_load_avg(self):
        return os.getloadavg()

    @lru_cache(maxsize=1)
    def _cached_linux_distro(self):
        try:
            with open('/etc/os-release', 'r') as f:
                distro_info = {}
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        distro_info[key] = value.strip('"')
                return distro_info.get('PRETTY_NAME', 'Unknown')
        except:
            return "Unknown"

    @lru_cache(maxsize=1)
    def _cached_net_if_addrs(self):
        import psutil
        return psutil.net_if_addrs()

    @lru_cache(maxsize=1)
    def _cached_process_iter(self):
        import psutil
        return list(psutil.process_iter(['pid', 'name', 'username']))

    @lru_cache(maxsize=32)
    def _cached_path_exists(self, path):
        return os.path.exists(path)

    @lru_cache(maxsize=32)
    def _cached_file_hash(self, filepath):
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    @lru_cache(maxsize=1)
    def _cached_getpwall(self):
        import pwd
        return pwd.getpwall()

    @lru_cache(maxsize=1)
    def _cached_getgrall(self):
        import grp
        return grp.getgrall()

    # ==============================
    # Utility Functions
    # ==============================

    def _get_timestamp(self):
        return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    def _save_json(self, path, data):
        try:
            import orjson
            with open(path, "wb") as f:
                f.write(orjson.dumps(data, option=orjson.OPT_INDENT_2))
        except ImportError:
            import json
            with open(path, "w") as f:
                json.dump(data, f, indent=2)

    def _load_json(self, path: Path) -> Dict[str, Any]:
        """Load JSON data from file"""
        try:
            import orjson
            with open(path, "rb") as f:
                return orjson.loads(f.read())
        except ImportError:
            import json
            with open(path, "r") as f:
                return json.load(f)

    def _print_findings_table(self, findings):
        table = Table(title="Baseline Scan Results", show_lines=True)
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Status", style="bold")
        table.add_column("Details", style="white")

        for f in findings:
            status = f.get("status", "UNKNOWN")
            color = {"PASS": "green", "WARNING": "yellow", "CRITICAL": "red"}.get(status, "white")
            
            # Create meaningful summary
            details_parts = []
            if f.get("message"):
                details_parts.append(f["message"])
            if f.get("check"):
                details_parts.append(f"check: {f['check']}")
            if f.get("process_count") is not None:
                details_parts.append(f"{f['process_count']} processes")
            if f.get("package_count") is not None:
                details_parts.append(f"{f['package_count']} packages")
            if f.get("users_count") is not None:
                details_parts.append(f"{f['users_count']} users")
            if f.get("interface_count") is not None:
                details_parts.append(f"{f['interface_count']} interfaces")
                
            summary = " | ".join(details_parts) if details_parts else "Completed"
            
            table.add_row(f["module"], f"[{color}]{status}[/{color}]", summary)

        self.console.print(Panel(table, title="[bold blue]Scan Summary[/bold blue]"))
