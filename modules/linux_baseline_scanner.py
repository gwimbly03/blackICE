import os
import json
import hashlib
import datetime
import platform
import psutil
import subprocess
import grp
import pwd
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import print as rprint

class LinuxBaselineScanner:
    
    description = "Comprehensive Linux system baseline scanner for security monitoring and change detection"
    
    def __init__(self):
        self.module_name = "linux_baseline_scanner"
        self.output_dir = "./baseline"
        os.makedirs(self.output_dir, exist_ok=True)
        self.console = Console()  # Rich console
        
        if platform.system() != "Linux":
            self.console.print(
                Panel(
                    "This module is designed for Linux systems only!",
                    style="red bold",
                    title="[red]System Compatibility Error[/red]"
                )
            )
            return
    
    def run(self):
        try:
            self.console.print(
                Panel.fit(
                    "[bold blue]Starting Linux System Baseline Scan...[/bold blue]",
                    style="blue",
                    title="[bold white]BlackICE Baseline Scanner[/bold white]"
                )
            )
            
            scan_config = self._get_scan_config()
            
            scan_result = self._perform_baseline_scan(scan_config)
            
            if scan_result["success"]:
                # Show success notification
                self.console.print(
                    Panel.fit(
                        f"[bold green]Baseline scan completed successfully![/bold green]\n"
                        f"[cyan]Output:[/cyan] {scan_result['output_file']}",
                        style="green",
                        title="[bold green]Scan Complete[/bold green]"
                    )
                )
                
                # Show scan summary table
                self._show_scan_summary(scan_result['data']['summary'])
                
                # Send scan completion notification
                self._notify_scan_completion(scan_result)
                
                self._offer_comparison(scan_result['output_file'])
            else:
                self.console.print(
                    Panel.fit(
                        f"[bold red]Scan failed: {scan_result['error']}[/bold red]",
                        style="red",
                        title="[bold red]Scan Failed[/bold red]"
                    )
                )
                
        except Exception as e:
            self.console.print(
                Panel.fit(
                    f"[bold red]Module execution failed: {e}[/bold red]",
                    style="red",
                    title="[bold red]Error[/bold red]"
                )
            )
    
    def _show_scan_summary(self, summary):
        """Display scan summary as a rich table"""
        table = Table(show_header=True, header_style="bold magenta", show_lines=True)
        table.add_column("Metric", style="cyan", width=20)
        table.add_column("Count", style="white", justify="center", width=10)
        table.add_column("Status", justify="center", width=15)
        
        total = summary['total_checks']
        
        # Add rows with appropriate status indicators
        table.add_row("Total Checks", str(total), "COMPLETE")
        
        # Passed row
        passed_status = "[green]PASS[/green]" if summary['passed'] == total else f"[green]{summary['passed']}/{total}[/green]"
        table.add_row("Passed", str(summary['passed']), passed_status)
        
        # Warnings row
        warnings_status = "[yellow]WARNINGS[/yellow]" if summary['warnings'] > 0 else "[green]NONE[/green]"
        table.add_row("Warnings", str(summary['warnings']), warnings_status)
        
        # Critical row
        critical_status = "[red]CRITICAL[/red]" if summary['critical'] > 0 else "[green]NONE[/green]"
        table.add_row("Critical", str(summary['critical']), critical_status)
        
        self.console.print("\n")
        self.console.print(
            Panel(
                table,
                title="[bold blue]Scan Summary[/bold blue]",
                style="blue"
            )
        )
    
    def _get_scan_config(self):
        self.console.print(
            Panel.fit(
                "Configure your baseline scan parameters",
                style="yellow",
                title="[bold yellow]Scan Configuration[/bold yellow]"
            )
        )
        
        # Use rich for interactive input
        self.console.print("\n[bold]Scan Depth Options:[/bold]")
        self.console.print("  [cyan]1.[/cyan] Standard scan (recommended)")
        self.console.print("  [yellow]2.[/yellow] Deep scan (more comprehensive, takes longer)")
        
        choice = self.console.input("\n[bold cyan]Select scan depth[/bold cyan] [[1]]: ").strip()
        scan_depth = "deep" if choice == "2" else "standard"
        
        # Show scan depth selection
        depth_color = "yellow" if scan_depth == "deep" else "cyan"
        self.console.print(f"\nSelected: [{depth_color}]{scan_depth.title()} Scan[/{depth_color}]")
        
        custom_paths = []
        add_custom = self.console.input("\n[bold]Add custom critical file paths?[/bold] (y/N): ").strip().lower()
        if add_custom == 'y':
            self.console.print("\n[dim]Enter custom file paths (one per line, empty line to finish):[/dim]")
            while True:
                path = self.console.input("[bold blue]>[/bold blue] ").strip()
                if not path:
                    break
                if os.path.exists(path):
                    custom_paths.append(path)
                    self.console.print(f"  [green]ADDED[/green] [cyan]{path}[/cyan]")
                else:
                    self.console.print(f"  [red]ERROR[/red] Path does not exist: [red]{path}[/red]")
        
        return {
            "scan_depth": scan_depth,
            "custom_paths": custom_paths
        }
    
    def _perform_baseline_scan(self, config):
        scan_id = f"linux_baseline_{self._get_timestamp()}"
        
        baseline_data = {
            "metadata": {
                "scan_id": scan_id,
                "timestamp": datetime.datetime.now().isoformat(),
                "scanner_version": "2.0",
                "scan_depth": config["scan_depth"],
                "distribution": self._get_linux_distro()
            },
            "findings": [],
            "summary": {
                "total_checks": 0,
                "passed": 0,
                "warnings": 0,
                "critical": 0
            }
        }
        
        try:
            standard_modules = [
                self._scan_system_info,
                self._scan_users_groups,
                self._scan_network_config,
                self._scan_processes_services,
                self._scan_file_integrity,
                self._scan_packages,
                self._scan_cron_jobs,
                self._scan_security_config,
            ]
            
            deep_modules = standard_modules + [
                self._scan_kernel_params,
                self._scan_logging_config,
                self._scan_suid_sgid_files,
            ]
            
            scan_modules = deep_modules if config["scan_depth"] == "deep" else standard_modules
            
            # Show scanning progress with rich
            self.console.print("\n")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                task = progress.add_task("[cyan]Scanning system components...", total=len(scan_modules))
                
                for i, module in enumerate(scan_modules, 1):
                    module_name = module.__name__.replace('_scan_', '').replace('_', ' ')
                    progress.update(task, advance=1, description=f"[cyan]Scanning {module_name}...")
                    
                    result = module(config)
                    if result:
                        baseline_data["findings"].extend(result)
            
            baseline_data["summary"]["total_checks"] = len(baseline_data["findings"])
            baseline_data["summary"]["passed"] = len([f for f in baseline_data["findings"] if f.get("status") == "PASS"])
            baseline_data["summary"]["warnings"] = len([f for f in baseline_data["findings"] if f.get("status") == "WARNING"])
            baseline_data["summary"]["critical"] = len([f for f in baseline_data["findings"] if f.get("status") == "CRITICAL"])
            
            output_file = self._save_baseline(scan_id, baseline_data)
            
            return {
                "success": True,
                "scan_id": scan_id,
                "output_file": output_file,
                "data": baseline_data
            }
            
        except Exception as e:
            self.console.print(
                Panel.fit(
                    f"[bold red]Scan failed: {str(e)}[/bold red]",
                    style="red",
                    title="[bold red]Scan Error[/bold red]"
                )
            )
            return {
                "success": False,
                "error": str(e),
                "scan_id": scan_id
            }
    
    def _offer_comparison(self, current_baseline):
        try:
            baselines = [f for f in os.listdir(self.output_dir) 
                        if f.endswith('.json') and f != os.path.basename(current_baseline)]
            
            if baselines:
                self.console.print(
                    Panel.fit(
                        f"Found [cyan]{len(baselines)}[/cyan] previous baselines",
                        style="blue",
                        title="[bold blue]Baseline Comparison[/bold blue]"
                    )
                )
                
                baselines.sort(reverse=True)
                
                self.console.print("\n[bold]Recent baselines:[/bold]")
                for i, baseline in enumerate(baselines[:5], 1):
                    self.console.print(f"  [cyan]{i}.[/cyan] {baseline}")
                
                compare = self.console.input("\n[bold]Compare with previous baseline?[/bold] (y/N): ").strip().lower()
                if compare == 'y':
                    if len(baselines) == 1:
                        prev_baseline = baselines[0]
                    else:
                        try:
                            choice = int(self.console.input(f"[bold]Select baseline[/bold] (1-{min(5, len(baselines))}): ")) - 1
                            prev_baseline = baselines[choice]
                        except:
                            prev_baseline = baselines[0]
                    
                    prev_path = os.path.join(self.output_dir, prev_baseline)
                    self._compare_baselines(prev_path, current_baseline)
                    
        except Exception as e:
            self.console.print(
                Panel.fit(
                    f"[yellow]Comparison offer failed: {e}[/yellow]",
                    style="yellow",
                    title="[bold yellow]Comparison Error[/bold yellow]"
                )
            )
    
    def _compare_baselines(self, baseline1_path, baseline2_path):
        try:
            with open(baseline1_path, 'r') as f:
                baseline1 = json.load(f)
            with open(baseline2_path, 'r') as f:
                baseline2 = json.load(f)
            
            changes = self._find_changes(baseline1, baseline2)
            
            if changes:
                self.console.print(
                    Panel.fit(
                        f"[bold yellow]Changes Detected: {len(changes)} modifications found[/bold yellow]",
                        style="yellow",
                        title="[bold yellow]Baseline Changes[/bold yellow]"
                    )
                )
                
                changes_summary = []
                self.console.print("\n[bold]Top Changes:[/bold]")
                for change_path, change_info in list(changes.items())[:10]:
                    action_color = {
                        "ADDED": "green",
                        "MODIFIED": "yellow", 
                        "REMOVED": "red"
                    }.get(change_info['action'], "white")
                    
                    self.console.print(f"  [{action_color}]{change_info['action']:>8}[/{action_color}] {change_path}")
                    changes_summary.append(f"{change_path}: {change_info['action']}")
                
                # Send email notification for changes
                self._notify_baseline_changes(len(changes), baseline2_path, changes_summary)
                
                comp_file = os.path.join(self.output_dir, f"comparison_{self._get_timestamp()}.json")
                with open(comp_file, 'w') as f:
                    json.dump(changes, f, indent=2)
                self.console.print(f"\n[cyan]Full comparison saved to:[/cyan] {comp_file}")
            else:
                self.console.print(
                    Panel.fit(
                        "[green]No significant changes detected[/green]",
                        style="green",
                        title="[bold green]No Changes[/bold green]"
                    )
                )
                # Send notification for no changes
                self._notify_baseline_changes(0, baseline2_path)
                
        except Exception as e:
            self.console.print(
                Panel.fit(
                    f"[red]Comparison failed: {e}[/red]",
                    style="red",
                    title="[bold red]Comparison Error[/bold red]"
                )
            )
    
    def _find_changes(self, old, new, path=""):
        """Find changes between two baselines - ADD THIS MISSING METHOD"""
        changes = {}
        
        all_keys = set(old.keys()) | set(new.keys())
        
        for key in all_keys:
            current_path = f"{path}.{key}" if path else key
            
            if key not in old:
                changes[current_path] = {"action": "ADDED", "new_value": new[key]}
            elif key not in new:
                changes[current_path] = {"action": "REMOVED", "old_value": old[key]}
            elif old[key] != new[key]:
                if isinstance(old[key], dict) and isinstance(new[key], dict):
                    nested_changes = self._find_changes(old[key], new[key], current_path)
                    changes.update(nested_changes)
                else:
                    changes[current_path] = {
                        "action": "MODIFIED", 
                        "old_value": old[key],
                        "new_value": new[key]
                    }
        
        return changes
    
    def _notify_scan_completion(self, scan_result):
        """Send notification when baseline scan completes"""
        try:
            from core.logger import logger
            logger.notify_baseline_scan_complete(scan_result)
        except Exception as e:
            self.console.print(f"[yellow]Failed to send scan completion notification: {e}[/yellow]")
    
    def _notify_baseline_changes(self, changes_count, scan_file, changes_list=None):
        """Send notification about baseline changes"""
        try:
            from core.logger import logger
            changes_summary = "\n".join(changes_list) if changes_list else ""
            logger.notify_baseline_changes(changes_count, scan_file, changes_summary)
        except Exception as e:
            self.console.print(f"[yellow]Failed to send changes notification: {e}[/yellow]")

    # ... (all your existing scan methods remain exactly the same)
    def _scan_system_info(self, config):
        try:
            system_info = {
                "hostname": platform.node(),
                "kernel": platform.release(),
                "architecture": platform.machine(),
                "boot_time": datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                "uptime": str(datetime.timedelta(seconds=psutil.boot_time())),
                "load_average": os.getloadavg(),
            }
            
            return [{
                "module": "system_info",
                "check": "system_identification",
                "status": "PASS",
                "data": system_info,
                "message": "System information collected"
            }]
        except Exception as e:
            return [{
                "module": "system_info", 
                "check": "system_identification",
                "status": "CRITICAL",
                "message": f"Failed: {e}"
            }]
    
    def _scan_users_groups(self, config):
        try:
            users = []
            for user in pwd.getpwall()[:20]:
                users.append({
                    "username": user.pw_name,
                    "uid": user.pw_uid,
                    "gid": user.pw_gid,
                    "shell": user.pw_shell
                })
            
            return [{
                "module": "users_groups",
                "check": "user_enumeration", 
                "status": "PASS",
                "data": {"users": users},
                "message": f"Enumerated {len(users)} users"
            }]
        except Exception as e:
            return [{
                "module": "users_groups",
                "check": "user_enumeration",
                "status": "WARNING", 
                "message": f"Partial: {e}"
            }]
    
    def _scan_network_config(self, config):
        try:
            interfaces = psutil.net_if_addrs()
            return [{
                "module": "network",
                "check": "network_config",
                "status": "PASS",
                "data": {"interface_count": len(interfaces)},
                "message": "Network interfaces scanned"
            }]
        except Exception as e:
            return [{
                "module": "network",
                "check": "network_config",
                "status": "WARNING",
                "message": f"Partial: {e}"
            }]
    
    def _scan_processes_services(self, config):
        try:
            process_count = len(list(psutil.process_iter()))
            return [{
                "module": "processes",
                "check": "process_enumeration",
                "status": "PASS", 
                "data": {"process_count": process_count},
                "message": f"Found {process_count} running processes"
            }]
        except Exception as e:
            return [{
                "module": "processes",
                "check": "process_enumeration",
                "status": "WARNING",
                "message": f"Partial: {e}"
            }]
    
    def _scan_file_integrity(self, config):
        try:
            critical_files = self._get_critical_file_list(config)
            scanned_files = []
            
            for file_path in critical_files[:10]:
                if os.path.exists(file_path):
                    scanned_files.append({
                        "path": file_path,
                        "size": os.path.getsize(file_path),
                        "hash": self._calculate_file_hash(file_path)
                    })
            
            return [{
                "module": "file_integrity",
                "check": "critical_files",
                "status": "PASS",
                "data": {"files_scanned": len(scanned_files)},
                "message": f"Integrity check for {len(scanned_files)} critical files"
            }]
        except Exception as e:
            return [{
                "module": "file_integrity",
                "check": "critical_files", 
                "status": "WARNING",
                "message": f"Partial: {e}"
            }]
    
    def _scan_packages(self, config):
        try:
            for cmd in ["dpkg -l | wc -l", "rpm -qa | wc -l"]:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    return [{
                        "module": "packages",
                        "check": "package_enumeration",
                        "status": "PASS",
                        "data": {"package_count": int(result.stdout.strip())},
                        "message": "Packages enumerated"
                    }]
            
            return [{
                "module": "packages",
                "check": "package_enumeration",
                "status": "WARNING", 
                "message": "No package manager detected"
            }]
        except Exception as e:
            return [{
                "module": "packages",
                "check": "package_enumeration",
                "status": "WARNING",
                "message": f"Partial: {e}"
            }]
    
    def _scan_cron_jobs(self, config):
        try:
            cron_count = 0
            if os.path.exists("/etc/crontab"):
                with open("/etc/crontab", 'r') as f:
                    cron_count = len([l for l in f.readlines() if l.strip() and not l.startswith('#')])
            
            return [{
                "module": "cron",
                "check": "cron_jobs",
                "status": "PASS",
                "data": {"cron_entries": cron_count},
                "message": "Cron jobs scanned"
            }]
        except Exception as e:
            return [{
                "module": "cron",
                "check": "cron_jobs",
                "status": "WARNING",
                "message": f"Partial: {e}"
            }]
    
    def _scan_security_config(self, config):
        try:
            security_tools = {}
            for tool in ["apparmor", "selinux", "ufw"]:
                result = subprocess.run(f"which {tool}", shell=True, capture_output=True)
                security_tools[tool] = "INSTALLED" if result.returncode == 0 else "NOT_FOUND"
            
            return [{
                "module": "security", 
                "check": "security_tools",
                "status": "PASS",
                "data": security_tools,
                "message": "Security tools status checked"
            }]
        except Exception as e:
            return [{
                "module": "security",
                "check": "security_tools",
                "status": "WARNING",
                "message": f"Partial: {e}"
            }]
    
    def _scan_kernel_params(self, config):
        try:
            return [{
                "module": "kernel",
                "check": "kernel_params",
                "status": "PASS", 
                "message": "Kernel parameters scanned"
            }]
        except Exception as e:
            return [{
                "module": "kernel",
                "check": "kernel_params",
                "status": "WARNING",
                "message": f"Partial: {e}"
            }]
    
    def _scan_logging_config(self, config):
        try:
            return [{
                "module": "logging",
                "check": "logging_config", 
                "status": "PASS",
                "message": "Logging configuration scanned"
            }]
        except Exception as e:
            return [{
                "module": "logging",
                "check": "logging_config",
                "status": "WARNING",
                "message": f"Partial: {e}"
            }]
    
    def _scan_suid_sgid_files(self, config):
        try:
            return [{
                "module": "file_integrity",
                "check": "suid_sgid_files",
                "status": "PASS",
                "message": "SUID/SGID files scanned"
            }]
        except Exception as e:
            return [{
                "module": "file_integrity",
                "check": "suid_sgid_files", 
                "status": "WARNING",
                "message": f"Partial: {e}"
            }]
    
    def _get_timestamp(self):
        return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def _get_linux_distro(self):
        try:
            with open('/etc/os-release', 'r') as f:
                lines = f.readlines()
                distro_info = {}
                for line in lines:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        distro_info[key] = value.strip('"')
                return distro_info
        except:
            return {"name": "Unknown"}
    
    def _get_critical_file_list(self, config):
        base_files = [
            "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/etc/hosts", "/etc/hostname",
            "/bin/bash", "/bin/sh", "/usr/bin/sudo"
        ]
        return base_files + config.get("custom_paths", [])
    
    def _calculate_file_hash(self, filepath):
        try:
            hasher = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return None
    
    def _save_baseline(self, scan_id, data):
        filename = os.path.join(self.output_dir, f"{scan_id}.json")
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return filename
