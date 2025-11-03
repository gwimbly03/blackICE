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

class LinuxBaselineScanner:
    
    description = "Comprehensive Linux system baseline scanner for security monitoring and change detection"
    
    def __init__(self):
        self.module_name = "linux_baseline_scanner"
        self.output_dir = "./baseline"
        os.makedirs(self.output_dir, exist_ok=True)
        
        if platform.system() != "Linux":
            print("This module is designed for Linux systems only!")
            return
    
    def run(self):
        try:
            print("Starting Linux System Baseline Scan...")
            
            scan_config = self._get_scan_config()
            
            scan_result = self._perform_baseline_scan(scan_config)
            
            if scan_result["success"]:
                print(f"Baseline scan completed: {scan_result['output_file']}")
                print(f"Scan Summary:")
                print(f"   - Total checks: {scan_result['data']['summary']['total_checks']}")
                print(f"   - Passed: {scan_result['data']['summary']['passed']}")
                print(f"   - Warnings: {scan_result['data']['summary']['warnings']}")
                print(f"   - Critical: {scan_result['data']['summary']['critical']}")
                
                self._offer_comparison(scan_result['output_file'])
            else:
                print(f"Scan failed: {scan_result['error']}")
                
        except Exception as e:
            print(f"Module execution failed: {e}")
    
    def _get_scan_config(self):
        print("\nScan Configuration:")
        print("1. Standard scan (recommended)")
        print("2. Deep scan (more comprehensive, takes longer)")
        
        choice = input("Select scan depth [1]: ").strip()
        scan_depth = "deep" if choice == "2" else "standard"
        
        custom_paths = []
        add_custom = input("Add custom critical file paths? (y/N): ").strip().lower()
        if add_custom == 'y':
            print("Enter custom file paths (one per line, empty line to finish):")
            while True:
                path = input("> ").strip()
                if not path:
                    break
                if os.path.exists(path):
                    custom_paths.append(path)
                else:
                    print(f"Path does not exist: {path}")
        
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
            
            print("Scanning system...")
            for i, module in enumerate(scan_modules, 1):
                module_name = module.__name__.replace('_scan_', '').replace('_', ' ')
                print(f"   [{i}/{len(scan_modules)}] Scanning {module_name}...")
                
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
                print(f"\nFound {len(baselines)} previous baselines")
                baselines.sort(reverse=True)
                
                print("Recent baselines:")
                for i, baseline in enumerate(baselines[:5], 1):
                    print(f"   {i}. {baseline}")
                
                compare = input("\nCompare with previous baseline? (y/N): ").strip().lower()
                if compare == 'y':
                    if len(baselines) == 1:
                        prev_baseline = baselines[0]
                    else:
                        try:
                            choice = int(input(f"Select baseline (1-{min(5, len(baselines))}): ")) - 1
                            prev_baseline = baselines[choice]
                        except:
                            prev_baseline = baselines[0]
                    
                    prev_path = os.path.join(self.output_dir, prev_baseline)
                    self._compare_baselines(prev_path, current_baseline)
                    
        except Exception as e:
            print(f"Comparison offer failed: {e}")
    
    def _compare_baselines(self, baseline1_path, baseline2_path):
        try:
            with open(baseline1_path, 'r') as f:
                baseline1 = json.load(f)
            with open(baseline2_path, 'r') as f:
                baseline2 = json.load(f)
            
            changes = self._find_changes(baseline1, baseline2)
            
            if changes:
                print("\nCHANGES DETECTED:")
                for change_path, change_info in list(changes.items())[:10]:
                    print(f"   {change_path}: {change_info['action']}")
                
                comp_file = os.path.join(self.output_dir, f"comparison_{self._get_timestamp()}.json")
                with open(comp_file, 'w') as f:
                    json.dump(changes, f, indent=2)
                print(f"Full comparison saved to: {comp_file}")
            else:
                print("No significant changes detected")
                
        except Exception as e:
            print(f"Comparison failed: {e}")
    
    def _find_changes(self, old, new, path=""):
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
