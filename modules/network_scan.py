from __future__ import annotations
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional, Dict, Any, List

try:
    from core.target import atk  
except Exception:
    atk = None  

logger = logging.getLogger("gateway_scanner")
if not logger.handlers:
    h = logging.StreamHandler()
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s")
    h.setFormatter(fmt)
    logger.addHandler(h)
logger.setLevel(logging.INFO)


class GatewayScanner:
    def __init__(self, gateway_ip: str, max_workers: int = 50):
        # Validate ip early
        try:
            ipaddress.ip_address(gateway_ip)
        except Exception as e:
            raise ValueError(f"Invalid gateway IP: {gateway_ip}") from e

        self.gateway_ip = gateway_ip
        self.network_range: Optional[str] = None
        self.hosts: List[Dict[str, str]] = []
        self.scanning = threading.Event()
        self.found_hosts = 0
        self.max_workers = max_workers

    def calculate_network_range(self) -> str:
        """Calculate network range from gateway IP - simpler approach."""
        if self.network_range:
            return self.network_range

        gateway_octets = self.gateway_ip.split('.')
        
        # Handle common private IP ranges
        if gateway_octets[0] == '10':
            self.network_range = f"{gateway_octets[0]}.{gateway_octets[1]}.{gateway_octets[2]}.0/24"
        elif gateway_octets[0] == '172' and 16 <= int(gateway_octets[1]) <= 31:
            self.network_range = f"{gateway_octets[0]}.{gateway_octets[1]}.{gateway_octets[2]}.0/24"
        elif gateway_octets[0] == '192' and gateway_octets[1] == '168':
            self.network_range = f"{gateway_octets[0]}.{gateway_octets[1]}.{gateway_octets[2]}.0/24"
        else:
            self.network_range = f"{gateway_octets[0]}.{gateway_octets[1]}.{gateway_octets[2]}.0/24"
        
        logger.info("Using network range: %s", self.network_range)
        return self.network_range

    def _ping_host(self, ip: str) -> Optional[Dict[str, str]]:
        """Ping one host; if alive, get MAC address."""
        try:
            result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True)
            if result.returncode != 0:
                return None

            mac = self._get_mac_address(ip)
            return {"ip": ip, "mac": mac}
        except Exception:
            return None
    
    def ping_sweep(self) -> None:
        """Perform ICMP ping sweep using a ThreadPoolExecutor."""
        if not self.network_range:
            self.calculate_network_range()

        network = ipaddress.ip_network(self.network_range, strict=False)
        gateway_ip_obj = ipaddress.ip_address(self.gateway_ip)
        if gateway_ip_obj not in network:
            logger.warning("Gateway IP %s is not in detected network %s!", self.gateway_ip, self.network_range)

        hosts = list(network.hosts())
        total_hosts = len(hosts)
        
        if total_hosts > 1000:
            logger.warning("Large network detected (%d hosts). This may take a while...", total_hosts)
            if total_hosts > 10000:
                response = input(f"Scan {total_hosts} hosts? This could take a long time. Continue? (y/N): ")
                if response.lower() not in ('y', 'yes'):
                    logger.info("Scan cancelled by user")
                    return

        logger.info("Scanning network: %s (%d hosts)", self.network_range, total_hosts)
        logger.info("Scanning for IP and MAC address...")

        self.scanning.set()
        self.found_hosts = 0 
        self.hosts = [] 

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(self._ping_host, str(host_ip)): host_ip for host_ip in hosts}
            checked = 0
            
            for future in as_completed(futures):
                checked += 1
                
                if not self.scanning.is_set():
                    logger.info("Scan stopped by user after %d hosts", checked)
                    break
                    
                try:
                    result = future.result()
                    if result:
                        self.hosts.append(result)
                        self.found_hosts += 1
                        logger.info("Found: %s - %s", result["ip"], result["mac"])
                except Exception as e:
                    logger.debug("Error scanning host: %s", e)
                
                if checked % 50 == 0 or checked == total_hosts:
                    percent_complete = (checked / total_hosts) * 100
                    logger.info("Progress: %d/%d hosts checked (%.1f%%) - Found: %d", 
                               checked, total_hosts, percent_complete, self.found_hosts)
        
        # Final summary
        logger.info("Scan completed. Found %d active hosts out of %d total hosts.", 
                    self.found_hosts, total_hosts)
        
        if not self.scanning.is_set():
            logger.info("Scan was stopped before completion.")

    def _get_mac_address(self, ip: str) -> str:
        mac = "Unknown"
    
        # Check ARP cache
        try:
            result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if ip in line:
                        mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
                        if mac_match:
                            mac = mac_match.group(0).upper()
                            return mac
        except Exception:
            pass
        
        # Use arping 
        try:
            result = subprocess.run(["arping", "-c", "1", "-w", "1", ip], 
                                  capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', result.stdout)
                if mac_match:
                    mac = mac_match.group(0).upper()
                    return mac
        except Exception:
            pass
        
        # Read from /proc/net/arp
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f.readlines()[1:]:  
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00":
                            return mac.upper()
        except Exception:
            pass
        
        return mac

    def stop_scan(self) -> None:
        self.scanning.clear()
        logger.info("Scan stopped by user")

    def display_results(self) -> None:
        if not self.hosts:
            logger.info("No hosts found on the network.")
            return

        # Sort hosts by IP
        self.hosts.sort(key=lambda x: [int(p) for p in x["ip"].split(".")])
        
        print("\n" + "=" * 50)
        print("NETWORK HOST DISCOVERY RESULTS")
        print("=" * 50)
        print(f"{'IP Address':<15} {'MAC Address':<17}")
        print("-" * 50)
        
        for host in self.hosts:
            ip = host['ip']
            mac = host['mac']
            print(f"{ip:<15} {mac:<17}")
        
        print("-" * 50)
        print(f"Total hosts found: {len(self.hosts)}")
        print("=" * 50)

    def export_to_json(self, filename: Optional[str] = None) -> str:
        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_hosts_{ts}.json"
        data = {
            "scan_time": datetime.now().isoformat(),
            "gateway_ip": self.gateway_ip,
            "network_range": self.network_range,
            "hosts_found": self.found_hosts,
            "hosts": self.hosts,
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        logger.info("Results exported to: %s", filename)
        return filename


# -------------------
# Helper to obtain gateway IP from atk
# -------------------
def get_gateway_ip_from_atk() -> str:
    if atk is None:
        raise RuntimeError("core.target.atk is not importable (atk is None)")

    tried = []
    # Direct attributes
    for attr in ("gateway_ip", "gateway", "ip", "target_ip", "address"):
        tried.append(f"attr: {attr}")
        val = getattr(atk, attr, None)
        if val:
            return str(val)

    # Common methods
    for meth in ("get_gateway_ip", "get_ip", "get_target_ip", "get_target", "get"):
        tried.append(f"call: {meth}()")
        fn = getattr(atk, meth, None)
        if callable(fn):
            try:
                val = fn()
                if val:
                    return str(val)
            except Exception:
                # continue trying
                pass

    # If atk is a string
    try:
        if isinstance(atk, str):
            tried.append("atk is str")
            return atk
    except Exception:
        pass

    # If atk has attribute 'target' that's dict-like
    t = getattr(atk, "target", None)
    if t:
        tried.append("atk.target")
        if isinstance(t, dict):
            for k in ("gateway", "gateway_ip", "ip", "address"):
                if k in t and t[k]:
                    return str(t[k])
        else:
            # try some attributes on atk.target
            for attr in ("gateway_ip", "gateway", "ip"):
                tried.append(f"atk.target.attr: {attr}")
                val = getattr(t, attr, None)
                if val:
                    return str(val)

    # Give the user a clear error describing what we attempted
    tried_str = ", ".join(tried)
    raise RuntimeError(f"Could not determine gateway IP from core.target.atk. Tried: {tried_str}")


# -------------------
# Module entrypoint
# -------------------
def run(export_results: bool = True) -> Dict[str, Any]:
    """
    Run the gateway scanner as a module.

    Returns a dict with keys:
      - success: bool
      - gateway_ip: str
      - network_range: str
      - hosts: list
      - exported_file: str or None
      - error: str or None
    """
    result: Dict[str, Any] = {
        "success": False,
        "gateway_ip": None,
        "network_range": None,
        "hosts": [],
        "exported_file": None,
        "error": None,
    }

    try:
        gateway_ip = get_gateway_ip_from_atk()
        logger.info("Using gateway IP from atk: %s", gateway_ip)
        result["gateway_ip"] = gateway_ip

        scanner = GatewayScanner(gateway_ip)
        network_range = scanner.calculate_network_range()
        result["network_range"] = network_range

        start = datetime.now()
        logger.info("Starting host discovery...")
        scanner.ping_sweep()
        duration = datetime.now() - start
        logger.info("Scan completed in %s", duration)

        scanner.display_results()

        result["hosts"] = scanner.hosts
        result["success"] = True

        if export_results and scanner.hosts:
            exported = scanner.export_to_json()
            result["exported_file"] = exported

        return result

    except Exception as e:
        logger.exception("Error running gateway scanner")
        result["error"] = str(e)
        return result


# If the module is run directly (for testing), try extracting gateway ip from atk then run.
if __name__ == "__main__":
    try:
        res = run(export_results=True)
        if res["success"]:
            print("Scan successful.")
        else:
            print("Scan failed:", res["error"])
    except Exception as e:
        print("Fatal error:", e)
        sys.exit(2)
