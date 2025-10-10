from __future__ import annotations
import ipaddress
import json
import logging
#import os
import re
#import socket
import subprocess
#import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional, Dict, Any, List

class GatewayScanner:
    description = "Scans the gateway to see all the hosts connected, returns the IP and MAC"
    
    def __init__(self):
        self.logger = self._setup_logger()
        self.gateway_ip = None
        self.network_range = None
        self.hosts = []
        self.scanning = threading.Event()
        self.found_hosts = 0
        self.max_workers = 50

    def _setup_logger(self):
        logger = logging.getLogger("gateway_scanner")
        if not logger.handlers:
            h = logging.StreamHandler()
            fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s")
            h.setFormatter(fmt)
            logger.addHandler(h)
        logger.setLevel(logging.INFO)
        return logger

    def set_gateway(self, gateway_ip: str) -> None:
        try:
            ipaddress.ip_address(gateway_ip)
            self.gateway_ip = gateway_ip
        except Exception as e:
            raise ValueError(f"Invalid gateway IP: {gateway_ip}") from e

    def calculate_network_range(self) -> str:
        if not self.gateway_ip:
            raise ValueError("Gateway IP not set. Call set_gateway() first.")
            
        if self.network_range:
            return self.network_range

        gateway_octets = self.gateway_ip.split('.')
        
        if gateway_octets[0] == '10':
            self.network_range = f"{gateway_octets[0]}.{gateway_octets[1]}.{gateway_octets[2]}.0/24"
        elif gateway_octets[0] == '172' and 16 <= int(gateway_octets[1]) <= 31:
            self.network_range = f"{gateway_octets[0]}.{gateway_octets[1]}.{gateway_octets[2]}.0/24"
        elif gateway_octets[0] == '192' and gateway_octets[1] == '168':
            self.network_range = f"{gateway_octets[0]}.{gateway_octets[1]}.{gateway_octets[2]}.0/24"
        else:
            self.network_range = f"{gateway_octets[0]}.{gateway_octets[1]}.{gateway_octets[2]}.0/24"
        
        self.logger.info("Using network range: %s", self.network_range)
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
        if not self.gateway_ip:
            raise ValueError("Gateway IP not set. Call set_gateway() first.")
            
        if not self.network_range:
            self.calculate_network_range()

        network = ipaddress.ip_network(self.network_range, strict=False)
        gateway_ip_obj = ipaddress.ip_address(self.gateway_ip)
        if gateway_ip_obj not in network:
            self.logger.warning("Gateway IP %s is not in detected network %s!", self.gateway_ip, self.network_range)

        hosts = list(network.hosts())
        total_hosts = len(hosts)
        
        if total_hosts > 1000:
            self.logger.warning("Large network detected (%d hosts). This may take a while...", total_hosts)
            if total_hosts > 10000:
                response = input(f"Scan {total_hosts} hosts? This could take a long time. Continue? (y/N): ")
                if response.lower() not in ('y', 'yes'):
                    self.logger.info("Scan cancelled by user")
                    return

        self.logger.info("Scanning network: %s (%d hosts)", self.network_range, total_hosts)
        self.logger.info("Scanning for IP and MAC address...")

        self.scanning.set()
        self.found_hosts = 0 
        self.hosts = [] 

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(self._ping_host, str(host_ip)): host_ip for host_ip in hosts}
            checked = 0
            
            for future in as_completed(futures):
                checked += 1
                
                if not self.scanning.is_set():
                    self.logger.info("Scan stopped by user after %d hosts", checked)
                    break
                    
                try:
                    result = future.result()
                    if result:
                        self.hosts.append(result)
                        self.found_hosts += 1
                        self.logger.info("Found: %s - %s", result["ip"], result["mac"])
                except Exception as e:
                    self.logger.debug("Error scanning host: %s", e)
                
                if checked % 50 == 0 or checked == total_hosts:
                    percent_complete = (checked / total_hosts) * 100
                    self.logger.info("Progress: %d/%d hosts checked (%.1f%%) - Found: %d", 
                                   checked, total_hosts, percent_complete, self.found_hosts)
        
        # Final summary
        self.logger.info("Scan completed. Found %d active hosts out of %d total hosts.", 
                        self.found_hosts, total_hosts)
        
        if not self.scanning.is_set():
            self.logger.info("Scan was stopped before completion.")

    def _get_mac_address(self, ip: str) -> str:
        mac = "Unknown"
    
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
        self.logger.info("Scan stopped by user")

    def display_results(self) -> None:
        if not self.hosts:
            self.logger.info("No hosts found on the network.")
            return

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
        self.logger.info("Results exported to: %s", filename)
        return filename

    def run(self):
        gateway_ip = input("Enter gateway IP: ").strip()
        
        if not gateway_ip:
            print("No gateway IP specified. Exiting.")
            return
        
        try:
            self.set_gateway(gateway_ip)
            
            start = datetime.now()
            self.logger.info("Starting host discovery...")
            self.ping_sweep()
            duration = datetime.now() - start
            self.logger.info("Scan completed in %s", duration)

            self.display_results()

            if self.hosts:
                export = input("\nExport results to JSON file? (y/n): ").lower()
                if export in ('y', 'yes'):
                    self.export_to_json()

        except Exception as e:
            self.logger.error("Error running gateway scanner: %s", e)
            return

    def get_results(self) -> Dict[str, Any]:
        return {
            "success": len(self.hosts) > 0,
            "gateway_ip": self.gateway_ip,
            "network_range": self.network_range,
            "hosts": self.hosts,
            "hosts_found": self.found_hosts
        }


scanner = GatewayScanner()
