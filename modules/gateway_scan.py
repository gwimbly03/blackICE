from __future__ import annotations
import ipaddress
import json
import logging
import re
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional, Dict, Any, List
from core.logger import logger

class GatewayScanner:
    """
    This module asks the user to input the gateway of a network then scans the network for all the hosts connected, returns the IP and MAC address. It does this my using ping to the network for IP and arp, arping and /proc/net/arp to resolve the MAC address for the hosts 
    """
    description = "Scans the gateway to see all the hosts connected, returns the IP and MAC"
    
    def __init__(self):
        """
        Start the GatewayScanner
        """
        self.gateway_ip = None
        self.network_range = None
        self.hosts = []
        self.scanning = threading.Event()
        self.found_hosts = 0
        self.max_workers = 50

    def set_gateway(self, gateway_ip: str) -> None:
        """
        Trys the check the IP of the gateway if it can find it then it will throw an error
        """
        try:
            ipaddress.ip_address(gateway_ip)
            self.gateway_ip = gateway_ip
        except Exception as e:
            raise ValueError(f"Invalid gateway IP: {gateway_ip}") from e

    def calculate_network_range(self) -> str:
        """
        Tries to find the /24 network range from the gateway IP. It throws an error if the gateway ip is not set properly
        """
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
        
        print(f"Using network range: {self.network_range}")
        return self.network_range

    def _ping_host(self, ip: str) -> Optional[Dict[str, str]]:
        """
        Pings one host at a time if IP is responds then tries to get MAC address
        """
        try:
            result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True)
            if result.returncode != 0:
                return None

            mac = self._get_mac_address(ip)
            return {"ip": ip, "mac": mac}
        except Exception:
            return None
    
    def ping_sweep(self) -> None:
        """
        Perform ICMP ping sweep using a ThreadPoolExecutor for the entire networke range.
        """
        if not self.gateway_ip:
            raise ValueError("Gateway IP not set. Call set_gateway() first.")
            
        if not self.network_range:
            self.calculate_network_range()

        network = ipaddress.ip_network(self.network_range, strict=False)
        gateway_ip_obj = ipaddress.ip_address(self.gateway_ip)
        if gateway_ip_obj not in network:
            print(f"Warning: Gateway IP {self.gateway_ip} is not in detected network {self.network_range}!")

        hosts = list(network.hosts())
        total_hosts = len(hosts)
        
        if total_hosts > 1000:
            print(f"Large network detected ({total_hosts} hosts). This may take a while...")
            if total_hosts > 10000:
                response = input(f"Scan {total_hosts} hosts? This could take a long time. Continue? (y/N): ")
                if response.lower() not in ('y', 'yes'):
                    print("Scan cancelled by user")
                    return

        print(f"Scanning network: {self.network_range} ({total_hosts} hosts)")
        print("Scanning for IP and MAC address...")

        self.scanning.set()
        self.found_hosts = 0 
        self.hosts = [] 

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(self._ping_host, str(host_ip)): host_ip for host_ip in hosts}
            checked = 0
            
            for future in as_completed(futures):
                checked += 1
                
                if not self.scanning.is_set():
                    print(f"Scan stopped by user after {checked} hosts")
                    break
                    
                try:
                    result = future.result()
                    if result:
                        self.hosts.append(result)
                        self.found_hosts += 1
                        print(f"Found: {result['ip']} - {result['mac']}")
                except Exception as e:
                    pass  # Silent error handling
                
                if checked % 50 == 0 or checked == total_hosts:
                    percent_complete = (checked / total_hosts) * 100
                    print(f"Progress: {checked}/{total_hosts} hosts checked ({percent_complete:.1f}%) - Found: {self.found_hosts}")
        
        print(f"Scan completed. Found {self.found_hosts} active hosts out of {total_hosts} total hosts.")
        
        if not self.scanning.is_set():
            print("Scan was stopped before completion.")

    def _get_mac_address(self, ip: str) -> str:
        """
        Try to find MAC using 3 methods arp, arping and checking the /proc/net/arp
        """
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
        """
        All this does is stop the scan if initiated by the user
        """
        self.scanning.clear()
        print("Scan stopped by user")

    def display_results(self) -> None:
        """
        Displays the results of the network scan in a nice formatted table then prints it to stout, if there are no hosts on the network then return a error 
        """
        if not self.hosts:
            print("No hosts found on the network.")
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

    def run(self):
        """
        This runs the the GatewayScanner asking the user to enter the gateway IP
        """
        gateway_ip = input("Enter gateway IP: ").strip()
        
        if not gateway_ip:
            print("No gateway IP specified. Exiting.")
            return
        
        # Log module start
        logger.log_module_start("gateway_scan", gateway_ip)
        
        try:
            self.set_gateway(gateway_ip)
            
            start = datetime.now()
            print("Starting host discovery...")
            self.ping_sweep()
            duration = datetime.now() - start
            print(f"Scan completed in {duration}")

            self.display_results()

            # Prepare results for logging
            result = {
                "status": "completed",
                "scan_duration": str(duration),
                "network_range": self.network_range,
                "hosts_found": len(self.hosts),
                "total_hosts_scanned": len(list(ipaddress.ip_network(self.network_range, strict=False).hosts())),
                "hosts": self.hosts,
                "summary": {
                    "total_hosts_found": len(self.hosts),
                    "gateway_ip": self.gateway_ip,
                    "network_range": self.network_range
                }
            }
            
            # Log the results
            logger.log_module_result("gateway_scan", gateway_ip, result)
            
            print(f"\nNetwork scan completed. Results have been logged.")
            
        except Exception as e:
            error_result = {
                "status": "error",
                "error": str(e)
            }
            logger.log_module_result("gateway_scan", gateway_ip, error_result)
            print(f"Error running gateway scanner: {e}")
            return

    def get_results(self) -> Dict[str, Any]:
        """
        Returns the results in a structured format 
        """
        return {
            "success": len(self.hosts) > 0,
            "gateway_ip": self.gateway_ip,
            "network_range": self.network_range,
            "hosts": self.hosts,
            "hosts_found": self.found_hosts
        }


gate_scan = GatewayScanner()
