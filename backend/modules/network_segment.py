import subprocess
import threading
import socket
import ipaddress
import time
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

from backend.core.logger import logger  # Uncomment if using your backend

class NetworkSegmentationModule:
    description = "Scan subnets for live hosts and infer firewall behavior (TCP/UDP/ICMP)"

    # -------------------------
    # Configuration
    # -------------------------
    tcp_ports = [22, 80, 443, 3389]
    udp_ports = [53, 161, 123]  # DNS, SNMP, NTP
    icmp_timeout = 1
    tcp_timeout = 1
    udp_timeout = 1
    max_threads = 50
    rate_limit = 0.05  # seconds between packets per thread
    host_timeout = 15   # seconds per host for scanning

    def run(self):
        print("Starting module: network_segmentation_firewall")
        # logger.log_module_start("network_segmentation_firewall", "user_input")

        target_input = input("Enter target subnet(s) or IP(s) (comma-separated): ")
        targets = [t.strip() for t in target_input.split(",")]

        live_hosts = self.scan_targets(targets)
        print(f"[+] Found {len(live_hosts)} live hosts.")
        # logger.log_info("network_segmentation_firewall", "user_input", f"Live hosts: {live_hosts}")

        results = {}
        print(f"[+] Inferring firewall behavior on {len(live_hosts)} hosts...")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.infer_firewall, host): host for host in live_hosts}
            for future in as_completed(futures):
                host = futures[future]
                try:
                    results[host] = future.result()
                    print(f"    {host} -> {results[host]}")
                    # logger.log_info("network_segmentation_firewall", host, f"Inference: {results[host]}")
                except Exception as e:
                    print(f"[ERROR] {host} -> {e}")
                    # logger.log_error("network_segmentation_firewall", host, str(e))

        # -------------------------
        # Summary
        # -------------------------
        tcp_open_hosts = sum(1 for r in results.values() if r["tcp_ports"])
        udp_resp_hosts = sum(1 for r in results.values() if r["udp_ports"])
        icmp_hosts = sum(1 for r in results.values() if r["icmp"])
        print("\n[+] Scan Summary:")
        print(f"    Total live hosts: {len(live_hosts)}")
        print(f"    Hosts with TCP open: {tcp_open_hosts}")
        print(f"    Hosts with UDP responsive: {udp_resp_hosts}")
        print(f"    Hosts ICMP reachable: {icmp_hosts}")
        print("\n[+] Module completed.\n")

    # -------------------------
    # Target Scanning
    # -------------------------
    def scan_targets(self, targets):
        live_hosts = []
        ip_list = []

        # Expand subnets
        for t in targets:
            try:
                if "/" in t:
                    net = ipaddress.ip_network(t, strict=False)
                    ip_list.extend([str(ip) for ip in net.hosts()])
                else:
                    ip_list.append(t)
            except Exception as e:
                print(f"[!] Invalid target {t}: {e}")

        def probe_ip(ip):
            if self.icmp_ping(ip) or self.tcp_probe(ip, self.tcp_ports):
                return ip
            return None

        print(f"[+] Scanning {len(ip_list)} IPs for live hosts...")
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for result in executor.map(probe_ip, ip_list):
                if result:
                    live_hosts.append(result)

        return live_hosts

    # -------------------------
    # Firewall inference
    # -------------------------
    def infer_firewall(self, host):
        result = {"tcp_ports": [], "udp_ports": [], "icmp": False}

        def tcp_worker():
            result["tcp_ports"] = self.tcp_probe_ports(host, self.tcp_ports)

        def udp_worker():
            result["udp_ports"] = self.udp_probe_ports(host, self.udp_ports)

        def icmp_worker():
            result["icmp"] = self.icmp_ping(host)

        # Run per-host probes in parallel
        threads = [
            threading.Thread(target=tcp_worker),
            threading.Thread(target=udp_worker),
            threading.Thread(target=icmp_worker)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=self.host_timeout)

        # Inference logic
        if not result["tcp_ports"] and not result["udp_ports"] and not result["icmp"]:
            result["status"] = "Host Lost / Strict Drop"
        else:
            result["status"] = "Open / Filtered"

        return result

    # -------------------------
    # ICMP
    # -------------------------
    def icmp_ping(self, host):
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"
            timeout_val = "1000" if platform.system().lower() == "windows" else str(self.icmp_timeout)
            cmd = ["ping", param, "1", timeout_flag, timeout_val, host]
            result = subprocess.run(cmd, capture_output=True, timeout=self.icmp_timeout + 2)
            time.sleep(self.rate_limit)
            return result.returncode == 0
        except Exception:
            return False

    # -------------------------
    # TCP
    # -------------------------
    def tcp_probe_ports(self, host, ports):
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.tcp_timeout)
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append(port)
                sock.close()
                time.sleep(self.rate_limit)
            except Exception:
                continue
        return open_ports

    def tcp_probe(self, host, ports):
        return bool(self.tcp_probe_ports(host, ports))

    # -------------------------
    # UDP (protocol-aware)
    # -------------------------
    def udp_probe_ports(self, host, ports):
        responsive_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.udp_timeout)

                # Protocol-specific payloads
                if port == 53:
                    sock.sendto(b"\x00\x00\x00\x00", (host, port))  # minimal DNS query
                elif port == 161:
                    sock.sendto(b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x71\xb4\x5b\x2c\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x01\x05\x00", (host, port))  # minimal SNMP GET
                elif port == 123:
                    sock.sendto(b"\x1b" + 47 * b"\0", (host, port))  # minimal NTP request
                else:
                    sock.sendto(b"\x00", (host, port))

                try:
                    sock.recvfrom(1024)
                    responsive_ports.append(port)
                except socket.timeout:
                    pass
                sock.close()
                time.sleep(self.rate_limit)
            except Exception:
                continue
        return responsive_ports

    def udp_probe(self, host, ports):
        return bool(self.udp_probe_ports(host, ports))


if __name__ == "__main__":
    scanner = NetworkSegmentationModule()
    scanner.run()
