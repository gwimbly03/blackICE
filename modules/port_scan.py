import socket
from datetime import datetime
from threading import Thread, Lock
from queue import Queue
from core.logger import logger
from scapy.all import IP, TCP, sr1, conf

conf.verb = 0  # quiet scapy for stealth scan


class PortScanner:

    description = "Advanced Port Scanner supporting TCP Connect, SYN Stealth, Xmas, FIN, and NULL scans"

    def __init__(self):
        self.open_ports = []
        self.lock = Lock()          # protects open_ports
        self.print_lock = Lock()    # protects console output
        self.job_queue = Queue()    # ports for worker threads

        # Common ports + service names
        self.common_ports = {
            20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 139: "netbios-ssn", 143: "imap",
            443: "https", 445: "microsoft-ds", 3389: "ms-wbt-server",
            3306: "mysql", 1433: "mssql", 1521: "oracle-db", 5900: "vnc",
            8080: "http-proxy"
        }

    def safe_print(self, msg: str):
        with self.print_lock:
            print(msg)

    # -----------------------------------------------------------
    # BANNER GRABBERS
    # -----------------------------------------------------------

    def grab_rdp_version(self, target, port=3389):
        try:
            sock = socket.socket()
            sock.settimeout(2)
            sock.connect((target, port))
            request = bytes.fromhex('030000130ee000000000000100080000000000')
            sock.sendall(request)
            response = sock.recv(1024)
            sock.close()

            if len(response) >= 19:
                version_byte = response[2]
                versions = {
                    0x00: "RDP 4.0", 0x01: "RDP 5.0", 0x02: "RDP 5.1",
                    0x04: "RDP 5.2", 0x05: "RDP 6.0", 0x06: "RDP 6.1",
                    0x07: "RDP 7.0", 0x08: "RDP 7.1", 0x09: "RDP 8.0",
                    0x0A: "RDP 10.0"
                }
                return versions.get(version_byte, "RDP (unknown version)")
            return "RDP (unknown)"
        except Exception as e:
            return f"RDP (negotiation error: {str(e)})"

    def grab_ssh_banner(self, sock):
        try:
            return sock.recv(1024).decode(errors="ignore").strip()
        except:
            return "SSH (no banner)"

    def grab_http_banner(self, sock, port, service):
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            response = sock.recv(1024).decode(errors="ignore")
            for line in response.split("\n"):
                if line.lower().startswith("server:"):
                    return line.strip()
            return "HTTP (no server header)"
        except:
            return "HTTP (no response)"

    def grab_ftp_banner(self, sock):
        try:
            return sock.recv(1024).decode(errors="ignore").strip()
        except:
            return "FTP (no banner)"

    def grab_smtp_banner(self, sock):
        try:
            banner = sock.recv(1024).decode(errors="ignore").strip()
            sock.sendall(b"EHLO example.com\r\n")
            resp = sock.recv(1024).decode(errors="ignore").split("\n")[0].strip()
            return f"{banner} | {resp}"
        except:
            return "SMTP (no banner)"

    def grab_mysql_banner(self, sock):
        try:
            return sock.recv(1024).decode(errors="ignore").strip()
        except:
            return "MySQL (no banner)"

    def grab_generic_banner(self, sock):
        try:
            sock.settimeout(2)
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return banner if banner else "no banner"
        except:
            return "no banner"

    def grab_banner(self, target, port, service):
        try:
            sock = socket.socket()
            sock.settimeout(3)
            sock.connect((target, port))

            if service == "ms-wbt-server":
                sock.close()
                return self.grab_rdp_version(target, port)

            banner_func = {
                "ssh": self.grab_ssh_banner,
                "http": self.grab_http_banner,
                "https": self.grab_http_banner,
                "http-proxy": self.grab_http_banner,
                "ftp": self.grab_ftp_banner,
                "smtp": self.grab_smtp_banner,
                "mysql": self.grab_mysql_banner
            }.get(service, self.grab_generic_banner)

            if service in ("http", "https", "http-proxy"):
                banner = banner_func(sock, port, service)
            else:
                banner = banner_func(sock)

            sock.close()

            if banner:
                banner = " ".join(banner.split())[:100]

            return banner

        except Exception:
            return "no banner"

    # -----------------------------------------------------------
    # SCAN TYPES (SCAPY)
    # -----------------------------------------------------------

    def syn_scan_port(self, target, port):
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=0.5)

        if resp and resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:  # SYN-ACK
                with self.lock:
                    self.open_ports.append((port, "open"))
                # Send RST to close half-open connection
                sr1(IP(dst=target) / TCP(dport=port, flags="R"), timeout=0.2)
                self.safe_print(f"[OPEN] {port}/tcp (SYN)")
            elif resp[TCP].flags == 0x14:
                self.safe_print(f"[CLOSED] {port}/tcp")
        else:
            self.safe_print(f"[FILTERED] {port}/tcp")

    def xmas_scan_port(self, target, port):
        resp = sr1(IP(dst=target) / TCP(dport=port, flags="FPU"), timeout=0.5)
        if resp is None:
            self.safe_print(f"[OPEN|FILTERED] {port}/tcp (Xmas)")
        elif resp.haslayer(TCP) and resp[TCP].flags == 0x14:
            self.safe_print(f"[CLOSED] {port}")

    def fin_scan_port(self, target, port):
        resp = sr1(IP(dst=target) / TCP(dport=port, flags="F"), timeout=0.5)
        if resp is None:
            self.safe_print(f"[OPEN|FILTERED] {port}/tcp (FIN)")
        elif resp.haslayer(TCP) and resp[TCP].flags == 0x14:
            self.safe_print(f"[CLOSED] {port}")

    def null_scan_port(self, target, port):
        resp = sr1(IP(dst=target) / TCP(dport=port, flags=0), timeout=0.5)
        if resp is None:
            self.safe_print(f"[OPEN|FILTERED] {port}/tcp (NULL)")
        elif resp.haslayer(TCP) and resp[TCP].flags == 0x14:
            self.safe_print(f"[CLOSED] {port}")

    def tcp_connect_scan(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            service = self.common_ports.get(port, "unknown")

            if result == 0:
                banner = self.grab_banner(target, port, service)
                with self.lock:
                    self.open_ports.append((port, service, banner))
                self.safe_print(f"Port {port}/{service} OPEN - Banner: {banner}")

            sock.close()
        except:
            pass

    # -----------------------------------------------------------
    # WORKER THREAD
    # -----------------------------------------------------------

    def worker(self, target, scan_function):
        while True:
            port = self.job_queue.get()
            if port is None:
                self.job_queue.task_done()
                return
            try:
                scan_function(target, port)
            except Exception as e:
                self.safe_print(f"[ERROR] {port}: {e}")
            finally:
                self.job_queue.task_done()

    # -----------------------------------------------------------
    # MAIN RUN
    # -----------------------------------------------------------

    def run(self):
        target = input("Enter target IP: ").strip()
        if not target:
            print("No target provided.")
            return

        print("\nSelect scan type:")
        print("1) TCP Connect Scan")
        print("2) SYN Stealth Scan")
        print("3) Xmas Scan")
        print("4) FIN Scan")
        print("5) NULL Scan")

        scan_type = input("Choice: ").strip()

        print("\nPort Range Options:")
        print("1) Custom range (e.g., 20-500)")
        print("2) Full range (0-65535)")
        print("3) Common ports only")

        range_choice = input("Choice: ").strip()

        if range_choice == "1":
            pr = input("Enter port range (example 20-500): ").strip()
            start, end = map(int, pr.split("-"))
            ports = list(range(start, end + 1))
        elif range_choice == "2":
            ports = list(range(0, 65536))
        else:
            ports = list(self.common_ports.keys())

        thread_count = input("Threads (default 100): ").strip()
        thread_count = int(thread_count) if thread_count.isdigit() else 100

        scan_function = {
            "1": self.tcp_connect_scan,
            "2": self.syn_scan_port,
            "3": self.xmas_scan_port,
            "4": self.fin_scan_port,
            "5": self.null_scan_port
        }.get(scan_type, self.tcp_connect_scan)

        print(f"\nStarting scan using {thread_count} threads...\n")

        # Start worker threads
        workers = []
        for _ in range(thread_count):
            t = Thread(target=self.worker, args=(target, scan_function))
            t.daemon = True
            t.start()
            workers.append(t)

        # Queue ports
        for port in ports:
            self.job_queue.put(port)

        self.job_queue.join()

        # Stop workers
        for _ in range(thread_count):
            self.job_queue.put(None)

        for t in workers:
            t.join()

        print("\nScan complete.\n")

