import socket
import time
from datetime import datetime
from threading import Thread, Lock
from queue import Queue
from typing import Callable, List, Tuple, Any, Optional
from core.logger import logger
from scapy.all import IP, TCP, sr1, send, conf
from core.cve_db import CVELookup

conf.verb = 0  

# These settings can be tuned to what the user wants I just set them to these values for testing 
DEFAULT_THREAD_COUNT = 100
SOCKET_TIMEOUT = 1.0           
BANNER_TIMEOUT = 2.0           
SCAPY_PACKET_TIMEOUT = 0.6    
DEFAULT_PPS = 50               

CVE_CACHE = {}


class RateLimiter:
    """
    Global rate limiter that throttles packet sends across threads.
    Very simple: ensures at least `delay` seconds between send events.
    """
    def __init__(self, pps: float = DEFAULT_PPS):
        self.set_pps(pps)
        self._lock = Lock()
        self._last = 0.0

    def set_pps(self, pps: float):
        if pps <= 0:
            pps = DEFAULT_PPS
        self.pps = pps
        self.delay = 1.0 / float(self.pps)

    def wait(self):
        with self._lock:
            now = time.time()
            diff = now - self._last
            if diff < self.delay:
                to_sleep = self.delay - diff
                time.sleep(to_sleep)
                self._last = time.time()
            else:
                self._last = now


class PortScanner:
    """
    Advanced Port Scanner:
      - TCP Connect (banner grabbing + CVE lookup)
      - SYN stealth (Scapy)
      - Xmas / FIN / NULL (Scapy)
      - Thread-pool + global rate limiting (PPS / T0-T5 mapping)
    """

    description = "Advanced Port Scanner supporting TCP Connect, SYN Stealth, Xmas, FIN, and NULL scans"

    def __init__(self):
        self.open_ports: List[Tuple[Any, ...]] = []
        self._results_lock = Lock()      
        self._print_lock = Lock()        
        self.job_queue = Queue()
        self.rate_limiter = RateLimiter(DEFAULT_PPS)

        self.common_ports = {
            20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 139: "netbios-ssn", 143: "imap",
            443: "https", 445: "microsoft-ds", 3389: "ms-wbt-server",
            3306: "mysql", 1433: "mssql", 1521: "oracle-db", 5900: "vnc",
            8080: "http-proxy"
        }

    def safe_print(self, *args, **kwargs):
        with self._print_lock:
            print(*args, **kwargs)

    def _make_socket(self):
        s = socket.socket()
        s.settimeout(SOCKET_TIMEOUT)
        return s

    def grab_rdp_version(self, target, port=3389):
        try:
            sock = self._make_socket()
            sock.settimeout(2)
            sock.connect((target, port))
            request = bytes.fromhex('030000130ee000000000000100080000000000')
            sock.sendall(request)
            sock.settimeout(BANNER_TIMEOUT)
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
            sock.settimeout(BANNER_TIMEOUT)
            return sock.recv(1024).decode(errors="ignore").strip()
        except:
            return "SSH (no banner)"

    def grab_http_banner(self, sock, port, service):
        try:
            sock.settimeout(BANNER_TIMEOUT)
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
            sock.settimeout(BANNER_TIMEOUT)
            return sock.recv(1024).decode(errors="ignore").strip()
        except:
            return "FTP (no banner)"

    def grab_smtp_banner(self, sock):
        try:
            sock.settimeout(BANNER_TIMEOUT)
            banner = sock.recv(1024).decode(errors="ignore").strip()
            sock.sendall(b"EHLO example.com\r\n")
            sock.settimeout(BANNER_TIMEOUT)
            resp = sock.recv(1024).decode(errors="ignore").split("\n")[0].strip()
            return f"{banner} | {resp}"
        except:
            return "SMTP (no banner)"

    def grab_mysql_banner(self, sock):
        try:
            sock.settimeout(BANNER_TIMEOUT)
            return sock.recv(1024).decode(errors="ignore").strip()
        except:
            return "MySQL (no banner)"

    def grab_generic_banner(self, sock):
        try:
            sock.settimeout(BANNER_TIMEOUT)
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return banner if banner else "no banner"
        except:
            return "no banner"

    def grab_banner(self, target: str, port: int, service: str):
        try:
            sock = self._make_socket()
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
                return " ".join(banner.split())[:200]
            return "no banner"
        except Exception:
            return "no banner"

    def syn_scan_port(self, target: str, port: int):
        try:
            self.rate_limiter.wait()
            pkt = IP(dst=target) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=SCAPY_PACKET_TIMEOUT, verbose=0)

            if resp is None:
                self.safe_print(f"[FILTERED] {port}/tcp")
                return

            if resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags & 0x12 == 0x12:  
                    rst = IP(dst=target) / TCP(dport=port, flags="R")
                    # respect rate limiter for RST too
                    self.rate_limiter.wait()
                    send(rst, verbose=0)
                    with self._results_lock:
                        self.open_ports.append((port, "open"))
                    self.safe_print(f"[OPEN] {port}/tcp (SYN)")
                elif flags & 0x14 == 0x14:
                    self.safe_print(f"[CLOSED] {port}/tcp")
                else:
                    self.safe_print(f"[UNKNOWN] {port}/tcp (flags={flags})")
            else:
                self.safe_print(f"[NO TCP LAYER] {port}/tcp")
        except PermissionError:
            self.safe_print("[!] SYN scan requires root (raw sockets).")
        except Exception as e:
            self.safe_print(f"[ERROR syn] {port}: {e}")

    def xmas_scan_port(self, target: str, port: int):
        try:
            self.rate_limiter.wait()
            pkt = IP(dst=target) / TCP(dport=port, flags="FPU")
            resp = sr1(pkt, timeout=SCAPY_PACKET_TIMEOUT, verbose=0)
            if resp is None:
                with self._results_lock:
                    self.open_ports.append((port, "open|filtered"))
                self.safe_print(f"[OPEN|FILTERED] {port}/tcp (XMAS)")
                return
            if resp.haslayer(TCP) and resp[TCP].flags & 0x04:
                self.safe_print(f"[CLOSED] {port}/tcp")
            else:
                self.safe_print(f"[RESP] {port}/tcp (XMAS)")
        except PermissionError:
            self.safe_print("[!] XMAS scan requires root.")
        except Exception as e:
            self.safe_print(f"[ERROR xmas] {port}: {e}")

    def fin_scan_port(self, target: str, port: int):
        try:
            self.rate_limiter.wait()
            pkt = IP(dst=target) / TCP(dport=port, flags="F")
            resp = sr1(pkt, timeout=SCAPY_PACKET_TIMEOUT, verbose=0)
            if resp is None:
                with self._results_lock:
                    self.open_ports.append((port, "open|filtered"))
                self.safe_print(f"[OPEN|FILTERED] {port}/tcp (FIN)")
                return
            if resp.haslayer(TCP) and resp[TCP].flags & 0x04:
                self.safe_print(f"[CLOSED] {port}/tcp")
            else:
                self.safe_print(f"[RESP] {port}/tcp (FIN)")
        except PermissionError:
            self.safe_print("[!] FIN scan requires root.")
        except Exception as e:
            self.safe_print(f"[ERROR fin] {port}: {e}")

    def null_scan_port(self, target: str, port: int):
        try:
            self.rate_limiter.wait()
            pkt = IP(dst=target) / TCP(dport=port, flags=0)
            resp = sr1(pkt, timeout=SCAPY_PACKET_TIMEOUT, verbose=0)
            if resp is None:
                with self._results_lock:
                    self.open_ports.append((port, "open|filtered"))
                self.safe_print(f"[OPEN|FILTERED] {port}/tcp (NULL)")
                return
            if resp.haslayer(TCP) and resp[TCP].flags & 0x04:
                self.safe_print(f"[CLOSED] {port}/tcp")
            else:
                self.safe_print(f"[RESP] {port}/tcp (NULL)")
        except PermissionError:
            self.safe_print("[!] NULL scan requires root.")
        except Exception as e:
            self.safe_print(f"[ERROR null] {port}: {e}")

    def tcp_connect_scan(self, target: str, port: int):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(SOCKET_TIMEOUT)
            result = sock.connect_ex((target, port))
            service = self.common_ports.get(port, "unknown")

            if result == 0:
                banner = self.grab_banner(target, port, service)

                cves = []
                cache_key = (service, banner)
                if cache_key in CVE_CACHE:
                    cves = CVE_CACHE[cache_key]
                else:
                    product, version = CVELookup.extract_version(banner)
                    if product and version:
                        cves = CVELookup.search_cves(product, version)
                    CVE_CACHE[cache_key] = cves

                with self._results_lock:
                    self.open_ports.append((port, service, banner, cves))

                self.safe_print(f"\n[OPEN] {port}/tcp ({service}) - {banner}")
                if cves:
                    self.safe_print("  └── CVEs Found:")
                    for cve, score, title in cves[:8]:
                        self.safe_print(f"       → {cve} | Score {score} | {title}")

            sock.close()
        except Exception as e:
            self.safe_print(f"[ERROR connect] {port}: {e}")

    def worker(self, target: str, scan_fn: Callable[[str, int], None]):
        while True:
            port = self.job_queue.get()
            if port is None:
                self.job_queue.task_done()
                return
            try:
                scan_fn(target, port)
            except Exception as e:
                self.safe_print(f"[ERROR worker] port {port}: {e}")
            finally:
                self.job_queue.task_done()

    @staticmethod
    def timing_to_pps(timing: str) -> int:
        """
        Maps Nmap timing template to a rough packets-per-second value.
        These values are adjustable I just made them similar to nmap.
        """
        mapping = {
            "T0": 2,      # paranoid
            "T1": 10,     # sneaky
            "T2": 25,     # polite
            "T3": 50,     # normal
            "T4": 200,    # aggressive
            "T5": 1000    # insane
        }
        return mapping.get(timing.upper(), DEFAULT_PPS)

    def run(self):
        target = input("Enter target IP: ").strip()
        if not target:
            self.safe_print("No target provided.")
            return

        logger.log_module_start("port_scan", target)
        self.open_ports.clear()
        CVE_CACHE.clear()

        self.safe_print("\nSelect scan type:")
        self.safe_print("1) TCP Connect Scan (banner + CVE)")
        self.safe_print("2) SYN Stealth Scan (requires root)")
        self.safe_print("3) Xmas Scan (requires root)")
        self.safe_print("4) FIN Scan (requires root)")
        self.safe_print("5) NULL Scan (requires root)")
        scan_choice = input("Choice (1-5): ").strip()

        scan_map = {
            "1": self.tcp_connect_scan,
            "2": self.syn_scan_port,
            "3": self.xmas_scan_port,
            "4": self.fin_scan_port,
            "5": self.null_scan_port
        }
        scan_fn = scan_map.get(scan_choice)
        if scan_fn is None:
            self.safe_print("Invalid scan selection.")
            return

        # Port range
        self.safe_print("\nPort Range Options:")
        self.safe_print("1) Custom range (e.g., 20-500)")
        self.safe_print("2) Full range (0-65535)")
        self.safe_print("3) Common ports only (default)")
        range_choice = input("Choice (1-3): ").strip()

        if range_choice == "1":
            pr = input("Enter port range (start-end): ").strip()
            try:
                start, end = map(int, pr.split("-"))
                if not (0 <= start <= 65535 and 0 <= end <= 65535 and start <= end):
                    raise ValueError
                ports = list(range(start, end + 1))
            except Exception:
                self.safe_print("Invalid range. Aborting.")
                return
        elif range_choice == "2":
            ports = list(range(0, 65536))
        else:
            ports = list(self.common_ports.keys())

        try:
            tcount = input(f"Threads (default {DEFAULT_THREAD_COUNT}): ").strip()
            threads = int(tcount) if tcount.isdigit() else DEFAULT_THREAD_COUNT
            if threads < 1:
                threads = DEFAULT_THREAD_COUNT
        except Exception:
            threads = DEFAULT_THREAD_COUNT

        self.safe_print("\nRate control options:")
        self.safe_print("1) Packets per second (custom PPS)")
        self.safe_print("2) Nmap timing template (T0-T5)")
        self.safe_print("3) Default PPS (no change)")
        rate_choice = input("Choice (1-3): ").strip()

        if rate_choice == "1":
            try:
                pps = float(input(f"Enter PPS (default {DEFAULT_PPS}): ").strip() or DEFAULT_PPS)
                self.rate_limiter.set_pps(pps)
            except Exception:
                self.safe_print("Invalid PPS provided, using default.")
                self.rate_limiter.set_pps(DEFAULT_PPS)
        elif rate_choice == "2":
            timing = input("Enter timing (T0..T5): ").strip().upper()
            pps = self.timing_to_pps(timing)
            self.safe_print(f"Using timing {timing} -> approx {pps} PPS")
            self.rate_limiter.set_pps(pps)
        else:
            self.rate_limiter.set_pps(DEFAULT_PPS)

        if len(ports) > 20000 and threads > 500:
            self.safe_print("[!] Very large scan requested. Consider reducing threads or range.")

        self.safe_print(f"\nStarting scan on {target} - {len(ports)} ports using {threads} threads (pps={self.rate_limiter.pps})")
        start_time = datetime.now()

        workers = []
        for _ in range(threads):
            t = Thread(target=self.worker, args=(target, scan_fn))
            t.daemon = True
            t.start()
            workers.append(t)

        for p in ports:
            self.job_queue.put(p)

        try:
            self.job_queue.join()
        except KeyboardInterrupt:
            self.safe_print("\n[!] Interrupted by user. Stopping...")
        finally:
            for _ in workers:
                self.job_queue.put(None)
            for w in workers:
                w.join()

        duration = datetime.now() - start_time
        self.safe_print(f"\nScan finished in {duration}. Found {len(self.open_ports)} open/filtered ports.\n")

        if scan_choice == "1":
            for entry in sorted(self.open_ports, key=lambda x: x[0]):
                try:
                    port, service, banner, cves = entry
                    self.safe_print(f"{port}/tcp ({service}) - {banner}")
                    if cves:
                        for cve, score, title in cves[:10]:
                            self.safe_print(f"   → {cve} | Score {score} | {title}")
                        self.safe_print("")
                except Exception:
                    self.safe_print(str(entry))
        else:
            for entry in sorted(self.open_ports, key=lambda x: x[0]):
                self.safe_print(f"{entry[0]}/tcp - {entry[1]}")

        result = {
            "status": "completed",
            "scan_mode": scan_choice,
            "ports_scanned": len(ports),
            "open_ports_count": len(self.open_ports),
            "open_ports": [
                {"port": e[0], "service": (e[1] if len(e) > 1 else None), "info": (e[2] if len(e) > 2 else None)}
                for e in self.open_ports
            ],
            "scan_duration": str(duration)
        }
        logger.log_module_result("port_scan", target, result)
        self.safe_print("Results logged.")
        return result


scanner = PortScanner()

