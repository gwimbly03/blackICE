import socket
from datetime import datetime
from threading import Thread, Lock
from core.logger import log_info, log_error

class PortScanner:
    """
    port scanner scans a target host for open tcp ports and tries to grab the service and banners 
    """

    description = "Port Scanner to find open ports and services and grab their banners"
    
    def __init__(self):
        self.open_ports = []
        self.lock = Lock()
        self.common_ports = {
            20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 139: "netbios-ssn", 143: "imap",
            443: "https", 445: "microsoft-ds", 3389: "ms-wbt-server",
            3306: "mysql", 1433: "mssql", 1521: "oracle-db", 5900: "vnc",
            8080: "http-proxy"
        }

    def grab_rdp_version(self, target, port=3389):
        """
        This grabs rdp banner and tries to guess the rdp version based on the response from the targeted host

        """
        try:
            sock = socket.socket()
            sock.settimeout(2)
            sock.connect((target, port))
            
            request = bytes.fromhex('030000130ee000000000000100080000000000')
            sock.sendall(request)
            response = sock.recv(1024)
            sock.close()
            
            if len(response) >= 19:
                if response[0] == 0x03 and response[1] == 0x00:
                    version_byte = response[2]
                    if version_byte == 0x00:
                        return "RDP 4.0"
                    elif version_byte == 0x01:
                        return "RDP 5.0"
                    elif version_byte == 0x02:
                        return "RDP 5.1"
                    elif version_byte == 0x04:
                        return "RDP 5.2"
                    elif version_byte == 0x05:
                        return "RDP 6.0"
                    elif version_byte == 0x06:
                        return "RDP 6.1"
                    elif version_byte == 0x07:
                        return "RDP 7.0"
                    elif version_byte == 0x08:
                        return "RDP 7.1"
                    elif version_byte == 0x09:
                        return "RDP 8.0"
                    elif version_byte == 0x0a:
                        return "RDP 10.0"
            
            return "RDP (version unknown)"
        except Exception as e:
            return f"RDP (unable to negotiate: {str(e)})"

    def grab_ssh_banner(self, sock):
        """
        Grabs ssh banner from the open socket
        """
        try:
            banner = sock.recv(1024).decode(errors='ignore').strip()
            return banner
        except:
            return "SSH (no banner received)"

    def grab_http_banner(self, sock, port, service):
        """
        Grabs http banner sends a head request and then parses server header for http/https
        """
        try:
            if service == "https":
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n")
            else:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            
            response = sock.recv(1024).decode(errors='ignore')
            lines = response.split('\n')
            for line in lines:
                if line.lower().startswith('server:'):
                    return line.strip()
            return "HTTP (no server banner)"
        except:
            return "HTTP (no response)"

    def grab_ftp_banner(self, sock):
        """
        Grabs the ftp banner from open socket
        """
        try:
            banner = sock.recv(1024).decode(errors='ignore').strip()
            return banner
        except:
            return "FTP (no banner)"

    def grab_smtp_banner(self, sock):
        """
        Reads the smpt greeting then send a ehlo and get the first response line to return the banner
        """
        try:
            banner = sock.recv(1024).decode(errors='ignore').strip()
            sock.sendall(b"EHLO example.com\r\n")
            response = sock.recv(1024).decode(errors='ignore').strip()
            return f"{banner} | {response.split(chr(10))[0]}"
        except:
            return "SMTP (no banner)"

    def grab_mysql_banner(self, sock):
        """
        Grab the sql banner by reading the sql handshake on the socket then return it as text
        """
        try:
            banner = sock.recv(1024).decode(errors='ignore').strip()
            return banner
        except:
            return "MySQL (no banner)"

    def grab_generic_banner(self, sock):
        """
        Grabs a generic banner running for a service from open socket
        """
        try:
            sock.settimeout(2)
            banner = sock.recv(1024).decode(errors='ignore').strip()
            return banner if banner else "no banner"
        except:
            return "no banner"

    def grab_banner(self, target, port, service):
        """
        opens a tcp connection yo the target host ip and port then call the banner function for the correct service
        """
        try:
            sock = socket.socket()
            sock.settimeout(3)
            sock.connect((target, port))
            
            if service == "ms-wbt-server":
                sock.close()
                return self.grab_rdp_version(target, port)
            elif service == "ssh":
                banner = self.grab_ssh_banner(sock)
            elif service in ["http", "https", "http-proxy"]:
                banner = self.grab_http_banner(sock, port, service)
            elif service == "ftp":
                banner = self.grab_ftp_banner(sock)
            elif service == "smtp":
                banner = self.grab_smtp_banner(sock)
            elif service == "mysql":
                banner = self.grab_mysql_banner(sock)
            else:
                banner = self.grab_generic_banner(sock)
            
            sock.close()
            
            if banner and banner != "no banner":
                banner = ' '.join(banner.split())[:100]
            return banner if banner else "no banner"
            
        except Exception as e:
            return f"error: {str(e)}"

    def scan_port(self, target, port):
        """
        This will check a tcp port on the target ip to see if its open, if it is then it grabs the banner
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            service = self.common_ports.get(port, "unknown")
            
            if result == 0:
                banner = self.grab_banner(target, port, service)
                with self.lock:
                    self.open_ports.append((port, service, banner))
                log_info(f"Port {port}/{service} is open - Banner: {banner}")
            else:
                log_info(f"Port {port}/{service} is closed")
                
            sock.close()
        except Exception as e:
            log_error(f"Error scanning port {port}: {e}")

    def run(self):
        """
        Asks for the user to input an ip and a port range then starts the port scan it uses multi threading, it allows the user to specify a port range once the scan finishs it outputs the service and the grabed banner of said service 
        """
        target = input("Enter target IP: ").strip()

        if not target:
            print("No target IP specified. Exiting.")
            return

        
        self.open_ports = []  
        
        start_time = datetime.now()
        print(f"\nStarting BlackICE TCP Scan at {start_time}")
        print(f"Scan report for {target}")

        port_input = input("Enter port range (e.g., 20-1024) or leave blank for common ports: ").strip()
        if port_input:
            try:
                start, end = map(int, port_input.split("-"))
                ports = list(range(start, end + 1))
                print(f"Scanning ports {start}-{end} ({len(ports)} ports)")
            except Exception:
                log_error("Invalid input. Scanning common ports instead.")
                ports = list(self.common_ports.keys())
        else:
            ports = list(self.common_ports.keys())
            print("Scanning common ports")

        threads = []
        max_threads = 50

        print(f"Starting scan with {max_threads} threads...")
        
        for port in ports:
            t = Thread(target=self.scan_port, args=(target, port))
            threads.append(t)
            t.start()
            
            if len(threads) >= max_threads:
                for thread in threads:
                    thread.join()
                threads = []

        for thread in threads:
            thread.join()

        print(f"\nHost is up")
        closed_count = len(ports) - len(self.open_ports)
        print(f"Not shown: {closed_count} closed tcp ports\n")

        if self.open_ports:
            print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}{'VERSION'}")
            print("-" * 60)
            for port, service, banner in sorted(self.open_ports):
                print(f"{str(port)}/tcp".ljust(10) + "open".ljust(10) + service.ljust(15) + banner)
        else:
            print("No open ports found")

        end_time = datetime.now()
        duration = end_time - start_time
        print(f"\nScan finished at {end_time} (Duration: {duration})")
        log_info(f"Scan finished on {target}")
        log_info(f"Open ports: {self.open_ports}")

scanner = PortScanner()
