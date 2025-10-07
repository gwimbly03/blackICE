import socket
from datetime import datetime
from threading import Thread, Lock

from core.logger import log_info, log_error

COMMON_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 3389: "ms-wbt-server",
    3306: "mysql", 1433: "mssql", 1521: "oracle-db", 5900: "vnc",
    8080: "http-proxy"
}

open_ports = []
lock = Lock()

# ---------------------- BANNER GRABBING ----------------------

def grab_rdp_version(target, port=3389):
    """
    Improved RDP handshake to extract version
    """
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((target, port))
        
        # More complete RDP connection request
        request = bytes.fromhex('030000130ee000000000000100080000000000')
        sock.sendall(request)
        response = sock.recv(1024)
        sock.close()
        
        if len(response) >= 19:
            # Parse RDP negotiation response
            if response[0] == 0x03 and response[1] == 0x00:
                version_byte = response[2]  # This indicates the RDP version
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

def grab_ssh_banner(sock):
    """Grab SSH banner"""
    try:
        banner = sock.recv(1024).decode(errors='ignore').strip()
        return banner
    except:
        return "SSH (no banner received)"

def grab_http_banner(sock, port, service):
    """Grab HTTP/HTTPS banner"""
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

def grab_ftp_banner(sock):
    """Grab FTP banner"""
    try:
        banner = sock.recv(1024).decode(errors='ignore').strip()
        return banner
    except:
        return "FTP (no banner)"

def grab_smtp_banner(sock):
    """Grab SMTP banner"""
    try:
        banner = sock.recv(1024).decode(errors='ignore').strip()
        # Send EHLO for more info
        sock.sendall(b"EHLO example.com\r\n")
        response = sock.recv(1024).decode(errors='ignore').strip()
        return f"{banner} | {response.split(chr(10))[0]}"
    except:
        return "SMTP (no banner)"

def grab_mysql_banner(sock):
    """Grab MySQL banner"""
    try:
        banner = sock.recv(1024).decode(errors='ignore').strip()
        return banner
    except:
        return "MySQL (no banner)"

def grab_generic_banner(sock):
    """Generic banner grab for other services"""
    try:
        sock.settimeout(2)
        banner = sock.recv(1024).decode(errors='ignore').strip()
        return banner if banner else "no banner"
    except:
        return "no banner"

def grab_banner(target, port, service):
    """
    Improved banner grabbing with service-specific handling
    """
    try:
        sock = socket.socket()
        sock.settimeout(3)  # Increased timeout for banner grabbing
        sock.connect((target, port))
        
        # Service-specific banner grabbing
        if service == "ms-wbt-server":
            sock.close()
            return grab_rdp_version(target, port)
        elif service == "ssh":
            banner = grab_ssh_banner(sock)
        elif service in ["http", "https", "http-proxy"]:
            banner = grab_http_banner(sock, port, service)
        elif service == "ftp":
            banner = grab_ftp_banner(sock)
        elif service == "smtp":
            banner = grab_smtp_banner(sock)
        elif service == "mysql":
            banner = grab_mysql_banner(sock)
        else:
            banner = grab_generic_banner(sock)
        
        sock.close()
        
        # Clean up the banner
        if banner and banner != "no banner":
            # Remove extra whitespace and limit length
            banner = ' '.join(banner.split())[:100]  # Limit to 100 chars
        return banner if banner else "no banner"
        
    except Exception as e:
        return f"error: {str(e)}"

# ---------------------- PORT SCAN FUNCTION ----------------------

def scan_port(target, port):
    """Threaded scan for a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Increased timeout for connect
        result = sock.connect_ex((target, port))
        service = COMMON_PORTS.get(port, "unknown")
        
        if result == 0:
            # Only grab banner for open ports
            banner = grab_banner(target, port, service)
            with lock:
                open_ports.append((port, service, banner))
            log_info(f"Port {port}/{service} is open - Banner: {banner}")
        else:
            log_info(f"Port {port}/{service} is closed")
            
        sock.close()
    except Exception as e:
        log_error(f"Error scanning port {port}: {e}")

# ---------------------- MAIN RUN FUNCTION ----------------------

def run(target):
    global open_ports
    open_ports = []  # Reset for each run
    
    start_time = datetime.now()
    print(f"\nStarting BlackICE TCP Scan at {start_time}")
    print(f"Scan report for {target}")

    # Interactive port range
    port_input = input("Enter port range (e.g., 20-1024) or leave blank for common ports: ").strip()
    if port_input:
        try:
            start, end = map(int, port_input.split("-"))
            ports = list(range(start, end + 1))
            print(f"Scanning ports {start}-{end} ({len(ports)} ports)")
        except Exception:
            log_error("Invalid input. Scanning common ports instead.")
            ports = list(COMMON_PORTS.keys())
    else:
        ports = list(COMMON_PORTS.keys())
        print("Scanning common ports")

    threads = []
    max_threads = 50  

    print(f"Starting scan with {max_threads} threads...")
    
    for port in ports:
        t = Thread(target=scan_port, args=(target, port))
        threads.append(t)
        t.start()
        
        # Manage threads to avoid too many concurrent connections
        if len(threads) >= max_threads:
            for thread in threads:
                thread.join()
            threads = []

    # Wait for remaining threads
    for thread in threads:
        thread.join()

    # ---------------------- DISPLAY RESULTS ----------------------
    print(f"\nHost is up")
    closed_count = len(ports) - len(open_ports)
    print(f"Not shown: {closed_count} closed tcp ports\n")

    if open_ports:
        print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}{'VERSION'}")
        print("-" * 60)
        for port, service, banner in sorted(open_ports):
            print(f"{str(port)}/tcp".ljust(10) + "open".ljust(10) + service.ljust(15) + banner)
    else:
        print("No open ports found")

    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\nScan finished at {end_time} (Duration: {duration})")
    log_info(f"Scan finished on {target}")
    log_info(f"Open ports: {open_ports}")
