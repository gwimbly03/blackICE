### I am gonna change this so that instead of doing a port scan here i can just use the port scan class that I have made. For now this was a quick implemenation of this.


import socket
import requests
import subprocess
import re
from typing import Dict, List, Any
from datetime import datetime
import json

class VulnerabilityScanner:
    description = "Vulnerability Scanner checks for common services and vulnerability checks them"
    
    def __init__(self):
        self.results = {}
        self.vulnerabilities = []
        
        self.vuln_checks = {
            'ftp': self.check_ftp_vulnerabilities,
            'ssh': self.check_ssh_vulnerabilities,
            'http': self.check_http_vulnerabilities,
            'smb': self.check_smb_vulnerabilities,
            'mysql': self.check_mysql_vulnerabilities,
            'rdp': self.check_rdp_vulnerabilities
        }

    def run(self):
        target = input("Enter target IP or hostname: ").strip()
        
        if not target:
            print("No target specified. Exiting.")
            return
            
        print(f"\nStarting vulnerability scan for: {target}")
        print("=" * 50)
        
        try:
            open_ports = self.port_scan(target)
            
            if not open_ports:
                print("No open ports found. Cannot perform vulnerability scan.")
                return
                
            print(f"Found {len(open_ports)} open ports. Starting vulnerability checks...")
            
            self.scan_vulnerabilities(target, open_ports)
            self.display_results()
            
            export = input("\nExport results to JSON? (y/n): ").lower()
            if export in ('y', 'yes'):
                self.export_results()
                
        except Exception as e:
            print(f"Error during vulnerability scan: {e}")

    def port_scan(self, target: str) -> Dict[str, List[int]]:
        #this is for the common port. this wont work it a service is running on another port other then default ex: if mysql is on 3307 instead of 3306 then it wont work
        common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 139: 'netbios', 143: 'imap', 
            443: 'https', 445: 'smb', 993: 'imaps', 995: 'pop3s',
            1433: 'mssql', 1521: 'oracle', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgres', 5900: 'vnc', 6379: 'redis'
        }
        
        open_ports = {}
        print("Performing quick port scan...")
        
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    if service not in open_ports:
                        open_ports[service] = []
                    open_ports[service].append(port)
                    print(f"  Found: {service} on port {port}")
                sock.close()
            except:
                pass
                
        return open_ports

    def scan_vulnerabilities(self, target: str, open_ports: Dict[str, List[int]]):
        self.results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'open_services': open_ports,
            'vulnerabilities_found': 0,
            'vulnerabilities': []
        }
        
        # this runs individual checks for all the services
        for service, ports in open_ports.items():
            if service in self.vuln_checks:
                print(f"Checking {service} for vulnerabilities...")
                self.vuln_checks[service](target, ports[0])  

    def check_ftp_vulnerabilities(self, target: str, port: int):
        try:
            # checking for anonymous FTP access and login
            sock = socket.socket()
            sock.settimeout(3)
            sock.connect((target, port))
            banner = sock.recv(1024).decode(errors='ignore')
            
            sock.send(b"USER anonymous\r\n")
            response = sock.recv(1024).decode(errors='ignore')
            
            if "331" in response:  
                sock.send(b"PASS anonymous\r\n")
                response = sock.recv(1024).decode(errors='ignore')
                if "230" in response:  
                    self.add_vulnerability(
                        'FTP_ANONYMOUS_ACCESS',
                        'High',
                        f'FTP anonymous access allowed on {target}:{port}',
                        'Attackers can access files without authentication',
                        'Disable anonymous FTP access'
                    )
            
            sock.close()
            
        except Exception as e:
            pass

    def check_ssh_vulnerabilities(self, target: str, port: int):
        """Check SSH service for common vulnerabilities"""
        try:
            sock = socket.socket()
            sock.settimeout(3)
            sock.connect((target, port))
            banner = sock.recv(1024).decode(errors='ignore')
            
            if 'SSH-1.99' in banner or 'SSH-1.5' in banner:
                self.add_vulnerability(
                    'SSH_VERSION_OLD',
                    'Medium',
                    f'Old SSH version detected on {target}:{port}',
                    banner.strip(),
                    'Upgrade to SSH version 2.0'
                )
            
            weak_algos = ['arcfour', 'des', '3des']
            for algo in weak_algos:
                if algo in banner.lower():
                    self.add_vulnerability(
                        'SSH_WEAK_ALGORITHM',
                        'Medium',
                        f'Weak SSH algorithm detected: {algo}',
                        'Weak encryption algorithm in use',
                        'Disable weak algorithms in SSH configuration'
                    )
            
            sock.close()
            
        except Exception as e:
            pass

    #this will check nginx and apache
    def check_http_vulnerabilities(self, target: str, port: int):
        schemes = ['https', 'http'] if port == 443 else ['http']
        
        for scheme in schemes:
            url = f"{scheme}://{target}:{port}"
            
            try:
                test_url = f"{url}/"
                response = requests.get(test_url, timeout=5, verify=False)
                
                if "Index of /" in response.text or "<title>Directory listing for /" in response.text:
                    self.add_vulnerability(
                        'HTTP_DIRECTORY_LISTING',
                        'Medium',
                        f'Directory listing enabled on {url}',
                        'Sensitive files and directories are exposed',
                        'Disable directory listing in web server configuration'
                    )
                
                sensitive_files = [
                    '/.git/HEAD', '/.env', '/backup.zip', '/wp-config.php',
                    '/config.php', '/.htaccess', '/web.config'
                ]
                
                for file_path in sensitive_files:
                    file_url = f"{url}{file_path}"
                    try:
                        file_response = requests.get(file_url, timeout=3, verify=False)
                        if file_response.status_code == 200:
                            self.add_vulnerability(
                                'SENSITIVE_FILE_EXPOSED',
                                'High',
                                f'Sensitive file exposed: {file_url}',
                                'Configuration or backup files accessible',
                                'Restrict access to sensitive files'
                            )
                    except:
                        pass
                
            
                security_headers = [
                    'X-Frame-Options', 'X-Content-Type-Options',
                    'Strict-Transport-Security', 'Content-Security-Policy'
                ]
                
                missing_headers = []
                for header in security_headers:
                    if header not in response.headers:
                        missing_headers.append(header)
                
                if missing_headers:
                    self.add_vulnerability(
                        'MISSING_SECURITY_HEADERS',
                        'Low',
                        f'Missing security headers on {url}',
                        f'Missing: {", ".join(missing_headers)}',
                        'Implement proper security headers'
                    )
                
                
                default_indicators = [
                    'Apache', 'IIS', 'nginx', 'Welcome to nginx',
                    'IIS Windows', 'Test Page'
                ]
                
                for indicator in default_indicators:
                    if indicator in response.text:
                        self.add_vulnerability(
                            'DEFAULT_PAGE_EXPOSED',
                            'Low',
                            f'Default web server page on {url}',
                            'Default installation page reveals server information',
                            'Replace default pages with custom content'
                        )
                        break
                        
            except Exception as e:
                pass

    def check_smb_vulnerabilities(self, target: str, port: int):
        """Check SMB service for common vulnerabilities"""
        try:
            # this is a easier implementation of a SMB vuln scan, to extend this further I should look into impacket for future milestones
            self.add_vulnerability(
                'SMB_SIGNING_NOT_REQUIRED',
                'Medium',
                f'SMB signing may not be required on {target}:{port}',
                'SMB message signing not enforced',
                'Enable SMB signing in group policy'
            )
            
            # this checks for anonymous access
            try:
                result = subprocess.run(
                    ['smbclient', f'//{target}/IPC$', '-N', '-c', 'exit'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    self.add_vulnerability(
                        'SMB_ANONYMOUS_ACCESS',
                        'High',
                        f'SMB anonymous access allowed on {target}',
                        'Null session authentication permitted',
                        'Restrict anonymous SMB access'
                    )
            except:
                pass
                
        except Exception as e:
            pass

    def check_mysql_vulnerabilities(self, target: str, port: int):
        try:
            sock = socket.socket()
            sock.settimeout(3)
            sock.connect((target, port))
            banner = sock.recv(1024).decode(errors='ignore')
            
            version_match = re.search(r'(\d+\.\d+\.\d+)', banner)
            if version_match:
                version = version_match.group(1)
                major, minor, patch = map(int, version.split('.'))
                
                if major < 5 or (major == 5 and minor < 7):
                    self.add_vulnerability(
                        'MYSQL_OUTDATED_VERSION',
                        'High',
                        f'Outdated MySQL version {version} on {target}:{port}',
                        'Older versions may have known vulnerabilities',
                        'Upgrade to MySQL 5.7 or later'
                    )
            
            # here im checking for an empty root passwd s
            self.add_vulnerability(
                'MYSQL_WEAK_AUTH_CHECK',
                'Info',
                f'MySQL service detected on {target}:{port}',
                'Manual password strength testing recommended',
                'Ensure strong passwords and limit network access'
            )
            
            sock.close()
            
        except Exception as e:
            pass

    def check_rdp_vulnerabilities(self, target: str, port: int):
        try:
            sock = socket.socket()
            sock.settimeout(3)
            sock.connect((target, port))
            
            rdp_request = bytes.fromhex('030000130ee000000000000100080000000000')
            sock.send(rdp_request)
            response = sock.recv(1024)
            
            if len(response) > 0:
                self.add_vulnerability(
                    'RDP_EXPOSED',
                    'Medium',
                    f'RDP service exposed on {target}:{port}',
                    'RDP is a common attack vector',
                    'Use VPN, enable NLA, or restrict RDP access'
                )
            
            sock.close()
            
        except Exception as e:
            pass

    def add_vulnerability(self, vuln_id: str, severity: str, title: str, description: str, remediation: str):
        """Add a vulnerability to the results"""
        vulnerability = {
            'id': vuln_id,
            'severity': severity,
            'title': title,
            'description': description,
            'remediation': remediation,
            'timestamp': datetime.now().isoformat()
        }
        
        self.vulnerabilities.append(vulnerability)
        self.results['vulnerabilities_found'] += 1
        
        # Print finding immediately
        severity_color = {
            'Critical': '🔴',
            'High': '🟠', 
            'Medium': '🟡',
            'Low': '🔵',
            'Info': '⚪'
        }
        
        emoji = severity_color.get(severity, '⚪')
        print(f"  {emoji} [{severity}] {title}")

    def display_results(self):
        """Display vulnerability scan results"""
        print(f"\n{'='*60}")
        print(f"🔍 VULNERABILITY SCAN RESULTS")
        print(f"{'='*60}")
        print(f"Target: {self.results['target']}")
        print(f"Vulnerabilities Found: {self.results['vulnerabilities_found']}")
        
        if not self.vulnerabilities:
            print("\nNo vulnerabilities found!")
            return
            
        by_severity = {}
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)
        
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        
        for severity in severity_order:
            if severity in by_severity:
                print(f"\n{severity.upper()} SEVERITY ({len(by_severity[severity])}):")
                print("-" * 40)
                
                for vuln in by_severity[severity]:
                    print(f"   {vuln['title']}")
                    print(f"   Description: {vuln['description']}")
                    print(f"   Remediation: {vuln['remediation']}")
                    print()
        
        # Summary
        print(f"\nSUMMARY:")
        print("-" * 40)
        for severity in severity_order:
            if severity in by_severity:
                count = len(by_severity[severity])
                print(f"{severity}: {count}")
        
        print(f"\n{'='*60}")

    def export_results(self, filename: str = None):
        """Export results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_clean = self.results['target'].replace('.', '_')
            filename = f"vuln_scan_{target_clean}_{timestamp}.json"
        
        try:
            self.results['vulnerabilities'] = self.vulnerabilities
            
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"Results exported to: {filename}")
        except Exception as e:
            print(f"Error exporting results: {e}")

vuln_scan = VulnerabilityScanner()
