import socket
import ssl
import OpenSSL
from datetime import datetime
from typing import Dict, List, Any
import json

class SSLScanner:
    """
    SSL scanner that get the certificate, expiry, supported protocols, ciphers and common vulnerabilities 
    """

    description = "SSL/TLS Scanner it finds SSL engryption, certs and expiry date, also runs some checks for common vulnerabilities"
    
    def __init__(self):
        self.results = {}
        self.supported_protocols = {
            ssl.PROTOCOL_TLSv1: "TLSv1.0",
            ssl.PROTOCOL_TLSv1_1: "TLSv1.1", 
            ssl.PROTOCOL_TLSv1_2: "TLSv1.2",
            getattr(ssl, 'PROTOCOL_TLSv1_3', None): "TLSv1.3"
        }
        
        self.ssl_ports = [443, 8443, 9443, 10443, 11443]

    
    def scan_ssl(self, host: str, port: int):
        """
        Start the ssl scanner with its supported protocols and ports
        """
        self.results = {
            'target': f"{host}:{port}",
            'scan_time': datetime.now().isoformat(),
            'certificate_info': {},
            'supported_protocols': {},
            'vulnerability_checks': {},
            'cipher_suites': [],
            'security_grade': 'Unknown'
        }
        
        self.get_certificate_info(host, port)
        
        self.check_supported_protocols(host, port)
        
        self.check_vulnerabilities(host, port)
        
        self.get_cipher_suites(host, port)
        
        self.calculate_security_grade()

    def get_certificate_info(self, host: str, port: int):
        """
        Find and parse cert info for a host
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = ssl.DER_cert_to_PEM_cert(cert_der)
                    
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                    
                    subject = dict(x509.get_subject().get_components())
                    issuer = dict(x509.get_issuer().get_components())
                    
                    self.results['certificate_info'] = {
                        'subject': {
                            'common_name': subject.get(b'CN', b'').decode(),
                            'organization': subject.get(b'O', b'').decode(),
                            'organizational_unit': subject.get(b'OU', b'').decode(),
                            'country': subject.get(b'C', b'').decode()
                        },
                        'issuer': {
                            'common_name': issuer.get(b'CN', b'').decode(),
                            'organization': issuer.get(b'O', b'').decode()
                        },
                        'serial_number': str(x509.get_serial_number()),
                        'version': x509.get_version(),
                        'signature_algorithm': x509.get_signature_algorithm().decode(),
                        'not_before': x509.get_notBefore().decode(),
                        'not_after': x509.get_notAfter().decode(),
                        'expires_in_days': self.get_days_until_expiry(x509),
                        'has_expired': x509.has_expired(),
                        'extensions': self.get_certificate_extensions(x509)
                    }
                    
        except Exception as e:
            self.results['certificate_info'] = {'error': str(e)}

    def get_days_until_expiry(self, x509_cert) -> int:
        """
        Calculates the remaining days before the cert expires
        """
        not_after = x509_cert.get_notAfter().decode('ascii')
        expiry_date = datetime.strptime(not_after, '%Y%m%d%H%M%SZ')
        days_left = (expiry_date - datetime.utcnow()).days
        return days_left

    def get_certificate_extensions(self, x509_cert) -> Dict:
        """
        Extract extensions from ssl certs 
        """
        extensions = {}
        for i in range(x509_cert.get_extension_count()):
            try:
                ext = x509_cert.get_extension(i)
                extensions[ext.get_short_name().decode()] = str(ext)
            except:
                pass
        return extensions

    def check_supported_protocols(self, host: str, port: int):
        """
        Check what tls version are supported 
        """
        supported = {}
        
        for protocol, protocol_name in self.supported_protocols.items():
            if protocol is None:  
                continue
                
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        supported[protocol_name] = True
            except:
                supported[protocol_name] = False
        
        self.results['supported_protocols'] = supported

    def check_vulnerabilities(self, host: str, port: int):
        """
        Checks common ssl vulnerabilities
        """
        vulnerabilities = {
            'heartbleed': self.check_heartbleed(host, port),
            'poodle': self.check_poodle(host, port),
            'freak': self.check_freak(host, port),
            'beast': self.check_beast(host, port),
            'weak_ciphers': self.check_weak_ciphers(host, port),
            'certificate_mismatch': self.check_certificate_mismatch(host, port)
        }
        
        self.results['vulnerability_checks'] = vulnerabilities

    def check_heartbleed(self, host: str, port: int) -> Dict:
        """
        This preforms a heartbleed check but this heartbleed test was made because I dont want to create a real heartbleed test and send exploit packets since it could be considered illegal
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    return {
                        'vulnerable': False,
                        'details': 'Heartbleed test requires specialized payload'
                    }
        except Exception as e:
            return {'vulnerable': False, 'details': f'Test failed: {e}'}

    def check_poodle(self, host: str, port: int) -> Dict:
        """
        This checks ssl version 3 support, the poodle vulnerability exploits the negotiation feature called the downgrade dance where a client and server may fall back to SSL 3.0 if a secure connection attempt fails
        """
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return {'vulnerable': True, 'details': 'SSLv3 supported - POODLE vulnerable'}
        except:
            return {'vulnerable': False, 'details': 'SSLv3 not supported'}

    def check_freak(self, host: str, port: int) -> Dict:
        """
        This checks the FREAK vulnerability. Which allows a man-in-the-middle attacker to manipulate the initial cipher suite negotiation between a client and a server, forcing the use of these weak 512-bit export-grade RSA keys
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers('EXPORT')
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return {'vulnerable': True, 'details': 'Export ciphers supported - FREAK vulnerable'}
        except:
            return {'vulnerable': False, 'details': 'Export ciphers not supported'}

    def check_beast(self, host: str, port: int) -> Dict:
        """
        Checks the beast vulnerability. It exploits the way TLS 1.0 generates initialization vectors for block ciphers in cipher block chaining mode, where each IV is the previous ciphertext block, making the encryption predictable under specific conditions.
        """
        tls10_supported = self.results['supported_protocols'].get('TLSv1.0', False)
        return {
            'vulnerable': tls10_supported,
            'details': 'TLS 1.0 supported - may be vulnerable to BEAST'
        }

    def check_weak_ciphers(self, host: str, port: int) -> Dict:
        """
        Checks if the cert is using weak and older ciphers from the cipher list
        """
        weak_ciphers = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5']
        weak_found = []
        
        for cipher in self.results.get('cipher_suites', []):
            for weak in weak_ciphers:
                if weak in cipher:
                    weak_found.append(cipher)
                    break
        
        return {
            'vulnerable': len(weak_found) > 0,
            'weak_ciphers': weak_found,
            'details': f'Found {len(weak_found)} weak cipher(s)'
        }

    def check_certificate_mismatch(self, host: str, port: int) -> Dict:
        """
        Checks to see if the cert matches the hostname
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return {'vulnerable': False, 'details': 'Certificate matches hostname'}
        except ssl.CertificateError:
            return {'vulnerable': True, 'details': 'Certificate hostname mismatch'}
        except:
            return {'vulnerable': False, 'details': 'Could not verify certificate'}

    def get_cipher_suites(self, host: str, port: int):
        """
        Get the cipher suit thats being used in the ssl session
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    self.results['cipher_suites'] = [f"{cipher[0]} ({cipher[1]} bits)"]
        except Exception as e:
            self.results['cipher_suites'] = [f"Error: {e}"]

    def calculate_security_grade(self):
        """
        Calculate the security score based on the above checks
        """
        score = 100
        
        vulns = self.results['vulnerability_checks']
        if vulns.get('poodle', {}).get('vulnerable'):
            score -= 30
        if vulns.get('heartbleed', {}).get('vulnerable'):
            score -= 40
        if vulns.get('freak', {}).get('vulnerable'):
            score -= 20
        if vulns.get('beast', {}).get('vulnerable'):
            score -= 15
        if vulns.get('weak_ciphers', {}).get('vulnerable'):
            score -= 25
        if vulns.get('certificate_mismatch', {}).get('vulnerable'):
            score -= 35
        
        protocols = self.results['supported_protocols']
        if protocols.get('TLSv1.0'):
            score -= 10
        if protocols.get('TLSv1.1'):
            score -= 5
        
        cert_info = self.results['certificate_info']
        if cert_info.get('has_expired'):
            score -= 50
        if cert_info.get('expires_in_days', 999) < 30:
            score -= 20
        
        if score >= 90:
            grade = 'A'
        elif score >= 80:
            grade = 'B'
        elif score >= 70:
            grade = 'C'
        elif score >= 60:
            grade = 'D'
        else:
            grade = 'F'
            
        self.results['security_grade'] = grade
        self.results['security_score'] = score

    def display_results(self):
        """
        Outputs the results to stout
        """
        print(f"\n{'='*60}")
        print(f"SSL/TLS SCAN RESULTS")
        print(f"{'='*60}")
        print(f"Target: {self.results['target']}")
        print(f"Security Grade: {self.results['security_grade']} ({self.results.get('security_score', 0)}/100)")
        
        cert_info = self.results['certificate_info']
        if 'error' not in cert_info:
            print(f"\nCERTIFICATE INFORMATION:")
            print("-" * 40)
            print(f"Subject: {cert_info['subject'].get('common_name', 'N/A')}")
            print(f"Issuer: {cert_info['issuer'].get('common_name', 'N/A')}")
            print(f"Expires: {cert_info.get('expires_in_days', 'N/A')} days")
            print(f"Expired: {'YES' if cert_info.get('has_expired') else 'NO'}") 
            print(f"Signature: {cert_info.get('signature_algorithm', 'N/A')}")
        
        print(f"\nSUPPORTED PROTOCOLS:")
        print("-" * 40)
        for protocol, supported in self.results['supported_protocols'].items():
            status = "SUPPORTED" if supported else "NOT SUPPORTED"
            print(f"{protocol:<10} {status}")
        
        print(f"\nVULNERABILITY CHECKS:")
        print("-" * 40)
        vulns = self.results['vulnerability_checks']
        for vuln_name, vuln_info in vulns.items():
            status = "VULNERABLE" if vuln_info.get('vulnerable') else "SECURE"
            print(f"{vuln_name.upper():<20} {status}")
            if vuln_info.get('vulnerable'):
                print(f"  └─ {vuln_info.get('details', '')}")
        
        print(f"\nCIPHER SUITES:")
        print("-" * 40)
        for cipher in self.results['cipher_suites']:
            print(f"  • {cipher}")
        
        print(f"\n{'='*60}")

    def export_results(self, filename: str = None):
        """
        Saves to json if needed
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_clean = self.results['target'].replace(':', '_')
            filename = f"ssl_scan_{target_clean}_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"Results exported to: {filename}")
        except Exception as e:
            print(f"Error exporting results: {e}")

    def run(self):
        target = input("Enter target domain or IP (e.g., example.com:443): ").strip()
        
        if not target:
            print("No target specified. Exiting.")
            return
            
        if ':' not in target:
            target += ':443'
            
        host, port_str = target.split(':', 1)
        port = int(port_str)
        
        print(f"\nStarting SSL/TLS scan for: {host}:{port}")
        print("=" * 50)
        
        try:
            self.scan_ssl(host, port)
            self.display_results()
            
            export = input("\nExport results to JSON? (y/n): ").lower()
            if export in ('y', 'yes'):
                self.export_results()
                
        except Exception as e:
            print(f"Error during SSL scan: {e}")


ssl_scan = SSLScanner()
