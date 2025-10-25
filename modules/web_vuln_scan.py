import requests
import json
import time
from urllib.parse import urljoin, quote
from core.logger import logger

# Disable SSL warnings for testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebVulnerabilityScanner:
    """
    OWASP Top 10 Web Application Vulnerability Scanner
    """
    
    description = "Scans for OWASP Top 10 web vulnerabilities (SQLi, XSS, CSRF, etc.)"
    
    def __init__(self):
        self.results = {}
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for testing
        
        # OWASP Top 10 2021 categories
        self.owasp_categories = {
            'a01': 'Broken Access Control',
            'a02': 'Cryptographic Failures', 
            'a03': 'Injection',
            'a05': 'Security Misconfiguration',
            'a07': 'Identification and Authentication Failures',
            'a10': 'Server-Side Request Forgery'
        }

    def run(self):
        """Main execution method"""
        target_url = input("Enter target URL (e.g., https://example.com): ").strip()
        
        if not target_url:
            print("No target URL specified. Exiting.")
            return
            
        # Ensure URL has scheme
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
            
        # Log module start
        logger.log_module_start("web_vuln_scan", target_url)
        
        print(f"\nStarting OWASP Top 10 scan for: {target_url}")
        print("=" * 60)
        
        try:
            # First, verify the target is accessible
            if not self.verify_target(target_url):
                print(f"Target {target_url} is not accessible. Exiting.")
                return
                
            self.scan_web_application(target_url)
            self.display_results()
            
            # Prepare results for logging
            result = {
                "status": "completed",
                "target_url": target_url,
                "vulnerabilities_found": len(self.vulnerabilities),
                "owasp_categories_checked": list(self.owasp_categories.keys()),
                "vulnerabilities": self.vulnerabilities,
                "summary": {
                    "total_vulnerabilities": len(self.vulnerabilities),
                    "critical_count": len([v for v in self.vulnerabilities if v['severity'] == 'Critical']),
                    "high_count": len([v for v in self.vulnerabilities if v['severity'] == 'High']),
                    "medium_count": len([v for v in self.vulnerabilities if v['severity'] == 'Medium']),
                    "low_count": len([v for v in self.vulnerabilities if v['severity'] == 'Low'])
                }
            }
            
            # Log the results
            logger.log_module_result("web_vuln_scan", target_url, result)
            
            print(f"\nWeb vulnerability scan completed. Results have been logged.")
            
        except Exception as e:
            error_result = {
                "status": "error", 
                "error": str(e)
            }
            logger.log_module_result("web_vuln_scan", target_url, error_result)
            print(f"Error during web vulnerability scan: {e}")

    def verify_target(self, target_url: str) -> bool:
        """Verify the target is accessible and identify the web server"""
        try:
            response = self.session.get(target_url, timeout=10)
            self.results['server_info'] = {
                'status_code': response.status_code,
                'server_header': response.headers.get('Server', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown')
            }
            print(f"Target is accessible (Status: {response.status_code})")
            print(f"Server: {response.headers.get('Server', 'Unknown')}")
            return True
        except Exception as e:
            print(f"Target verification failed: {e}")
            return False

    def scan_web_application(self, target_url: str):
        """Perform comprehensive OWASP Top 10 scanning"""
        self.results = {
            'target_url': target_url,
            'scan_time': time.time(),
            'vulnerabilities': []
        }
        
        print("\nScanning for OWASP Top 10 vulnerabilities...")
        
        # Test each OWASP category
        self.test_broken_access_control(target_url)
        self.test_cryptographic_failures(target_url)
        self.test_injection_vulnerabilities(target_url)
        self.test_security_misconfiguration(target_url)
        self.test_authentication_failures(target_url)
        self.test_ssrf_vulnerabilities(target_url)

    def test_broken_access_control(self, target_url: str):
        """A01: Broken Access Control - Improved testing"""
        print("Testing Broken Access Control...")
        
        # Test for information disclosure in error messages
        test_params = {
            'id': '-1',
            'user': 'nonexistentuser123',
            'page': '../../../etc/passwd'
        }
        
        for param, value in test_params.items():
            test_url = f"{target_url}?{param}={quote(value)}"
            try:
                response = self.session.get(test_url, timeout=5)
                
                # Check for information disclosure in errors
                error_indicators = [
                    'error in', 'exception', 'stack trace', 'sql', 'mysql',
                    'postgresql', 'oracle', 'microsoft', 'odbc', 'syntax'
                ]
                
                if any(indicator in response.text.lower() for indicator in error_indicators):
                    self.add_vulnerability(
                        'A01', 'Broken Access Control', 'Medium',
                        f'Information disclosure in parameter: {param}',
                        'Detailed error messages revealed sensitive information',
                        'Implement proper error handling without information disclosure'
                    )
                    break
                    
            except Exception as e:
                pass

    def test_cryptographic_failures(self, target_url: str):
        """A02: Cryptographic Failures - Improved testing"""
        print("Testing Cryptographic Failures...")
        
        # Check if HTTPS is available but not enforced
        if target_url.startswith('http://'):
            http_response = self.session.get(target_url, timeout=5)
            https_url = target_url.replace('http://', 'https://')
            
            try:
                https_response = self.session.get(https_url, timeout=5)
                if https_response.status_code == 200:
                    self.add_vulnerability(
                        'A02', 'Cryptographic Failures', 'Medium',
                        'HTTPS available but not enforced',
                        'Website supports HTTPS but allows HTTP access',
                        'Implement HTTP to HTTPS redirect and HSTS'
                    )
            except:
                pass
        
        # Check for mixed content issues
        try:
            response = self.session.get(target_url, timeout=5)
            if 'http://' in response.text and target_url.startswith('https://'):
                self.add_vulnerability(
                    'A02', 'Cryptographic Failures', 'Low',
                    'Mixed content detected',
                    'HTTP resources loaded on HTTPS page',
                    'Ensure all resources are loaded over HTTPS'
                )
        except:
            pass

    def test_injection_vulnerabilities(self, target_url: str):
        """A03: Injection - More sophisticated testing"""
        print("Testing Injection Vulnerabilities...")
        
        # More realistic SQL injection payloads
        sql_payloads = [
            "'", 
            "1' OR '1'='1'--",
            "1' AND 1=1--",
            "1' UNION SELECT null--"
        ]
        
        # Test parameters that are likely to be vulnerable
        test_params = ['id', 'product', 'category', 'user_id', 'article']
        
        for param in test_params:
            for payload in sql_payloads:
                test_url = f"{target_url}?{param}={quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=5)
                    original_response = self.session.get(f"{target_url}?{param}=1", timeout=5)
                    
                    # Check for differences that indicate potential SQL injection
                    if (response.status_code != original_response.status_code or
                        len(response.text) != len(original_response.text) or
                        "sql" in response.text.lower() or "mysql" in response.text.lower()):
                        self.add_vulnerability(
                            'A03', 'Injection', 'High',
                            f'Potential SQL Injection in parameter: {param}',
                            f'Different response with SQL payload: {payload}',
                            'Use parameterized queries and input validation'
                        )
                        break
                except:
                    pass

        # Improved XSS testing
        xss_payloads = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "\" onmouseover=\"alert(1)"
        ]
        
        search_params = ['q', 'search', 'query', 's']
        
        for param in search_params:
            for payload in xss_payloads:
                test_url = f"{target_url}?{param}={quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=5)
                    # Check if payload is reflected without proper encoding
                    if payload in response.text and '<script>' not in response.text:
                        # Payload is reflected but might be encoded - check context
                        if any(ctx in response.text for ctx in ['<', '>', '"', "'"]):
                            self.add_vulnerability(
                                'A03', 'Injection', 'Medium',
                                f'Potential XSS in parameter: {param}',
                                f'User input reflected without proper encoding',
                                'Implement proper output encoding and Content Security Policy'
                            )
                            break
                except:
                    pass

    def test_security_misconfiguration(self, target_url: str):
        """A05: Security Misconfiguration - More accurate testing"""
        print("Testing Security Misconfiguration...")
        
        # Check for really sensitive files (not just existence, but content)
        sensitive_files = {
            '.env': ['database', 'password', 'secret'],
            'config.php': ['password', 'secret', 'api_key'],
            'web.config': ['connectionString', 'password'],
            '.git/config': '[core]',
            'phpinfo.php': 'phpinfo'
        }
        
        for file, indicators in sensitive_files.items():
            test_url = urljoin(target_url, file)
            try:
                response = self.session.get(test_url, timeout=3)
                if response.status_code == 200:
                    # Check if the file actually contains sensitive content
                    if isinstance(indicators, list):
                        if any(indicator in response.text.lower() for indicator in indicators):
                            self.add_vulnerability(
                                'A05', 'Security Misconfiguration', 'High',
                                f'Exposed sensitive file with credentials: {file}',
                                'Configuration file with sensitive data accessible',
                                'Restrict access to configuration files and remove from web root'
                            )
                    elif indicators in response.text:
                        self.add_vulnerability(
                            'A05', 'Security Misconfiguration', 'Medium',
                            f'Exposed sensitive file: {file}',
                            'Sensitive file accessible via web',
                            'Restrict access to sensitive files'
                        )
            except:
                pass
        
        # Check security headers more thoroughly
        try:
            response = self.session.get(target_url, timeout=5)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': {'required': True, 'severity': 'Low'},
                'X-Content-Type-Options': {'required': True, 'severity': 'Low'},
                'Strict-Transport-Security': {'required': target_url.startswith('https://'), 'severity': 'Medium'},
                'Content-Security-Policy': {'required': False, 'severity': 'Low'}
            }
            
            for header, config in security_headers.items():
                if config['required'] and header not in headers:
                    self.add_vulnerability(
                        'A05', 'Security Misconfiguration', config['severity'],
                        f'Missing security header: {header}',
                        f'Recommended security header not implemented',
                        f'Implement {header} security header'
                    )
        except:
            pass

    def test_authentication_failures(self, target_url: str):
        """A07: Identification and Authentication Failures - More realistic testing"""
        print("Testing Authentication Failures...")
        
        # Only report admin pages if they actually look like login interfaces
        admin_pages = [
            'admin', 'login', 'wp-admin', 'administrator',
            'cpanel', 'webmail', 'phpmyadmin'
        ]
        
        for page in admin_pages:
            test_url = urljoin(target_url, page)
            try:
                response = self.session.get(test_url, timeout=3)
                if response.status_code == 200:
                    # Check if it actually looks like a login page
                    page_content = response.text.lower()
                    login_indicators = ['password', 'username', 'login', 'sign in', 'form']
                    
                    if any(indicator in page_content for indicator in login_indicators):
                        self.add_vulnerability(
                            'A07', 'Authentication Failures', 'Low',
                            f'Login interface exposed: {page}',
                            'Authentication interface accessible without restrictions',
                            'Implement rate limiting and strong authentication controls'
                        )
            except:
                pass

    def test_ssrf_vulnerabilities(self, target_url: str):
        """A10: Server-Side Request Forgery - More realistic testing"""
        print("Testing SSRF Vulnerabilities...")
        
        # Test for potential SSRF with internal IPs
        ssrf_params = ['url', 'image', 'file', 'path', 'redirect']
        internal_ips = [
            'http://127.0.0.1:80',
            'http://localhost',
            'http://169.254.169.254/latest/meta-data/'
        ]
        
        for param in ssrf_params:
            for internal_ip in internal_ips:
                test_url = f"{target_url}?{param}={quote(internal_ip)}"
                try:
                    response = self.session.get(test_url, timeout=5)
                    # Check for timeouts or different responses that might indicate SSRF
                    if response.status_code in [200, 302, 307]:
                        # Check if the response suggests internal access
                        if any(indicator in response.text for indicator in ['instance', 'metadata', 'localhost']):
                            self.add_vulnerability(
                                'A10', 'SSRF', 'High',
                                f'Potential SSRF vulnerability in parameter: {param}',
                                f'Able to make requests to internal resources: {internal_ip}',
                                'Validate and sanitize all user-supplied URLs'
                            )
                            break
                except:
                    pass

    def add_vulnerability(self, category: str, name: str, severity: str, 
                         title: str, description: str, remediation: str):
        """Add a vulnerability to results - only if not already reported"""
        # Check if similar vulnerability already reported
        for existing_vuln in self.vulnerabilities:
            if (existing_vuln['category'] == category and 
                existing_vuln['title'] == title):
                return
        
        vulnerability = {
            'category': category,
            'name': name,
            'severity': severity,
            'title': title,
            'description': description,
            'remediation': remediation,
            'timestamp': time.time()
        }
        
        self.vulnerabilities.append(vulnerability)
        print(f"  Found: {title}")

    def display_results(self):
        """Display scan results"""
        print(f"\n{'='*80}")
        print(f"OWASP TOP 10 SCAN RESULTS")
        print(f"{'='*80}")
        print(f"Target: {self.results['target_url']}")
        print(f"Vulnerabilities Found: {len(self.vulnerabilities)}")
        
        if not self.vulnerabilities:
            print("\n✅ No significant vulnerabilities found!")
            print("Note: This is a basic scanner. Manual testing is recommended for comprehensive assessment.")
            return
            
        # Group by severity
        by_severity = {}
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)
        
        # Display by severity
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if severity in by_severity:
                print(f"\n{severity.upper()} SEVERITY ({len(by_severity[severity])}):")
                print("-" * 40)
                
                for vuln in by_severity[severity]:
                    print(f"[{vuln['category']}] {vuln['title']}")
                    print(f"   Description: {vuln['description']}")
                    print(f"   Remediation: {vuln['remediation']}")
                    print()

# Create module instance
web_vuln_scanner = WebVulnerabilityScanner()
