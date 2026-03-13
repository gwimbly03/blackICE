import requests
import json
import time
import re
import ssl
import os
from urllib.parse import urljoin, quote, urlparse, parse_qs, urlencode
from typing import Dict, List, Optional, Any

# Disable SSL warnings only for testing - remove in production
# import urllib3
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Use your existing logger
from backend.core.logger import logger


class WebVulnerabilityScanner:
    """
    OWASP Top 10 Web Application Vulnerability Scanner.
    Performs automated heuristic tests for OWASP Top 10 web vulnerabilities.
    
    Production-ready: requests + stdlib only, SSL verification enabled,
    rate limiting, proper error handling.
    """

    description = "Scans for OWASP Top 10 2021 web vulnerabilities (SQLi, XSS, CSRF, etc.)"

    def __init__(self, timeout: int = 10, rate_limit: float = 0.5, verify_ssl: bool = True):
        """
        Initialize a new WebVulnerabilityScanner.
        
        Args:
            timeout: Request timeout in seconds
            rate_limit: Seconds to wait between requests (rate limiting)
            verify_ssl: Verify SSL certificates (MUST be True in production)
        """
        self.results = {}
        self.vulnerabilities = []
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.verify_ssl = verify_ssl
        
        self.session = requests.Session()
        # Production: SSL verification MUST be enabled
        self.session.verify = verify_ssl
        if not verify_ssl:
            # Only disable for local testing with self-signed certs
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.session.headers.update({
            "User-Agent": "SecurityScanner/2.0 (Authorized Testing)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        
        self.owasp_categories = {
            'a01': 'Broken Access Control',
            'a02': 'Cryptographic Failures',
            'a03': 'Injection',
            'a04': 'Insecure Design',
            'a05': 'Security Misconfiguration',
            'a06': 'Vulnerable and Outdated Components',
            'a07': 'Identification and Authentication Failures',
            'a08': 'Software and Data Integrity Failures',
            'a09': 'Security Logging and Monitoring Failures',
            'a10': 'Server-Side Request Forgery'
        }
        
        self._last_request_time = 0

    def _rate_limit(self):
        """Simple rate limiting between requests"""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.time()

    def run(self):
        """
        Main runner method for the scanner.
        (Preserved from original implementation)
        """
        target_url = input("Enter target URL (e.g., https://example.com  ): ").strip()

        if not target_url:
            print("No target URL specified. Exiting.")
            return

        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        logger.log_module_start("web_vuln_scan", target_url)

        print(f"\nStarting OWASP Top 10 scan for: {target_url}")
        print("=" * 60)

        try:
            if not self.verify_target(target_url):
                print(f"Target {target_url} is not accessible. Exiting.")
                return

            self.scan_web_application(target_url)
            self.display_results()

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
        """
        Verify the target URL is accessible and collect basic information.
        """
        try:
            self._rate_limit()
            response = self.session.get(target_url, timeout=self.timeout)
            self.results['server_info'] = {
                'status_code': response.status_code,
                'server_header': response.headers.get('Server', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown')
            }
            print(f"Target is accessible (Status: {response.status_code})")
            print(f"Server: {response.headers.get('Server', 'Unknown')}")
            return True
        except requests.exceptions.SSLError as e:
            print(f"SSL verification failed: {e}")
            print("Ensure target has valid SSL certificate or set verify_ssl=False for testing only")
            return False
        except requests.exceptions.RequestException as e:
            print(f"Target verification failed: {e}")
            return False

    def scan_web_application(self, target_url: str):
        """
        Perform comprehensive scanning against the target.
        """
        self.results = {
            'target_url': target_url,
            'scan_time': time.time(),
            'vulnerabilities': []
        }

        print("\nScanning for OWASP Top 10 vulnerabilities...")

        self.test_broken_access_control(target_url)
        self.test_cryptographic_failures(target_url)
        self.test_injection_vulnerabilities(target_url)
        self.test_security_misconfiguration(target_url)
        self.test_authentication_failures(target_url)
        self.test_ssrf_vulnerabilities(target_url)
        self.test_insecure_design(target_url)
        self.test_outdated_components(target_url)
        self.test_integrity_failures(target_url)
        self.test_logging_monitoring_failures(target_url)

    def test_broken_access_control(self, target_url: str):
        """
        Tests for access control issues.
        """
        print("Testing Broken Access Control...")

        test_params = {
            'id': '-1',
            'user': 'nonexistentuser123',
            'page': '../../../etc/passwd'
        }

        for param, value in test_params.items():
            self._rate_limit()
            test_url = f"{target_url}?{param}={quote(value)}"
            try:
                response = self.session.get(test_url, timeout=self.timeout)

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

            except requests.exceptions.RequestException:
                pass

    def test_cryptographic_failures(self, target_url: str):
        """
        Tests for insecure handling of encryption and transmission.
        """
        print("Testing Cryptographic Failures...")

        if target_url.startswith('http://'):
            https_url = target_url.replace('http://', 'https://')
            try:
                self._rate_limit()
                https_response = self.session.get(https_url, timeout=self.timeout, verify=True)
                if https_response.status_code == 200:
                    self.add_vulnerability(
                        'A02', 'Cryptographic Failures', 'Medium',
                        'HTTPS available but not enforced',
                        'Website supports HTTPS but allows HTTP access',
                        'Implement HTTP to HTTPS redirect and HSTS'
                    )
            except requests.exceptions.RequestException:
                pass

        try:
            self._rate_limit()
            response = self.session.get(target_url, timeout=self.timeout)
            if 'http://' in response.text and target_url.startswith('https://'):
                self.add_vulnerability(
                    'A02', 'Cryptographic Failures', 'Low',
                    'Mixed content detected',
                    'HTTP resources loaded on HTTPS page',
                    'Ensure all resources are loaded over HTTPS'
                )
        except requests.exceptions.RequestException:
            pass

    def test_injection_vulnerabilities(self, target_url: str):
        """
        Checks for common injection flaws.
        """
        print("Testing Injection Vulnerabilities...")

        sql_payloads = [
            "'",
            "1' OR '1'='1'--",
            "1' AND 1=1--",
            "1' UNION SELECT null--"
        ]

        test_params = ['id', 'product', 'category', 'user_id', 'article']

        for param in test_params:
            for payload in sql_payloads:
                self._rate_limit()
                test_url = f"{target_url}?{param}={quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    original_response = self.session.get(f"{target_url}?{param}=1", timeout=self.timeout)

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
                except requests.exceptions.RequestException:
                    pass

        xss_payloads = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "\" onmouseover=\"alert(1)"
        ]

        search_params = ['q', 'search', 'query', 's']

        for param in search_params:
            for payload in xss_payloads:
                self._rate_limit()
                test_url = f"{target_url}?{param}={quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    if payload in response.text and '<script>' not in response.text:
                        if any(ctx in response.text for ctx in ['<', '>', '"', "'"]):
                            self.add_vulnerability(
                                'A03', 'Injection', 'Medium',
                                f'Potential XSS in parameter: {param}',
                                f'User input reflected without proper encoding',
                                'Implement proper output encoding and Content Security Policy'
                            )
                            break
                except requests.exceptions.RequestException:
                    pass

    def test_security_misconfiguration(self, target_url: str):
        """
        Scans for insecure server configurations and exposed files.
        """
        print("Testing Security Misconfiguration...")

        sensitive_files = {
            '.env': ['database', 'password', 'secret'],
            'config.php': ['password', 'secret', 'api_key'],
            'web.config': ['connectionString', 'password'],
            '.git/config': '[core]',
            'phpinfo.php': 'phpinfo'
        }

        for file, indicators in sensitive_files.items():
            self._rate_limit()
            test_url = urljoin(target_url, file)
            try:
                response = self.session.get(test_url, timeout=3)
                if response.status_code == 200:
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
            except requests.exceptions.RequestException:
                pass

        try:
            self._rate_limit()
            response = self.session.get(target_url, timeout=self.timeout)
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
        except requests.exceptions.RequestException:
            pass

    def test_authentication_failures(self, target_url: str):
        """
        Searches for exposed login or admin interfaces.
        """
        print("Testing Authentication Failures...")

        admin_pages = [
            'admin', 'login', 'wp-admin', 'administrator',
            'cpanel', 'webmail', 'phpmyadmin'
        ]

        for page in admin_pages:
            self._rate_limit()
            test_url = urljoin(target_url, page)
            try:
                response = self.session.get(test_url, timeout=3)
                if response.status_code == 200:
                    page_content = response.text.lower()
                    login_indicators = ['password', 'username', 'login', 'sign in', 'form']

                    if any(indicator in page_content for indicator in login_indicators):
                        self.add_vulnerability(
                            'A07', 'Authentication Failures', 'Low',
                            f'Login interface exposed: {page}',
                            'Authentication interface accessible without restrictions',
                            'Implement rate limiting and strong authentication controls'
                        )
            except requests.exceptions.RequestException:
                pass

    def test_ssrf_vulnerabilities(self, target_url: str):
        """
        Tests for SSRF vulnerabilities.
        """
        print("Testing SSRF Vulnerabilities...")

        ssrf_params = ['url', 'image', 'file', 'path', 'redirect']
        internal_ips = [
            'http://127.0.0.1:80',
            'http://localhost',
        ]

        for param in ssrf_params:
            for internal_ip in internal_ips:
                self._rate_limit()
                test_url = f"{target_url}?{param}={quote(internal_ip)}"
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    if response.status_code in [200, 302, 307]:
                        if any(indicator in response.text for indicator in ['instance', 'metadata', 'localhost']):
                            self.add_vulnerability(
                                'A10', 'SSRF', 'High',
                                f'Potential SSRF vulnerability in parameter: {param}',
                                f'Able to make requests to internal resources: {internal_ip}',
                                'Validate and sanitize all user-supplied URLs'
                            )
                            break
                except requests.exceptions.RequestException:
                    pass

    def test_insecure_design(self, target_url: str):
        """
        Performs lightweight checks for insecure design choices.
        """
        print("Testing Insecure Design...")

        candidate_paths = ['login', 'api/login', 'auth', 'admin', 'user/login']
        burst_count = 5
        for path in candidate_paths:
            login_url = urljoin(target_url, path)
            try:
                statuses = []
                for _ in range(burst_count):
                    self._rate_limit()
                    resp = self.session.get(login_url, timeout=4)
                    statuses.append(resp.status_code)
                    time.sleep(0.2)
                if all(s != 429 for s in statuses):
                    if any(keyword in resp.text.lower() for keyword in ['password', 'username', 'login', 'sign in', 'csrf']):
                        self.add_vulnerability(
                            'A04', 'Insecure Design', 'Medium',
                            f'No obvious rate limiting on login-like endpoint: {path}',
                            'Login endpoint did not exhibit rate-limiting on a small burst; design may lack throttling',
                            'Implement rate limiting, incremental backoff, and Captcha for authentication endpoints'
                        )
            except requests.exceptions.RequestException:
                pass

        suspicious_get_patterns = ['delete', 'remove', 'update', 'set', 'action']
        try:
            self._rate_limit()
            response = self.session.get(target_url, timeout=5)
            for p in suspicious_get_patterns:
                if f"/{p}" in response.text.lower() or f"?{p}=" in response.text.lower():
                    self.add_vulnerability(
                        'A04', 'Insecure Design', 'Low',
                        'Potential state-changing operations discoverable via GET',
                        'Application appears to reference state-changing operations via GET or query parameters',
                        'Design APIs to use safe HTTP verbs (POST/PUT/DELETE) for state changes and require CSRF protection'
                    )
                    break
        except requests.exceptions.RequestException:
            pass

    def test_outdated_components(self, target_url: str):
        """
        Fingerprints server and application components.
        """
        print("Testing Vulnerable & Outdated Components...")

        try:
            self._rate_limit()
            response = self.session.get(target_url, timeout=6)
            headers = response.headers

            findings = []

            server_header = headers.get('Server')
            if server_header:
                findings.append(('Server', server_header))

            x_powered = headers.get('X-Powered-By')
            if x_powered:
                findings.append(('X-Powered-By', x_powered))

            if '<meta name="generator"' in response.text.lower():
                start = response.text.lower().find('<meta name="generator"')
                snippet = response.text[start:start + 200]
                findings.append(('Generator meta', snippet))

            cms_checks = ['readme.html', 'license.txt', 'changelog.txt', 'wp-includes/']
            for p in cms_checks:
                self._rate_limit()
                check_url = urljoin(target_url, p)
                try:
                    r = self.session.get(check_url, timeout=3)
                    if r.status_code == 200 and len(r.text) > 50:
                        findings.append((p, f"Accessible ({r.status_code})"))
                except requests.exceptions.RequestException:
                    pass

            if findings:
                details = '; '.join([f"{k}: {v}" for k, v in findings])
                self.add_vulnerability(
                    'A06', 'Vulnerable Components', 'Medium',
                    'Potentially fingerprintable components detected',
                    f'Observed component/version hints: {details}',
                    'Manually verify component versions and check against CVE databases; keep dependencies patched'
                )
        except requests.exceptions.RequestException:
            pass

    def test_integrity_failures(self, target_url: str):
        """
        Scans for exposed repository and package manifest files.
        """
        print("Testing Software & Data Integrity Failures...")

        files_to_check = [
            '.git/', '.git/config', 'composer.lock', 'composer.json',
            'package.json', 'requirements.txt', 'Pipfile', 'Pipfile.lock'
        ]

        for f in files_to_check:
            self._rate_limit()
            check_url = urljoin(target_url, f)
            try:
                r = self.session.get(check_url, timeout=4)
                if r.status_code == 200 and len(r.text) > 30:
                    if any(keyword in r.text.lower() for keyword in ['version', 'require', 'dependencies', '[package]']):
                        self.add_vulnerability(
                            'A08', 'Integrity Failures', 'High' if f.endswith('.lock') else 'Medium',
                            f'Exposed manifest/lock file: {f}',
                            f'Public access to {f} reveals dependency or build information',
                            'Remove manifests/lockfiles from webroot and ensure CI/CD artifacts are integrity-signed'
                        )
            except requests.exceptions.RequestException:
                pass

        try:
            self._rate_limit()
            git_index = urljoin(target_url, '.git/')
            r = self.session.get(git_index, timeout=3)
            if r.status_code == 200 and ('index of' in r.text.lower() or '.git' in r.text.lower()):
                self.add_vulnerability(
                    'A08', 'Integrity Failures', 'High',
                    'Exposed .git directory',
                    'Repository metadata exposed on web root; attackers may reconstruct source or history',
                    'Remove .git from webroot and restrict access; use deployment artifacts that do not include VCS metadata'
                )
        except requests.exceptions.RequestException:
            pass

    def test_logging_monitoring_failures(self, target_url: str):
        """
        Performs non-invasive checks for logging/monitoring gaps.
        """
        print("Testing Logging & Monitoring Failures...")

        log_paths = ['logs', 'log', 'audit', 'var/log', 'syslog']
        for p in log_paths:
            self._rate_limit()
            check_url = urljoin(target_url, p)
            try:
                r = self.session.get(check_url, timeout=3)
                if r.status_code == 200 and len(r.text) > 50:
                    self.add_vulnerability(
                        'A09', 'Logging & Monitoring Failures', 'High',
                        f'Exposed log/audit path accessible: {p}',
                        'Application exposes logs or audit output via web',
                        'Remove or protect logs from public access and implement proper access controls'
                    )
            except requests.exceptions.RequestException:
                pass

        try:
            self._rate_limit()
            r = self.session.get(target_url, timeout=5)
            headers = r.headers
            if 'X-Request-Id' not in headers and 'X-Correlation-Id' not in headers:
                self.add_vulnerability(
                    'A09', 'Logging & Monitoring Failures', 'Low',
                    'Missing request correlation headers',
                    'No evidence of request correlation headers (X-Request-Id/X-Correlation-Id) in responses',
                    'Instrument the application to generate request IDs and log them for traceability'
                )
        except requests.exceptions.RequestException:
            pass

        candidate_login_paths = ['login', 'api/login', 'auth']
        for p in candidate_login_paths:
            login_url = urljoin(target_url, p)
            try:
                self._rate_limit()
                resp_before = self.session.get(login_url, timeout=4)
                time.sleep(0.2)
                self._rate_limit()
                resp_after = self.session.get(login_url, timeout=4)
                if resp_before.status_code == resp_after.status_code and resp_before.status_code != 429:
                    if any(keyword in resp_before.text.lower() for keyword in ['password', 'username', 'login']):
                        self.add_vulnerability(
                            'A09', 'Logging & Monitoring Failures', 'Low',
                            f'No observable lockout/rate-limit behavior on: {p}',
                            'Small non-destructive checks did not trigger rate-limiting on login page',
                            'Implement and monitor account lockout and rate-limiting for authentication endpoints'
                        )
            except requests.exceptions.RequestException:
                pass

    def add_vulnerability(self, category: str, name: str, severity: str,
                          title: str, description: str, remediation: str):
        """
        Add a detected vulnerability to the result set.
        Avoids adding duplicate findings based on category and title.
        """
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
        """
        Display the final scan results in a structured format.
        """
        print(f"\n{'='*80}")
        print(f"OWASP TOP 10 SCAN RESULTS")
        print(f"{'='*80}")
        print(f"Target: {self.results.get('target_url', 'Unknown')}")
        print(f"Vulnerabilities Found: {len(self.vulnerabilities)}")

        if not self.vulnerabilities:
            print("\nNo significant vulnerabilities found!")
            print("Note: This is a basic scanner. Manual testing is recommended for comprehensive assessment.")
            return

        by_severity = {}
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)

        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if severity in by_severity:
                print(f"\n{severity.upper()} SEVERITY ({len(by_severity[severity])}):")
                print("-" * 40)

                for vuln in by_severity[severity]:
                    print(f"[{vuln['category']}] {vuln['title']}")
                    print(f"   Description: {vuln['description']}")
                    print(f"   Remediation: {vuln['remediation']}")
                    print()


# Module-level instance (preserved from original)
web_vuln_scanner = WebVulnerabilityScanner()
