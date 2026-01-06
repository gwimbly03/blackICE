# core/cve_db.py
import requests
import re
import time
from threading import Lock
from typing import Optional, Tuple, List

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_API_KEY: Optional[str] = "5c0b779e-36af-4f14-92f6-7566bb75cec1"

_LOOKUP_CACHE = {}
_CACHE_LOCK = Lock()

# NVD anonymous rate-limits are strict: ~5 requests / 30s, I need a key.
_NVD_LOCK = Lock()
_MIN_INTERVAL = 6.5
_last_nvd_call = 0.0


class CVELookup:
    """
    NVD-backed CVE lookup utility (anonymous mode by default).
    Provides:
      - extract_version(banner) -> (product, version)
      - fuzzy_product_match(banner) -> product or None
      - build_cpe(product, version) -> cpe string or None
      - search_cves(product, version=None) -> List[(cve_id, score, title)]
    """

    PRODUCT_CPE = {
        # Web servers
        "nginx": "nginx:nginx",
        "apache": "apache:http_server",
        "httpd": "apache:http_server",
        "iis": "microsoft:iis",
        "lighttpd": "lighttpd:lighttpd",

        # SSH
        "openssh": "openbsd:openssh",
        "dropbear": "dropbear:dropbear_ssh_server",

        # FTP
        "vsftpd": "vsftpd:vsftpd",
        "proftpd": "proftpd:proftpd",
        "pure-ftpd": "pureftpd:pure-ftpd",

        # Mail
        "postfix": "postfix:postfix",
        "exim": "exim:exim",
        "dovecot": "dovecot:dovecot",
        "sendmail": "sendmail:sendmail",

        # Databases
        "mysql": "oracle:mysql",
        "mariadb": "mariadb:mariadb",
        "postgresql": "postgresql:postgresql",
        "mongodb": "mongodb:mongodb",
        "redis": "redis:redis",

        # SMB / Windows
        "samba": "samba:samba",

        # RDP/VNC
        "rdp": "microsoft:remote_desktop_protocol",
        "tightvnc": "tightvnc:tightvnc",
        "realvnc": "realvnc:realvnc",
        "tigervnc": "tigervnc:tigervnc",

        # DNS
        "bind": "isc:bind",
        "powerdns": "powerdns:authoritative",
        "dnsmasq": "kamatari:dnsmasq",

        # Proxy / LB
        "haproxy": "haproxy:haproxy",
        "squid": "squid-cache:squid",
        "varnish": "varnish:varnish_cache",

        # Message brokers
        "rabbitmq": "pivotal_software:rabbitmq",
        "activemq": "apache:activemq",
        "mosquitto": "eclipse:mosquitto",

        # App servers
        "tomcat": "apache:tomcat",
        "jetty": "eclipse:jetty",
        "jboss": "redhat:jboss_enterprise_application_platform",
        "wildfly": "redhat:wildfly",

        # Cache systems
        "memcached": "danga:memcached",

        # VPN
        "openvpn": "openvpn:openvpn",
        "strongswan": "strongswan:strongswan",
        "ipsec": "strongswan:strongswan",

        # SNMP
        "net-snmp": "net-snmp:net-snmp",

        # IoT / BusyBox
        "busybox": "busybox:busybox",

        # Misc
        "ntp": "ntp:ntp",
    }


    @staticmethod
    def extract_version(banner: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Try to extract (product, version) from a banner string.
        Returns (product, version) or (None, None).
        """
        if not banner:
            return None, None

        b = banner.lower()

        patterns = [
            # SSH
            ("openssh", r"openssh[_\- ]?(\d+\.\d+(?:p\d+)?)"),
            ("dropbear", r"dropbear[_\- ]?(\d+\.\d+)"),

            # Web servers
            ("nginx", r"nginx[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("apache", r"(?:apache|httpd)[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("iis", r"microsoft-iis[/ ](\d+\.\d+)"),
            ("lighttpd", r"lighttpd[/ ](\d+\.\d+(?:\.\d+)?)"),

            # FTP
            ("vsftpd", r"vsftpd[^\d]*(\d+\.\d+(?:\.\d+)?)"),
            ("proftpd", r"proftpd[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("pure-ftpd", r"pure-ftpd[^\d]*(\d+\.\d+(?:\.\d+)?)"),

            # Mail
            ("postfix", r"postfix[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("exim", r"exim[_ ](\d+\.\d+(?:\.\d+)?)"),
            ("dovecot", r"dovecot[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("sendmail", r"sendmail[/ ](\d+\.\d+(?:\.\d+)?)"),

            # Databases
            ("mysql", r"mysql[^0-9]*(\d+\.\d+(?:\.\d+)?)"),
            ("mariadb", r"mariadb[^0-9]*(\d+\.\d+(?:\.\d+)?)"),
            ("postgresql", r"postgresql[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("mongodb", r"mongodb[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("redis", r"redis[/ ](\d+\.\d+(?:\.\d+)?)"),

            # SMB
            ("samba", r"samba[/ ](\d+\.\d+(?:\.\d+)?)"),

            # VNC/RDP
            ("tightvnc", r"tightvnc[/ ](\d+\.\d+)"),
            ("realvnc", r"realvnc[/ ](\d+\.\d+)"),
            ("tigervnc", r"tigervnc[/ ](\d+\.\d+)"),

            # DNS
            ("bind", r"bind[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("dnsmasq", r"dnsmasq[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("powerdns", r"powerdns[/ ](\d+\.\d+(?:\.\d+)?)"),

            # Proxy/LB
            ("haproxy", r"haproxy[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("squid", r"squid[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("varnish", r"varnish[/ ](\d+\.\d+(?:\.\d+)?)"),

            # Message brokers
            ("rabbitmq", r"rabbitmq[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("activemq", r"activemq[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("mosquitto", r"mosquitto[/ ](\d+\.\d+(?:\.\d+)?)"),

            # App servers
            ("tomcat", r"apache-tomcat[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("jetty", r"jetty[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("jboss", r"jboss[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("wildfly", r"wildfly[/ ](\d+\.\d+(?:\.\d+)?)"),

            # Cache
            ("memcached", r"memcached[/ ](\d+\.\d+(?:\.\d+)?)"),

            # VPN
            ("openvpn", r"openvpn[/ ](\d+\.\d+(?:\.\d+)?)"),
            ("strongswan", r"strongswan[/ ](\d+\.\d+(?:\.\d+)?)"),

            # SNMP
            ("net-snmp", r"net-snmp[/ ](\d+\.\d+(?:\.\d+)?)"),

            # IoT
            ("busybox", r"busybox[/ ](\d+\.\d+(?:\.\d+)?)"),
        ]

        for product, pattern in patterns:
            m = re.search(pattern, b)
            if m:
                return product, m.group(1)

        return None, None


    @staticmethod
    def fuzzy_product_match(banner: str) -> Optional[str]:
        if not banner:
            return None
        b = banner.lower()
        for product in CVELookup.PRODUCT_CPE.keys():
            if product in b:
                return product
        return None


    @staticmethod
    def build_cpe(product: str, version: Optional[str]) -> Optional[str]:
        """
        Build a cpe:2.3:a:... string from product+version using PRODUCT_CPE mapping.
        Returns None if not possible.
        """
        if not product:
            return None

        mapped = CVELookup.PRODUCT_CPE.get(product)
        if mapped:
            vendor, prod = mapped.split(":", 1)
        else:
            vendor = product
            prod = product

        if not version:
            return f"cpe:2.3:a:{vendor}:{prod}"
        return f"cpe:2.3:a:{vendor}:{prod}:{version}"

    @staticmethod
    def _nvd_get(params: dict) -> Optional[dict]:
        global _last_nvd_call
        with _NVD_LOCK:
            now = time.time()
            delta = now - _last_nvd_call
            if delta < _MIN_INTERVAL:
                time.sleep(_MIN_INTERVAL - delta)
            headers = {}
            if NVD_API_KEY:
                headers["apiKey"] = NVD_API_KEY
            try:
                resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=10)
                _last_nvd_call = time.time()
                if resp.status_code != 200:
                    return {"error": f"HTTP {resp.status_code}", "body": resp.text}
                return resp.json()
            except Exception as e:
                return {"error": str(e)}

    @staticmethod
    def search_cves(product: str, version: Optional[str] = None, results_per_page: int = 20) -> List[Tuple[str, str, str]]:
        """
        Search NVD using constructed CPE. Returns list of tuples.
        This function caches results and obeys NVD anonymous rate limits.
        """
        if not product:
            return []

        cache_key = (product, version)
        with _CACHE_LOCK:
            if cache_key in _LOOKUP_CACHE:
                return _LOOKUP_CACHE[cache_key]

        results = []

        tried = []
        if version:
            cpe = CVELookup.build_cpe(product, version)
            if cpe:
                tried.append(("versioned", cpe))
                params = {"cpeName": cpe, "resultsPerPage": results_per_page}
                data = CVELookup._nvd_get(params)
                if data and "error" not in data:
                    results = CVELookup._parse_nvd_response(data)
                    if results:
                        with _CACHE_LOCK:
                            _LOOKUP_CACHE[cache_key] = results
                        return results

        cpe_nover = CVELookup.build_cpe(product, None)
        if cpe_nover:
            tried.append(("product-only", cpe_nover))
            params = {"cpeName": cpe_nover, "resultsPerPage": results_per_page}
            data = CVELookup._nvd_get(params)
            if data and "error" not in data:
                results = CVELookup._parse_nvd_response(data)

        if not results:
            tried.append(("keyword", product))
            params = {"keywordSearch": product, "resultsPerPage": results_per_page}
            data = CVELookup._nvd_get(params)
            if data and "error" not in data:
                results = CVELookup._parse_nvd_response(data)

        with _CACHE_LOCK:
            _LOOKUP_CACHE[cache_key] = results

        return results

    @staticmethod
    def _parse_nvd_response(data: dict) -> List[Tuple[str, str, str]]:
        out = []
        vulns = data.get("vulnerabilities") or data.get("result", {}).get("vulnerabilities") or []
        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id") or cve.get("CVE_data_meta", {}).get("ID") or None
            if not cve_id:
                continue

            title = ""
            descriptions = cve.get("descriptions") or []
            if isinstance(descriptions, list):
                for d in descriptions:
                    v = d.get("value") or d.get("description")
                    if v:
                        title = v
                        break

            score = "N/A"
            metrics = cve.get("metrics") or {}
            # v3.1
            cvss31 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV3")
            if isinstance(cvss31, list) and cvss31:
                try:
                    score = str(cvss31[0].get("cvssData", {}).get("baseScore", "N/A"))
                except Exception:
                    score = "N/A"
            else:
                # v3.0
                cvss30 = metrics.get("cvssMetricV30")
                if isinstance(cvss30, list) and cvss30:
                    score = str(cvss30[0].get("cvssData", {}).get("baseScore", "N/A"))
                else:
                    # v2
                    cvss2 = metrics.get("cvssMetricV2")
                    if isinstance(cvss2, list) and cvss2:
                        score = str(cvss2[0].get("cvssData", {}).get("baseScore", "N/A"))

            out.append((cve_id, score, title))
        def score_key(t):
            try:
                return float(t[1])
            except Exception:
                return 0.0
        out.sort(key=score_key, reverse=True)
        return out

