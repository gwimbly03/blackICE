import requests
import re

class CVELookup:
    VULNERS_API = "https://vulners.com/api/v3/search/lucene/"

    @staticmethod
    def extract_version(banner: str):
        """
        Extract product + version from banners obtained during port scans.
        Supports common services like SSH, Apache, nginx, MySQL, etc.
        """
        if not banner:
            return None, None

        banner = banner.lower()

        patterns = [
            r"(openssh)\s+([\d\.p]+)",
            r"(apache|httpd)\s*/\s*([\d\.]+)",
            r"(nginx)\s*/\s*([\d\.]+)",
            r"(mysql)\s*([\d\.]+)",
            r"(postgresql)\s*([\d\.]+)",
            r"(samba)\s*([\d\.]+)",
            r"(vsftpd)\s*([\d\.]+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, banner)
            if match:
                product = match.group(1)
                version = match.group(2)
                return product, version

        return None, None

    @staticmethod
    def search_cves(product, version):
        """
        Query Vulners API for matching CVEs.
        """
        try:
            query = f"{product} {version}"
            data = {
                "query": query,
                "size": 20
            }

            r = requests.post(CVELookup.VULNERS_API, json=data, timeout=5)
            response = r.json()

            if "result" not in response or "documents" not in response["result"]:
                return []

            vulns = []
            for doc in response["result"]["documents"]:
                if "cvelist" not in doc:
                    continue

                cve_list = doc["cvelist"]
                score = doc.get("cvss", {}).get("score", "N/A")
                title = doc.get("title", "")

                for cve in cve_list:
                    vulns.append((cve, score, title))

            return vulns

        except Exception:
            return []

