import os
import time
import json
import math
import textwrap
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_PAGE_SIZE = 25
DEFAULT_MAX_RESULTS = 200
DEFAULT_TIMEOUT = 10.0


class NvdCveReporter:
    description = "Live NVD CVE Reporter (NVD API v2.0) — master search function supporting all parameters"

    def __init__(self, page_size: int = DEFAULT_PAGE_SIZE, timeout: float = DEFAULT_TIMEOUT):
        self.console = Console()
        self.page_size = page_size
        self.timeout = timeout
        self.paged_sleep = 0.6
        self.api_key = os.environ.get("NVD_API_KEY", None)

    def _request(self, params: Dict[str, Any], start_index: int = 0) -> Optional[Dict[str, Any]]:
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        params = params.copy()
        params["startIndex"] = start_index
        params["resultsPerPage"] = min(self.page_size, 2000)
        try:
            r = requests.get(NVD_BASE, params=params, headers=headers, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except requests.HTTPError as e:
            self.console.print(f"[red]HTTP error: {e} - {getattr(e.response, 'text', '')}[/red]")
            return None
        except requests.RequestException as e:
            self.console.print(f"[red]Network error: {e}[/red]")
            return None
        except Exception as e:
            self.console.print(f"[red]Unexpected error: {e}[/red]")
            return None

    def _parse_cve_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a CVE item returned from NVD API 2.0.
        """
        cve_obj = item.get("cve", item)
        cve_id = cve_obj.get("id") or "UNKNOWN"
        published = item.get("published") or cve_obj.get("published") or item.get("publishedDate") or "N/A"
        last_modified = item.get("lastModified") or cve_obj.get("lastModified") or item.get("lastModifiedDate") or "N/A"
        summary = ""
        descriptions = cve_obj.get("descriptions", [])
        if isinstance(descriptions, list):
            for d in descriptions:
                if d.get("lang", "en").lower().startswith("en"):
                    summary = d.get("value", "")
                    break
        if not summary:
            summary = "No description available."
        metrics = cve_obj.get("metrics", {}) or {}
        severity = self.extract_severity(cve_obj)
        cvss_score = None
        if "cvssMetricV31" in metrics:
            try:
                cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            except:
                pass
        elif "cvssMetricV30" in metrics:
            try:
                cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            except:
                pass
        elif "cvssMetricV2" in metrics:
            try:
                cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            except:
                pass
        try:
            cvss_score = float(cvss_score) if cvss_score is not None else None
        except:
            cvss_score = None
        refs = []
        for r in cve_obj.get("references", []) if isinstance(cve_obj.get("references", []), list) else []:
            url = r.get("url") or r.get("href")
            if url:
                refs.append(url)
        is_kev = False
        if isinstance(cve_obj.get("cveTag"), list):
            for t in cve_obj.get("cveTag", []):
                try:
                    if isinstance(t, str) and t.lower() == "kev":
                        is_kev = True
                        break
                except:
                    pass
        if not is_kev:
            if isinstance(cve_obj.get("cveTags"), list):
                for t in cve_obj.get("cveTags", []):
                    try:
                        if isinstance(t, str) and t.lower() == "kev":
                            is_kev = True
                            break
                    except:
                        pass
        if not is_kev:
            if item.get("hasKev") is True or cve_obj.get("hasKev") is True:
                is_kev = True
        return {
            "id": cve_id,
            "published": str(published),
            "lastModified": str(last_modified),
            "summary": summary.strip(),
            "cvss_score": cvss_score,
            "severity": severity.upper() if severity else "N/A",
            "references": refs,
            "is_kev": is_kev
        }

    @staticmethod
    def score_to_severity(score: Optional[float]) -> str:
        if score is None:
            return "UNKNOWN"
        try:
            s = float(score)
        except Exception:
            return "UNKNOWN"
        if s >= 9.0:
            return "CRITICAL"
        if s >= 7.0:
            return "HIGH"
        if s >= 4.0:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def severity_color_label(sev: str) -> str:
        s = sev.upper() if sev else "UNKNOWN"
        if s == "CRITICAL":
            return "[bold red]CRITICAL[/bold red]"
        if s == "HIGH":
            return "[red]HIGH[/red]"
        if s == "MEDIUM":
            return "[yellow]MEDIUM[/yellow]"
        if s == "LOW":
            return "[green]LOW[/green]"
        return "[grey50]UNKNOWN[/grey50]"

    @staticmethod
    def extract_severity(cve: Dict[str, Any]) -> str:
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            try:
                sev = metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity")
                if sev:
                    return sev
            except:
                pass
        if "cvssMetricV30" in metrics:
            try:
                sev = metrics["cvssMetricV30"][0]["cvssData"].get("baseSeverity")
                if sev:
                    return sev
            except:
                pass
        if "cvssMetricV2" in metrics:
            try:
                score = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore")
                if score is not None:
                    return f"CVSSv2 Score {score}"
            except:
                pass
        return "N/A (not provided)"

    def _render_table(self, rows: List[Dict[str, Any]], page: int = 1, page_size: Optional[int] = None):
        page_size = page_size or self.page_size
        total = len(rows)
        if total == 0:
            self.console.print("[yellow]No results to display.[/yellow]")
            return
        pages = max(1, math.ceil(total / page_size))
        page = max(1, min(page, pages))
        start = (page - 1) * page_size
        end = min(start + page_size, total)
        subset = rows[start:end]
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("CVE ID", style="green", no_wrap=True)
        table.add_column("Published", style="magenta", no_wrap=True)
        table.add_column("Last Modified", style="magenta", no_wrap=True)
        table.add_column("CVSS", style="yellow", no_wrap=True)
        table.add_column("Severity", style="red", no_wrap=True)
        table.add_column("Summary", style="white")
        for r in subset:
            score = r.get("cvss_score")
            score_str = f"{score:.1f}" if isinstance(score, float) else (str(score) if score is not None else "N/A")
            sev = r.get("severity") or self.score_to_severity(score)
            sev_label = self.severity_color_label(sev)
            if r.get("is_kev"):
                sev_label = sev_label + "  KEV"
            summary = (r.get("summary") or "").replace("\n", " ").strip()
            if len(summary) > 240:
                summary = summary[:236].rstrip() + "..."
            table.add_row(r.get("id"), r.get("published")[:19], r.get("lastModified")[:19], score_str, sev_label, summary)
        self.console.print(table)
        self.console.print(f"[grey37]Showing {start+1}-{end} of {total} results — Page {page}/{pages}[/grey37]")

    def _interactive_paged_display(self, rows: List[Dict[str, Any]]):
        total = len(rows)
        if total == 0:
            self.console.print("[yellow]No results found.[/yellow]")
            return
        pages = max(1, math.ceil(total / self.page_size))
        page = 1
        while True:
            os.system("clear" if os.name == "posix" else "cls")
            self._render_table(rows, page=page)
            if pages == 1:
                _ = Prompt.ask("Enter [x] to return", default="x")
                return
            action = Prompt.ask("Navigation (n=next, p=prev, e=export, q=quit)", choices=["n", "p", "e", "q"], default="n")
            if action == "n":
                if page < pages:
                    page += 1
                else:
                    self.console.print("[dim]Already on last page[/dim]")
            elif action == "p":
                if page > 1:
                    page -= 1
                else:
                    self.console.print("[dim]Already on first page[/dim]")
            elif action == "e":
                self._export_menu(rows)
            else:
                return

    def _export_menu(self, rows: List[Dict[str, Any]]):
        self.console.print("\n[bold]Export Options[/bold]")
        self.console.print("1) Export to JSON")
        self.console.print("2) Export to Markdown")
        self.console.print("3) Export to HTML")
        self.console.print("0) Cancel")
        choice = Prompt.ask("Choose", choices=["0", "1", "2", "3"], default="0")
        if choice == "0":
            return
        filename = Prompt.ask("Enter output filename (without extension)", default=f"nvd_export_{int(time.time())}")
        try:
            if choice == "1":
                out = filename + ".json"
                with open(out, "w", encoding="utf-8") as f:
                    json.dump(rows, f, indent=2, ensure_ascii=False)
                self.console.print(f"[green]Exported JSON to {out}[/green]")
            elif choice == "2":
                out = filename + ".md"
                self._write_markdown(rows, out)
                self.console.print(f"[green]Exported Markdown to {out}[/green]")
            elif choice == "3":
                out = filename + ".html"
                self._write_html(rows, out)
                self.console.print(f"[green]Exported HTML to {out}[/green]")
        except Exception as e:
            self.console.print(f"[red]Export failed: {e}[/red]")

    def _write_markdown(self, rows: List[Dict[str, Any]], path: str):
        with open(path, "w", encoding="utf-8") as f:
            f.write("# NVD CVE Export\n\n")
            for r in rows:
                f.write(f"## {r.get('id')}\n\n")
                f.write(f"- **Published:** {r.get('published')}\n")
                f.write(f"- **Last Modified:** {r.get('lastModified')}\n")
                f.write(f"- **CVSS:** {r.get('cvss_score')}\n")
                f.write(f"- **Severity:** {r.get('severity')}" + (f"  KEV" if r.get("is_kev") else "") + "\n\n")
                f.write("**Summary:**\n\n")
                f.write(textwrap.fill(r.get("summary") or "", width=100))
                f.write("\n\n---\n\n")

    def _write_html(self, rows: List[Dict[str, Any]], path: str):
        html_rows = []
        for r in rows:
            kev_text = " KEV" if r.get("is_kev") else ""
            html_rows.append(f"""
            <tr>
              <td>{r.get('id')}</td>
              <td>{r.get('published')}</td>
              <td>{r.get('lastModified')}</td>
              <td>{r.get('cvss_score') or 'N/A'}</td>
              <td>{r.get('severity')}{kev_text}</td>
              <td>{(r.get('summary') or '')[:400]}</td>
            </tr>
            """)
        html = f"""<!doctype html>
        <html>
        <head><meta charset="utf-8"><title>NVD CVE Export</title>
        <style>table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px}}</style>
        </head>
        <body>
        <h1>NVD CVE Export</h1>
        <table><thead><tr><th>CVE</th><th>Published</th><th>Last Modified</th><th>CVSS</th><th>Severity</th><th>Summary</th></tr></thead>
        <tbody>{''.join(html_rows)}</tbody></table>
        </body></html>
        """
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def search_cves(
        self,
        keywordSearch: Optional[str] = None,
        keywordExactMatch: bool = False,
        cpeName: Optional[str] = None,
        virtualMatchString: Optional[str] = None,
        versionStart: Optional[str] = None,
        versionStartType: Optional[str] = None,
        versionEnd: Optional[str] = None,
        versionEndType: Optional[str] = None,
        cveId: Optional[str] = None,
        cveTag: Optional[str] = None,
        cvssV2Metrics: Optional[str] = None,
        cvssV2Severity: Optional[str] = None,
        cvssV3Metrics: Optional[str] = None,
        cvssV3Severity: Optional[str] = None,
        cvssV4Metrics: Optional[str] = None,
        cvssV4Severity: Optional[str] = None,
        cweId: Optional[str] = None,
        hasCertAlerts: bool = False,
        hasCertNotes: bool = False,
        hasKev: bool = False,
        hasOval: bool = False,
        isVulnerable: bool = False,
        kevStartDate: Optional[str] = None,
        kevEndDate: Optional[str] = None,
        lastModStartDate: Optional[str] = None,
        lastModEndDate: Optional[str] = None,
        pubStartDate: Optional[str] = None,
        pubEndDate: Optional[str] = None,
        noRejected: bool = False,
        sourceIdentifier: Optional[str] = None,
        resultsPerPage: Optional[int] = None,
        sortBy: Optional[str] = None,
        sortOrder: Optional[str] = None,
        startIndex: int = 0,
        max_results: int = DEFAULT_MAX_RESULTS
    ) -> List[Dict[str, Any]]:
        """
        Master search function for NVD CVE API v2.0. Accepts all supported parameters.
        Returns a list of normalized CVE records (parsed).
        """
        params: Dict[str, Any] = {}
        if keywordSearch:
            params["keywordSearch"] = keywordSearch
        if keywordExactMatch:
            params["keywordExactMatch"] = ""
        if cpeName:
            params["cpeName"] = cpeName
        if virtualMatchString:
            params["virtualMatchString"] = virtualMatchString
        if versionStart:
            params["versionStart"] = versionStart
        if versionStartType:
            params["versionStartType"] = versionStartType
        if versionEnd:
            params["versionEnd"] = versionEnd
        if versionEndType:
            params["versionEndType"] = versionEndType
        if cveId:
            params["cveId"] = cveId
        if cveTag:
            params["cveTag"] = cveTag
        if cvssV2Metrics:
            params["cvssV2Metrics"] = cvssV2Metrics
        if cvssV2Severity:
            params["cvssV2Severity"] = cvssV2Severity
        if cvssV3Metrics:
            params["cvssV3Metrics"] = cvssV3Metrics
        if cvssV3Severity:
            params["cvssV3Severity"] = cvssV3Severity
        if cvssV4Metrics:
            params["cvssV4Metrics"] = cvssV4Metrics
        if cvssV4Severity:
            params["cvssV4Severity"] = cvssV4Severity
        if cweId:
            params["cweId"] = cweId
        if hasCertAlerts:
            params["hasCertAlerts"] = ""
        if hasCertNotes:
            params["hasCertNotes"] = ""
        if hasKev:
            params["hasKev"] = ""
        if hasOval:
            params["hasOval"] = ""
        if isVulnerable:
            params["isVulnerable"] = ""
        if kevStartDate:
            params["kevStartDate"] = kevStartDate
        if kevEndDate:
            params["kevEndDate"] = kevEndDate
        if lastModStartDate:
            params["lastModStartDate"] = lastModStartDate
        if lastModEndDate:
            params["lastModEndDate"] = lastModEndDate
        if pubStartDate:
            params["pubStartDate"] = pubStartDate
        if pubEndDate:
            params["pubEndDate"] = pubEndDate
        if noRejected:
            params["noRejected"] = ""
        if sourceIdentifier:
            params["sourceIdentifier"] = sourceIdentifier
        if resultsPerPage:
            params["resultsPerPage"] = resultsPerPage
        if sortBy:
            params["sortBy"] = sortBy
        if sortOrder:
            params["sortOrder"] = sortOrder

        if isVulnerable and not cpeName:
            raise ValueError("isVulnerable requires cpeName to be provided")

        if (cvssV2Metrics and (cvssV3Metrics or cvssV4Metrics)) or (cvssV3Metrics and cvssV4Metrics):
            raise ValueError("cvss metric filters are mutually exclusive")

        if (cvssV2Severity and (cvssV3Severity or cvssV4Severity)) or (cvssV3Severity and cvssV4Severity):
            raise ValueError("cvss severity filters are mutually exclusive")

        if (lastModStartDate and not lastModEndDate) or (lastModEndDate and not lastModStartDate):
            raise ValueError("Both lastModStartDate and lastModEndDate must be provided together")

        if (pubStartDate and not pubEndDate) or (pubEndDate and not pubStartDate):
            raise ValueError("Both pubStartDate and pubEndDate must be provided together")

        if kevStartDate and not kevEndDate or kevEndDate and not kevStartDate:
            raise ValueError("Both kevStartDate and kevEndDate must be provided together")

        date_params = []
        if lastModStartDate and lastModEndDate:
            date_params.append(("lastMod", lastModStartDate, lastModEndDate))
        if pubStartDate and pubEndDate:
            date_params.append(("pub", pubStartDate, pubEndDate))
        if kevStartDate and kevEndDate:
            date_params.append(("kev", kevStartDate, kevEndDate))
        for kind, s, e in date_params:
            try:
                s_dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
                e_dt = datetime.fromisoformat(e.replace("Z", "+00:00"))
            except Exception:
                raise ValueError(f"Invalid ISO-8601 date format for {kind}StartDate/EndDate")
            if s_dt > e_dt:
                raise ValueError(f"{kind}StartDate must be <= {kind}EndDate")
            if (e_dt - s_dt).days > 120:
                raise ValueError(f"{kind} date range cannot exceed 120 days")

        results: List[Dict[str, Any]] = []
        fetched = 0
        si = startIndex
        cap = max_results
        with Progress() as progress:
            task = progress.add_task("[cyan]Querying NVD...", start=False)
            while fetched < cap:
                data = self._request(params, start_index=si)
                if data is None:
                    break
                vulns = data.get("vulnerabilities", []) or []
                total_results = data.get("totalResults", 0) or data.get("total", 0) or 0
                if not vulns:
                    break
                for v in vulns:
                    parsed = self._parse_cve_item(v)
                    results.append(parsed)
                    fetched += 1
                    if fetched >= cap:
                        break
                si += len(vulns)
                if fetched >= cap or si >= total_results:
                    break
                time.sleep(self.paged_sleep)
            progress.update(task, completed=True)
        return results

    
    def run(self):
        self.console.print("[bold green]BlackICE - NVD CVE Live Reporter (Master Search)[/bold green]")
        if self.api_key:
            self.console.print(f"[dim]Using NVD API key from environment.[/dim]")

        while True:
            self.console.print("\n[bold]Options[/bold]")
            self.console.print("1) Lookup CVE by ID (e.g. CVE-2023-1234)")
            self.console.print("2) Search by keyword (e.g. openssl, apache, rce)")
            self.console.print("4) Advanced search (open parameter form)")
            self.console.print("0) Exit")

            choice = Prompt.ask("Choose", choices=["0", "1", "2", "4"], default="0")

            if choice == "0":
                self.console.print("Exiting NVD CVE Reporter.")
                return

            if choice == "1":
                cve_id = Prompt.ask("Enter CVE ID").strip().upper()
                if not cve_id:
                    continue
                parsed = self.search_cves(cveId=cve_id, max_results=1)
                if not parsed:
                    self.console.print(f"[yellow]No results for {cve_id}[/yellow]")
                    continue
                self._interactive_paged_display(parsed)

            elif choice == "2":
                keyword = Prompt.ask("Enter search keyword").strip()
                if not keyword:
                    continue
                limit = Prompt.ask(f"Max results (default {DEFAULT_MAX_RESULTS})",
                                   default=str(DEFAULT_MAX_RESULTS))
                try:
                    limit_i = int(limit)
                except Exception:
                    limit_i = DEFAULT_MAX_RESULTS

                rows = self.search_cves(keywordSearch=keyword,
                                        max_results=min(limit_i, 2000))
                if not rows:
                    self.console.print("[yellow]No results returned or network error.[/yellow]")
                    continue

                if Confirm.ask("Filter results by severity?"):
                    choices = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                    for idx, val in enumerate(choices, start=1):
                        self.console.print(f"{idx}) {val}")

                    pick = Prompt.ask("Choose severity index",
                                      choices=[str(i) for i in range(1, len(choices) + 1)],
                                      default="1")
                    sev = choices[int(pick) - 1]

                    rows = [
                        r for r in rows
                        if (r.get("severity") == sev or
                            (r.get("cvss_score") is not None
                             and self.score_to_severity(r.get("cvss_score")) == sev))
                    ]

                self._interactive_paged_display(rows)

            elif choice == "4":
                params = {}
                self.console.print("[bold]Enter advanced parameters. Leave blank to skip.[/bold]")

                params["keywordSearch"] = Prompt.ask("keywordSearch", default="").strip() or None
                params["cpeName"] = Prompt.ask("cpeName", default="").strip() or None
                params["cveId"] = Prompt.ask("cveId", default="").strip() or None
                params["cvssV3Severity"] = (
                    Prompt.ask("cvssV3Severity (LOW/MEDIUM/HIGH/CRITICAL)", default="")
                    .strip() or None
                )
                params["hasKev"] = Confirm.ask("hasKev?", default=False)
                params["noRejected"] = Confirm.ask("noRejected?", default=False)

                try:
                    limit = int(Prompt.ask("Max results",
                                           default=str(DEFAULT_MAX_RESULTS)))
                except:
                    limit = DEFAULT_MAX_RESULTS

                rows = self.search_cves(
                    keywordSearch=params.get("keywordSearch"),
                    cpeName=params.get("cpeName"),
                    cveId=params.get("cveId"),
                    cvssV3Severity=params.get("cvssV3Severity"),
                    hasKev=params.get("hasKev", False),
                    noRejected=params.get("noRejected", False),
                    max_results=min(limit, 2000)
                )

                if not rows:
                    self.console.print("[yellow]No results returned or network error.[/yellow]")
                    continue

                self._interactive_paged_display(rows)


reporter = NvdCveReporter()

