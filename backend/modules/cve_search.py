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
    description = "Live NVD CVE Reporter (NVD API v2.0) — search CVEs live and show publish dates & CVSS"

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
        return {
            "id": cve_id,
            "published": str(published),
            "lastModified": str(last_modified),
            "summary": summary.strip(),
            "cvss_score": cvss_score,
            "severity": severity.upper() if severity else "N/A",
            "references": refs
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
        if s.startswith("CVSSV2"):
            return f"[magenta]{sev}[/magenta]"
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

    def fetch_cves_keyword(self, keyword: str, max_results: int = DEFAULT_MAX_RESULTS) -> List[Dict[str, Any]]:
        """
        Query NVD using keywordSearch and return parsed CVE rows.
        """
        results: List[Dict[str, Any]] = []
        params = {"keywordSearch": keyword}
        with Progress() as progress:
            task = progress.add_task(f"[cyan]Querying NVD for '{keyword}'...", start=False)
            start_index = 0
            fetched = 0
            while True:
                progress.update(task, description=f"[cyan]Fetching startIndex={start_index}...")
                data = self._request(params, start_index=start_index)
                if data is None:
                    break
                vulnerabilities = data.get("vulnerabilities", []) or []
                total_results = data.get("totalResults", 0) or data.get("total", 0) or 0
                if not vulnerabilities:
                    break
                for v in vulnerabilities:
                    parsed = self._parse_cve_item(v)
                    results.append(parsed)
                    fetched += 1
                    if fetched >= max_results:
                        break
                if fetched >= max_results or (start_index + len(vulnerabilities)) >= total_results:
                    break
                start_index += len(vulnerabilities)
                time.sleep(self.paged_sleep)
            progress.update(task, completed=True)
        return results

    def fetch_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a single CVE record by ID.
        """
        params = {"cveId": cve_id}
        data = self._request(params, start_index=0)
        if not data:
            return None
        vulnerabilities = data.get("vulnerabilities") or []
        if not vulnerabilities:
            return None
        parsed = self._parse_cve_item(vulnerabilities[0])
        return parsed

    def fetch_newest_cves(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Fetch newest CVEs without using date filters (avoids 404 when system clock is wrong).
        We simply sort by lastModified descending and take the first N.
        """
        results = []
        params = {
            "sortBy": "lastModified",
            "sortOrder": "desc"
        }

        start_index = 0
        fetched = 0

        with Progress() as progress:
            task = progress.add_task("[cyan]Fetching newest CVEs...", start=False)

            while fetched < limit:
                data = self._request(params, start_index=start_index)
                if not data:
                    break

                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    break

                for v in vulns:
                    parsed = self._parse_cve_item(v)
                    results.append(parsed)
                    fetched += 1
                    if fetched >= limit:
                        break

                start_index += len(vulns)
                time.sleep(self.paged_sleep)

            progress.update(task, completed=True)

        return results

    def show_newest_cves(self, limit: int = 20):
        cves = self.fetch_newest_cves(limit)
        if not cves:
            self.console.print("[red]No CVEs found.[/red]")
            return
        table = Table(title=f"Top {limit} Newest CVEs", show_lines=True)
        table.add_column("CVE ID", style="cyan", overflow="fold")
        table.add_column("Published", style="green")
        table.add_column("Severity", style="magenta")
        table.add_column("Score", style="yellow")
        table.add_column("Description", overflow="fold")
        for c in cves:
            table.add_row(
                c["id"],
                c["published"][:19],
                self.severity_color_label(c["severity"]),
                str(c["cvss_score"]) if c["cvss_score"] else "N/A",
                textwrap.shorten(c["summary"], width=140)
            )
        self.console.print(table)

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
                f.write(f"- **Severity:** {r.get('severity')}\n\n")
                f.write("**Summary:**\n\n")
                f.write(textwrap.fill(r.get("summary") or "", width=100))
                f.write("\n\n---\n\n")

    def _write_html(self, rows: List[Dict[str, Any]], path: str):
        html_rows = []
        for r in rows:
            html_rows.append(f"""
            <tr>
              <td>{r.get('id')}</td>
              <td>{r.get('published')}</td>
              <td>{r.get('lastModified')}</td>
              <td>{r.get('cvss_score') or 'N/A'}</td>
              <td>{r.get('severity')}</td>
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

    def run(self):
        self.console.print("[bold green]BlackICE - NVD CVE Live Reporter[/bold green]")
        if self.api_key:
            self.console.print(f"[dim]Using NVD API key from environment.[/dim]")
        while True:
            self.console.print("\n[bold]Options[/bold]")
            self.console.print("1) Lookup CVE by ID (e.g. CVE-2023-1234)")
            self.console.print("2) Search by keyword (e.g. openssl, apache, rce)")
            self.console.print("3) Show Top Newest CVE's")
            self.console.print("0) Exit")
            choice = Prompt.ask("Choose", choices=["0", "1", "2", "3"], default="0")
            if choice == "0":
                self.console.print("Exiting NVD CVE Reporter.")
                return
            if choice == "1":
                cve_id = Prompt.ask("Enter CVE ID").strip().upper()
                if not cve_id:
                    continue
                self.console.print(f"[blue]Fetching {cve_id}...[/blue]")
                parsed = self.fetch_cve_by_id(cve_id)
                if not parsed:
                    self.console.print(f"[yellow]No results for {cve_id}[/yellow]")
                    continue
                self._interactive_paged_display([parsed])
            elif choice == "2":
                keyword = Prompt.ask("Enter search keyword").strip()
                if not keyword:
                    continue
                limit = Prompt.ask(f"Max results (default {DEFAULT_MAX_RESULTS})", default=str(DEFAULT_MAX_RESULTS))
                try:
                    limit_i = int(limit)
                except Exception:
                    limit_i = DEFAULT_MAX_RESULTS
                limit_i = min(limit_i, 2000)
                self.console.print(f"[blue]Searching NVD for '{keyword}' (up to {limit_i} results)...[/blue]")
                rows = self.fetch_cves_keyword(keyword, max_results=limit_i)
                if not rows:
                    self.console.print("[yellow]No results returned or network error.[/yellow]")
                    continue
                if Confirm.ask("Filter results by severity?"):
                    choices = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                    for idx, val in enumerate(choices, start=1):
                        self.console.print(f"{idx}) {val}")
                    pick = Prompt.ask("Choose severity index", choices=[str(i) for i in range(1, len(choices) + 1)], default="1")
                    sev = choices[int(pick) - 1]
                    rows = [r for r in rows if (r.get("severity") == sev or (r.get("cvss_score") is not None and self.score_to_severity(r.get("cvss_score")) == sev))]
                self._interactive_paged_display(rows)
            #elif choice == "3":
            #    limit = Prompt.ask("How many newest CVEs?", default="20")
            #    try:
            #        li = int(limit)
            #    except:
            #        li = 20
            #    self.show_newest_cves(li)


reporter = NvdCveReporter()

