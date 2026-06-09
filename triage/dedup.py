"""Dedup Checker — check findings against known CVEs via NVD API"""

import json
import urllib.request
import urllib.parse
from pathlib import Path


class DedupChecker:
    def __init__(self, nvd_api_key: str = ""):
        self.api_key = nvd_api_key
        self.cache_dir = Path("./output/nvd_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def check(self, finding: dict, project: str) -> str:
        component = finding.get("location", "").split(":")[-1] if ":" in finding.get("location", "") else ""
        if not component:
            return ""
        cache_file = self.cache_dir / f"{project}_{component}.json"
        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    cves = json.load(f)
            except (json.JSONDecodeError, OSError):
                cves = self._query_nvd(project, component)
        else:
            cves = self._query_nvd(project, component)
        bug_type = finding.get("bug_type", "").lower()
        type_kw = {"heap-buffer-overflow": ["buffer overflow", "heap overflow"],
                    "use-after-free": ["use-after-free", "use after free"],
                    "integer-overflow": ["integer overflow"],
                    "null-pointer-dereference": ["null pointer", "null dereference"],
                    "race-condition": ["race condition", "data race"]}
        keywords = type_kw.get(bug_type, [bug_type])
        for cve in cves:
            if any(kw in cve["description"] for kw in keywords):
                return cve["cve_id"]
        return ""

    def _query_nvd(self, project: str, component: str) -> list:
        params = {"keywordSearch": f"{project} {component}", "resultsPerPage": 20}
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{urllib.parse.urlencode(params)}"
        headers = {"apiKey": self.api_key} if self.api_key else {}
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
            cves = []
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln["cve"]["id"]
                descs = vuln["cve"].get("descriptions", [])
                desc = next((d["value"] for d in descs if d["lang"] == "en"), "")
                cves.append({"cve_id": cve_id, "description": desc.lower()})
            return cves
        except Exception:
            return []
