"""Advisory fetcher — retrieves security advisories from external sources."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx


class AdvisoryFetcher:
    def __init__(self) -> None:
        self.sources = {
            "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "osv": "https://api.osv.dev/v1/query",
        }

    async def fetch_recent(self, days: int = 7, limit: int = 50) -> list[dict[str, Any]]:
        advisories: list[dict[str, Any]] = []

        nvd_advisories = await self._fetch_nvd_recent(days, limit)
        advisories.extend(nvd_advisories)

        return advisories

    async def _fetch_nvd_recent(self, days: int, limit: int) -> list[dict[str, Any]]:
        from datetime import timedelta

        pub_start = (datetime.now(UTC) - timedelta(days=days)).strftime(
            "%Y-%m-%dT%H:%M:%S.000"
        )

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                response = await client.get(
                    self.sources["nvd"],
                    params={
                        "pubStartDate": pub_start,
                        "resultsPerPage": min(limit, 200),
                    },
                )
                response.raise_for_status()
                data = response.json()
                advisories: list[dict[str, Any]] = []
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    advisories.append(
                        {
                            "source": "nvd",
                            "id": cve.get("id", ""),
                            "published": cve.get("published", ""),
                            "description": self._get_description(cve),
                            "severity": self._get_severity(cve),
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
                        }
                    )
                return advisories
            except Exception:
                return []

    async def query_osv(self, package: str, ecosystem: str = "PyPI") -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                response = await client.post(
                    self.sources["osv"],
                    json={
                        "package": {"name": package, "ecosystem": ecosystem},
                        "version": "",
                    },
                )
                response.raise_for_status()
                data = response.json()
                return [
                    {
                        "source": "osv",
                        "id": vuln.get("id", ""),
                        "summary": vuln.get("summary", ""),
                        "aliases": vuln.get("aliases", []),
                        "severity": vuln.get("severity", []),
                    }
                    for vuln in data.get("vulns", [])
                ]
            except Exception:
                return []

    def _get_description(self, cve: dict[str, Any]) -> str:
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                return desc.get("value", "")
        return ""

    def _get_severity(self, cve: dict[str, Any]) -> str:
        metrics = cve.get("metrics", {})
        cvss = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        return cvss.get("baseSeverity", "UNKNOWN")
