"""CVE lookup enrichment — queries NVD for vulnerability data."""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class CVELookup:
    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def lookup(self, cve_id: str) -> dict[str, Any] | None:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            try:
                response = await client.get(
                    self.base_url,
                    params={"cveId": cve_id},
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve = vulns[0].get("cve", {})
                    return self._parse_cve(cve)
            except Exception as e:
                logger.warning("CVE lookup error for %s: %s", cve_id, e)
                return None
        return None

    async def bulk_lookup(self, cve_ids: list[str]) -> dict[str, dict[str, Any] | None]:
        results: dict[str, dict[str, Any] | None] = {}
        for cve_id in cve_ids:
            results[cve_id] = await self.lookup(cve_id)
        return results

    def _parse_cve(self, cve: dict[str, Any]) -> dict[str, Any]:
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        metrics = cve.get("metrics", {})
        cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        base_score = cvss_data.get("baseScore", 0)
        severity = cvss_data.get("baseSeverity", "UNKNOWN")

        references = [
            {"url": ref.get("url"), "source": ref.get("source")}
            for ref in cve.get("references", [])
        ]

        weaknesses = [
            {"id": w.get("description", [{}])[0].get("value", ""), "source": w.get("source")}
            for w in cve.get("weaknesses", [])
        ]

        return {
            "id": cve_id,
            "description": description,
            "base_score": base_score,
            "severity": severity,
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "references": references,
            "weaknesses": weaknesses,
        }
