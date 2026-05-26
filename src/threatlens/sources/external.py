"""External threat intelligence source client (CVEs, ATLAS, advisories)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
from mcp_taxonomy import AttackCategory, Confidence, DetectionMethod, Severity

from threatlens.models import RawSignal, SignalSource
from threatlens.sources.base import SourceClient


def _cve_to_signal(cve: dict[str, Any]) -> RawSignal:
    cve_id = cve.get("id", "CVE-UNKNOWN")
    desc = cve.get("descriptions", [{}])
    description = ""
    for d in desc:
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    metrics = cve.get("metrics", {})
    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
    base_score = cvss_v3.get("baseScore", 0)
    severity_str = cvss_v3.get("baseSeverity", "MEDIUM").lower()
    severity = Severity.HIGH if severity_str == "critical" else Severity(severity_str)
    risk_score = min(100, int(base_score * 10))

    return RawSignal(
        source=SignalSource.EXTERNAL,
        source_id=cve_id,
        category=AttackCategory.MALWARE,
        severity=severity,
        confidence=Confidence.HIGH,
        title=f"CVE: {cve_id}",
        description=description,
        recommendation="Apply vendor patches and verify mitigations.",
        detection_method=DetectionMethod.INJECTION_PATTERNS,
        target="",
        snippet=cve_id,
        raw_data=cve,
        timestamp=datetime.now(UTC).isoformat(),
        risk_score=risk_score,
        tags=["cve", "external"],
    )


class ExternalClient(SourceClient):
    name = "external"

    def __init__(
        self,
        nvd_api_key: str = "",
        nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0",
    ) -> None:
        self.nvd_api_key = nvd_api_key
        self.nvd_base_url = nvd_base_url

    async def fetch_cves(self, keywords: list[str], limit: int = 50) -> list[RawSignal]:
        signals: list[RawSignal] = []
        headers: dict[str, str] = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        params: dict[str, str | int] = {
            "keywordSearch": " ".join(keywords),
            "resultsPerPage": min(limit, 200),
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(self.nvd_base_url, params=params, headers=headers)
                response.raise_for_status()
                data = response.json()
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    signals.append(_cve_to_signal(cve))
            except Exception:
                pass

        return signals

    async def fetch(self, **kwargs: Any) -> list[RawSignal]:
        keywords = kwargs.get("keywords", ["mcp", "ai", "llm", "prompt injection"])
        return await self.fetch_cves(keywords=keywords, limit=kwargs.get("limit", 50))
