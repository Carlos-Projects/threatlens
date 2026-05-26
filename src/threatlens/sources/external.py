"""External threat intelligence source client (CVEs, ATLAS, advisories)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import httpx
from mcp_taxonomy import AttackCategory, Confidence, DetectionMethod, Severity

from threatlens.models import RawSignal, SignalSource
from threatlens.sources.base import SourceClient

logger = logging.getLogger(__name__)

CWE_CATEGORY_MAP: dict[str, AttackCategory] = {
    "CWE-77": AttackCategory.CMD_INJECTION,
    "CWE-78": AttackCategory.CMD_INJECTION,
    "CWE-88": AttackCategory.CMD_INJECTION,
    "CWE-89": AttackCategory.SQL_INJECTION,
    "CWE-90": AttackCategory.CMD_INJECTION,
    "CWE-91": AttackCategory.CMD_INJECTION,
    "CWE-94": AttackCategory.RCE,
    "CWE-95": AttackCategory.RCE,
    "CWE-98": AttackCategory.RCE,
    "CWE-116": AttackCategory.INJECTION,
    "CWE-200": AttackCategory.EXFILTRATION,
    "CWE-201": AttackCategory.EXFILTRATION,
    "CWE-287": AttackCategory.IMPERSONATION,
    "CWE-288": AttackCategory.IMPERSONATION,
    "CWE-306": AttackCategory.IMPERSONATION,
    "CWE-352": AttackCategory.IMPERSONATION,
    "CWE-400": AttackCategory.RESOURCE_SCAN,
    "CWE-434": AttackCategory.MALWARE,
    "CWE-502": AttackCategory.RCE,
    "CWE-601": AttackCategory.SSRF,
    "CWE-611": AttackCategory.SSRF,
    "CWE-798": AttackCategory.IMPERSONATION,
    "CWE-862": AttackCategory.IMPERSONATION,
    "CWE-863": AttackCategory.IMPERSONATION,
    "CWE-915": AttackCategory.INJECTION,
    "CWE-918": AttackCategory.SSRF,
    "CWE-1193": AttackCategory.MALWARE,
}

CATEGORY_DETECTION_METHOD: dict[AttackCategory, DetectionMethod] = {
    AttackCategory.CMD_INJECTION: DetectionMethod.INJECTION_PATTERNS,
    AttackCategory.SQL_INJECTION: DetectionMethod.INJECTION_PATTERNS,
    AttackCategory.RCE: DetectionMethod.INJECTION_PATTERNS,
    AttackCategory.INJECTION: DetectionMethod.INJECTION_PATTERNS,
    AttackCategory.EXFILTRATION: DetectionMethod.EXFILTRATION,
    AttackCategory.IMPERSONATION: DetectionMethod.METADATA_ANALYZER,
    AttackCategory.RESOURCE_SCAN: DetectionMethod.ANOMALY_DETECTOR,
    AttackCategory.MALWARE: DetectionMethod.INSTRUCTION_CLASSIFIER,
    AttackCategory.SSRF: DetectionMethod.ANOMALY_DETECTOR,
    AttackCategory.STEGO: DetectionMethod.STEGO_MARKERS,
}


def _infer_category_from_cwe(cve: dict[str, Any]) -> AttackCategory | None:
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            cwe_id = desc.get("value", "")
            if cwe_id in CWE_CATEGORY_MAP:
                return CWE_CATEGORY_MAP[cwe_id]
    return None


def _infer_category_from_text(description: str) -> AttackCategory | None:
    text = description.lower()
    patterns: list[tuple[list[str], AttackCategory]] = [
        (["remote code execution", "rce", "arbitrary code", "code execution"], AttackCategory.RCE),
        (["command injection", "os command", "shell command"], AttackCategory.CMD_INJECTION),
        (["sql injection", "sqli", "sql command"], AttackCategory.SQL_INJECTION),
        (
            ["server-side request forgery", "ssrf", "server side request forgery"],
            AttackCategory.SSRF,
        ),
        (["cross-site scripting", "xss", "injection"], AttackCategory.INJECTION),
        (
            ["information disclosure", "information exposure", "data leak"],
            AttackCategory.EXFILTRATION,
        ),
        (
            ["privilege escalation", "authentication bypass", "auth bypass"],
            AttackCategory.IMPERSONATION,
        ),
        (["denial of service", "dos", "resource exhaustion"], AttackCategory.RESOURCE_SCAN),
        (["steganography", "stego", "covert channel"], AttackCategory.STEGO),
        (["malware", "trojan", "backdoor", "virus", "worm"], AttackCategory.MALWARE),
    ]
    for keywords, category in patterns:
        if any(kw in text for kw in keywords):
            return category
    return None


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
    severity = Severity.CRITICAL if severity_str == "critical" else Severity(severity_str)
    risk_score = min(100, int(base_score * 10))

    category = (
        _infer_category_from_cwe(cve)
        or _infer_category_from_text(description)
        or AttackCategory.MALWARE
    )
    detection_method = CATEGORY_DETECTION_METHOD.get(category, DetectionMethod.INJECTION_PATTERNS)

    return RawSignal(
        source=SignalSource.EXTERNAL,
        source_id=cve_id,
        category=category,
        severity=severity,
        confidence=Confidence.HIGH,
        title=f"CVE: {cve_id}",
        description=description,
        recommendation="Apply vendor patches and verify mitigations.",
        detection_method=detection_method,
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

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
            try:
                response = await client.get(self.nvd_base_url, params=params, headers=headers)
                response.raise_for_status()
                data = response.json()
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    signals.append(_cve_to_signal(cve))
            except Exception as e:
                logger.warning("NVD fetch error: %s", e)

        return signals

    async def fetch(self, **kwargs: Any) -> list[RawSignal]:
        keywords = kwargs.get("keywords", ["mcp", "ai", "llm", "prompt injection"])
        return await self.fetch_cves(keywords=keywords, limit=kwargs.get("limit", 50))
