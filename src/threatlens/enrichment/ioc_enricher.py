"""IOC enrichment — extracts and enriches indicators of compromise."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

import httpx

IOC_PATTERNS: dict[str, str] = {
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "url": r"https?://[^\s<>\"']+",
    "hash_md5": r"\b[0-9a-fA-F]{32}\b",
    "hash_sha1": r"\b[0-9a-fA-F]{40}\b",
    "hash_sha256": r"\b[0-9a-fA-F]{64}\b",
    "cve": r"CVE-\d{4}-\d{4,7}",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
}


class IOCEnricher:
    def extract_iocs(self, text: str) -> dict[str, list[str]]:
        iocs: dict[str, list[str]] = {
            "ipv4": [],
            "domain": [],
            "url": [],
            "hash_md5": [],
            "hash_sha1": [],
            "hash_sha256": [],
            "cve": [],
            "email": [],
        }

        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = re.findall(pattern, text)
            if ioc_type == "ipv4":
                matches = [m for m in matches if self._is_valid_ip(m)]
            iocs[ioc_type] = list(set(matches))

        return {k: v for k, v in iocs.items() if v}

    def _is_valid_ip(self, ip_str: str) -> bool:
        try:
            ipaddress.ip_address(ip_str)
            parts = [int(p) for p in ip_str.split(".")]
            return all(0 <= p <= 255 for p in parts)
        except ValueError:
            return False

    async def enrich_ip(self, ip: str) -> dict[str, Any]:
        result: dict[str, Any] = {"ip": ip, "source": "abuseipdb"}
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                response = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": "", "Accept": "application/json"},
                    timeout=5.0,
                )
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    result.update(
                        {
                            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                            "country": data.get("countryCode", ""),
                            "isp": data.get("isp", ""),
                            "domain": data.get("domain", ""),
                            "total_reports": data.get("totalReports", 0),
                            "last_reported": data.get("lastReportedAt", ""),
                        }
                    )
            except Exception:
                result["error"] = "Failed to query AbuseIPDB"

        return result
