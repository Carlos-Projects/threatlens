"""Palisade Scanner source client."""

from __future__ import annotations

from typing import Any

import httpx
from mcp_taxonomy import palisade_finding_to_taxonomy

from threatlens.models import RawSignal, SignalSource
from threatlens.sources.base import SourceClient


class PalisadeClient(SourceClient):
    name = "palisade"

    def __init__(self, base_url: str = "http://localhost:8082") -> None:
        self.base_url = base_url.rstrip("/")

    async def fetch(self, **kwargs: Any) -> list[RawSignal]:
        url = f"{self.base_url}/api/v1/scans"
        params = {"limit": kwargs.get("limit", 100)}
        signals: list[RawSignal] = []

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, params=params)
                response.raise_for_status()
                scans = response.json()
        except Exception:
            return signals

        for scan in scans:
            findings = scan.get("findings", scan if isinstance(scan, list) else [scan])
            for finding in findings:
                tax = palisade_finding_to_taxonomy(finding)
                signals.append(
                    RawSignal(
                        source=SignalSource.PALISADE,
                        source_id=f"palisade-{tax.timestamp}",
                        category=tax.attack_category,
                        severity=tax.severity,
                        confidence=tax.confidence,
                        title=tax.title,
                        description=tax.description,
                        recommendation=tax.recommendation,
                        detection_method=str(tax.detection_method),
                        target=tax.target,
                        snippet=tax.snippet,
                        raw_data=tax.raw or finding,
                        timestamp=tax.timestamp,
                        risk_score=tax.risk_score,
                    )
                )
        return signals
