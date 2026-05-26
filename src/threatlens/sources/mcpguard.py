"""MCPGuard event source client."""

from __future__ import annotations

import logging
from typing import Any

import httpx
from mcp_taxonomy import mcpguard_event_to_taxonomy

from threatlens.models import RawSignal, SignalSource
from threatlens.sources.base import SourceClient

logger = logging.getLogger(__name__)


class MCPGuardClient(SourceClient):
    name = "mcpguard"

    def __init__(self, base_url: str = "http://localhost:8081") -> None:
        self.base_url = base_url.rstrip("/")

    async def fetch(self, **kwargs: Any) -> list[RawSignal]:
        url = f"{self.base_url}/api/v1/events"
        params = {"limit": kwargs.get("limit", 100)}
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
                response = await client.get(url, params=params)
                response.raise_for_status()
                events = response.json()
        except Exception as e:
            logger.warning("MCPGuard fetch error from %s: %s", self.base_url, e)
            return []

        signals: list[RawSignal] = []
        for event in events:
            tax = mcpguard_event_to_taxonomy(event)
            signals.append(
                RawSignal(
                    source=SignalSource.MCPGUARD,
                    source_id=f"mcpguard-{tax.timestamp}",
                    category=tax.attack_category,
                    severity=tax.severity,
                    confidence=tax.confidence,
                    title=tax.title,
                    description=tax.description,
                    recommendation=tax.recommendation,
                    detection_method=str(tax.detection_method),
                    target=tax.target,
                    snippet=tax.snippet,
                    raw_data=tax.raw or event,
                    timestamp=tax.timestamp,
                    blocked=tax.blocked,
                    risk_score=tax.risk_score,
                )
            )
        return signals
