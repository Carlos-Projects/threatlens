"""AgentGate signal source client."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_taxonomy import agentgate_signal_to_taxonomy

from threatlens.models import RawSignal, SignalSource
from threatlens.sources.base import SourceClient


class AgentGateClient(SourceClient):
    name = "agentgate"

    def __init__(self, log_path: str = "/var/log/agentgate/access.log") -> None:
        self.log_path = Path(log_path).expanduser()

    async def fetch(self, **kwargs: Any) -> list[RawSignal]:
        signals: list[RawSignal] = []
        if not self.log_path.exists():
            return signals

        content = self.log_path.read_text()
        for line in content.strip().split("\n"):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            signal_type = entry.get("signal_type", entry.get("type", ""))
            weight = entry.get("weight", 0)
            action = entry.get("action", "log_only")
            path = entry.get("path", "")
            user_agent = entry.get("user_agent", entry.get("ua", ""))
            score = entry.get("score", entry.get("risk_score", 0))

            tax = agentgate_signal_to_taxonomy(
                signal_type=signal_type,
                weight=weight,
                action=action,
                path=path,
                user_agent=user_agent,
                score=score,
            )

            signals.append(
                RawSignal(
                    source=SignalSource.AGENTGATE,
                    source_id=f"agentgate-{tax.timestamp}",
                    category=tax.attack_category,
                    severity=tax.severity,
                    confidence=tax.confidence,
                    title=tax.title,
                    description=tax.description,
                    recommendation=tax.recommendation,
                    detection_method=str(tax.detection_method),
                    target=tax.target,
                    snippet=tax.snippet,
                    raw_data=tax.raw or entry,
                    timestamp=tax.timestamp,
                    blocked=tax.blocked,
                    risk_score=tax.risk_score,
                )
            )
        return signals
