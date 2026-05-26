"""MCPwn findings source client."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_taxonomy import mcpwn_finding_to_taxonomy

from threatlens.models import RawSignal, SignalSource
from threatlens.sources.base import SourceClient


class MCPwnClient(SourceClient):
    name = "mcpwn"

    def __init__(self, results_dir: str = "~/.mcpwn/results") -> None:
        self.results_dir = Path(results_dir).expanduser()

    async def fetch(self, **kwargs: Any) -> list[RawSignal]:
        signals: list[RawSignal] = []
        results_path = self.results_dir
        if not results_path.exists():
            return signals

        for fpath in sorted(results_path.glob("*.json")):
            raw = json.loads(fpath.read_text())
            findings = raw if isinstance(raw, list) else [raw]
            for finding in findings:
                tax = mcpwn_finding_to_taxonomy(finding)
                signals.append(
                    RawSignal(
                        source=SignalSource.MCPWN,
                        source_id=f"mcpwn-{fpath.stem}",
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
