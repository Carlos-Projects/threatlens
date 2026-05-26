"""Reverse-Abliterate scan source client."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_taxonomy import AttackCategory, Confidence, DetectionMethod, Severity, TaxonomyEvent

from threatlens.models import RawSignal, SignalSource
from threatlens.sources.base import SourceClient


def _abliterate_to_taxonomy(scan: dict[str, Any]) -> TaxonomyEvent:
    category = AttackCategory.MISCONFIGURATION
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    title = scan.get("title", "Reverse-Abliterate Scan Result")
    description = scan.get("description", "")
    recommendation = scan.get("recommendation", "")
    target = scan.get("model_path", scan.get("target", ""))
    snippet = scan.get("snippet", "")
    risk_score = scan.get("risk_score", 30)

    if (scan.get("anomalies") or scan.get("safety_violations")) and any(
        "abliteration" in str(a).lower() for a in scan.get("anomalies", [])
    ):
        category = AttackCategory.TOOL_POISONING
        severity = Severity.HIGH
        risk_score = max(risk_score, 60)

    return TaxonomyEvent(
        source="reverse-abliterate",
        attack_category=category,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        recommendation=recommendation,
        detection_method=DetectionMethod.METADATA_ANALYZER,
        target=target,
        snippet=snippet,
        raw=scan,
        risk_score=risk_score,
    )


class AbliterateClient(SourceClient):
    name = "abliterate"

    def __init__(self, scan_dir: str = "~/.reverse-abliterate/scans") -> None:
        self.scan_dir = Path(scan_dir).expanduser()

    async def fetch(self, **kwargs: Any) -> list[RawSignal]:
        signals: list[RawSignal] = []
        if not self.scan_dir.exists():
            return signals

        for fpath in sorted(self.scan_dir.glob("*.json")):
            scan = json.loads(fpath.read_text())
            tax = _abliterate_to_taxonomy(scan)
            signals.append(
                RawSignal(
                    source=SignalSource.ABLITERATE,
                    source_id=f"abliterate-{fpath.stem}",
                    category=tax.attack_category,
                    severity=tax.severity,
                    confidence=tax.confidence,
                    title=tax.title,
                    description=tax.description,
                    recommendation=tax.recommendation,
                    detection_method=str(tax.detection_method),
                    target=tax.target,
                    snippet=tax.snippet,
                    raw_data=tax.raw or scan,
                    timestamp=tax.timestamp,
                    risk_score=tax.risk_score,
                    tags=["model-scan", "abliteration"],
                )
            )
        return signals
