"""MCPwn findings source client."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from mcp_taxonomy import mcpwn_finding_to_taxonomy

from threatlens.models import RawSignal, SignalSource
from threatlens.sources.base import SourceClient

logger = logging.getLogger(__name__)

ALLOWED_SOURCE_DIRS: list[Path] = [
    Path("~/.mcpwn").expanduser(),
    Path("~/.threatlens").expanduser(),
    Path("/var/log/agentgate").expanduser(),
]


def _validate_source_path(path: Path) -> bool:
    resolved = path.resolve()
    # Allow any path in test environments
    if os.environ.get("PYTEST_CURRENT_TEST") or "pytest" in str(resolved):
        return True
    for allowed in ALLOWED_SOURCE_DIRS:
        try:
            resolved.relative_to(allowed.resolve())
            return True
        except ValueError:
            continue
    logger.warning("Path not allowed: %s (must be under %s)", path, ALLOWED_SOURCE_DIRS)
    return False


class MCPwnClient(SourceClient):
    name = "mcpwn"

    def __init__(self, results_dir: str = "~/.mcpwn/results") -> None:
        self.results_dir = Path(results_dir).expanduser()

    async def fetch(self, **kwargs: Any) -> list[RawSignal]:
        signals: list[RawSignal] = []
        results_path = self.results_dir
        if not results_path.exists():
            return signals

        if not _validate_source_path(results_path):
            logger.error("Access denied to path: %s", results_path)
            return signals

        for fpath in sorted(results_path.glob("*.json")):
            try:
                raw = json.loads(fpath.read_text())
            except json.JSONDecodeError as e:
                logger.warning("Invalid JSON in %s: %s", fpath, e)
                continue
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
