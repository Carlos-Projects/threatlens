"""Shared data models for the ThreatLens engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from mcp_taxonomy import AttackCategory, Confidence, DetectionMethod, Severity


class SignalSource(StrEnum):
    MCPGUARD = "mcpguard"
    MCPWN = "mcpwn"
    PALISADE = "palisade"
    AGENTGATE = "agentgate"
    ABLITERATE = "abliterate"
    EXTERNAL = "external"


@dataclass
class RawSignal:
    source: SignalSource
    source_id: str
    category: AttackCategory
    severity: Severity
    confidence: Confidence
    title: str
    description: str = ""
    recommendation: str = ""
    detection_method: DetectionMethod | str = ""
    target: str = ""
    snippet: str = ""
    raw_data: dict[str, Any] | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    blocked: bool | None = None
    risk_score: int = 0
    tags: list[str] = field(default_factory=list)

    @property
    def normalized_timestamp(self) -> datetime:
        return datetime.fromisoformat(self.timestamp)


@dataclass
class CorrelatedEvent:
    id: str
    signals: list[RawSignal]
    correlation_type: str
    correlation_score: float
    title: str
    description: str
    ttps: list[dict[str, Any]] = field(default_factory=list)
    campaign_id: str = ""
    first_seen: str = ""
    last_seen: str = ""
    severity: Severity = Severity.INFO
    enriched: dict[str, Any] = field(default_factory=dict)

    @property
    def risk_score(self) -> int:
        scores = [s.risk_score for s in self.signals if s.risk_score]
        if not scores:
            return 0
        if len(scores) > 1:
            return min(100, int(max(scores) * 1.5))
        return max(scores)


@dataclass
class Alert:
    id: str
    title: str
    description: str
    severity: Severity
    correlation_ids: list[str]
    signal_ids: list[str]
    ttps: list[dict[str, Any]]
    enriched: dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    acknowledged: bool = False
    notified: bool = False

    @property
    def risk_score(self) -> int:
        return self.severity.weight * 4


@dataclass
class ThreatReport:
    id: str
    report_type: str
    title: str
    summary: str
    period_start: str
    period_end: str
    generated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    total_signals: int = 0
    total_alerts: int = 0
    total_campaigns: int = 0
    top_ttps: list[dict[str, Any]] = field(default_factory=list)
    top_sources: dict[str, int] = field(default_factory=dict)
    severity_distribution: dict[str, int] = field(default_factory=dict)
    campaign_summaries: list[dict[str, Any]] = field(default_factory=list)
    executive_summary: str = ""
    recommendations: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] | None = None


@dataclass
class Campaign:
    id: str
    name: str
    description: str
    severity: Severity
    signals: list[RawSignal]
    events: list[CorrelatedEvent] = field(default_factory=list)
    ttps: list[dict[str, Any]] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    active: bool = True
    tags: list[str] = field(default_factory=list)
