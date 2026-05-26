"""Threat report generation engine."""

from __future__ import annotations

import uuid
from collections import Counter
from typing import Any

from threatlens.database import Database
from threatlens.models import Alert, Campaign, CorrelatedEvent, RawSignal, ThreatReport


class ReportGenerator:
    def __init__(self, db: Database | None = None) -> None:
        self.db = db

    def generate(
        self,
        report_type: str,
        signals: list[RawSignal],
        correlated_events: list[CorrelatedEvent],
        alerts: list[Alert],
        campaigns: list[Campaign],
        period_start: str = "",
        period_end: str = "",
    ) -> ThreatReport:
        top_ttps = self._compute_top_ttps(signals, correlated_events)
        top_sources = self._compute_source_distribution(signals)
        severity_dist = self._compute_severity_distribution(signals, alerts)
        campaign_summaries = self._summarize_campaigns(campaigns)
        recommendations = self._generate_recommendations(alerts, campaigns, severity_dist)

        total_alerts = len(alerts)
        total_campaigns = len(campaigns)
        total_signals = len(signals)

        report = ThreatReport(
            id=f"report-{uuid.uuid4().hex[:12]}",
            report_type=report_type,
            title=f"ThreatLens {report_type.capitalize()} Report",
            summary=self._generate_summary(
                report_type, total_signals, total_alerts, total_campaigns
            ),
            period_start=period_start,
            period_end=period_end,
            total_signals=total_signals,
            total_alerts=total_alerts,
            total_campaigns=total_campaigns,
            top_ttps=top_ttps[:10],
            top_sources=top_sources,
            severity_distribution=severity_dist,
            campaign_summaries=campaign_summaries,
            recommendations=recommendations,
        )

        if self.db:
            self.db.save_report(report)

        return report

    def _compute_top_ttps(
        self,
        signals: list[RawSignal],
        events: list[CorrelatedEvent],
    ) -> list[dict[str, Any]]:
        ttp_counter: Counter = Counter()
        for event in events:
            for ttp in event.ttps:
                ttp_counter[ttp.get("id", "unknown")] += 1

        return [{"ttp_id": ttp_id, "count": count} for ttp_id, count in ttp_counter.most_common(20)]

    def _compute_source_distribution(self, signals: list[RawSignal]) -> dict[str, int]:
        return dict(Counter(s.source.value for s in signals).most_common())

    def _compute_severity_distribution(
        self, signals: list[RawSignal], alerts: list[Alert]
    ) -> dict[str, int]:
        dist: dict[str, int] = {}
        for sig in signals:
            key = sig.severity.value
            dist[key] = dist.get(key, 0) + 1
        for alert in alerts:
            key = alert.severity.value
            dist[key] = dist.get(key, 0) + 1
        return dist

    def _summarize_campaigns(self, campaigns: list[Campaign]) -> list[dict[str, Any]]:
        return [
            {
                "campaign_id": c.id,
                "name": c.name,
                "severity": c.severity.value,
                "signal_count": len(c.signals),
                "ttp_count": len(c.ttps),
                "first_seen": c.first_seen,
                "last_seen": c.last_seen,
                "active": c.active,
                "tags": c.tags,
            }
            for c in campaigns
        ]

    def _generate_summary(
        self,
        report_type: str,
        total_signals: int,
        total_alerts: int,
        total_campaigns: int,
    ) -> str:
        return (
            f"{report_type.capitalize()} threat assessment: "
            f"{total_signals} signals aggregated, "
            f"{total_alerts} alerts generated, "
            f"{total_campaigns} campaigns active."
        )

    def _generate_recommendations(
        self,
        alerts: list[Alert],
        campaigns: list[Campaign],
        severity_dist: dict[str, int],
    ) -> list[str]:
        recs: list[str] = []

        critical_count = severity_dist.get("critical", 0)
        if critical_count > 0:
            recs.append(
                f"Immediate action required: {critical_count} critical severity events detected"
            )

        if campaigns:
            recs.append(f"Investigate {len(campaigns)} active threat campaigns")

        high_alerts = sum(1 for a in alerts if a.severity.value == "high")
        if high_alerts > 5:
            recs.append(f"High alert volume ({high_alerts}) suggests ongoing coordinated activity")

        recs.append("Review and update security policies for AI/ML systems")
        recs.append("Ensure all MCP tools are running latest versions")
        recs.append("Validate threat feed integrations are healthy")

        return recs
