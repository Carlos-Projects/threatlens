"""Executive report generator — high-level summaries for management."""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import UTC, datetime

from threatlens.database import Database
from threatlens.models import Alert, Campaign, RawSignal, ThreatReport


class ExecutiveReportGenerator:
    def __init__(self, db: Database | None = None) -> None:
        self.db = db

    def generate(
        self,
        signals: list[RawSignal],
        alerts: list[Alert],
        campaigns: list[Campaign],
        period_label: str = "",
    ) -> ThreatReport:
        critical_alerts = [a for a in alerts if a.severity.value == "critical"]
        high_alerts = [a for a in alerts if a.severity.value == "high"]

        top_sources = dict(Counter(s.source.value for s in signals).most_common())
        severity_dist = dict(Counter(s.severity.value for s in signals))
        for a in alerts:
            severity_dist[a.severity.value] = severity_dist.get(a.severity.value, 0) + 1

        campaign_count = len(campaigns)
        active_campaigns = [c for c in campaigns if c.active]
        signal_count = len(signals)

        executive_summary = (
            f"ThreatLens Executive Summary ({period_label or 'Current Period'})\n\n"
            f"Overview: {signal_count} threat signals analyzed, "
            f"{len(alerts)} alerts generated, "
            f"{campaign_count} campaigns detected "
            f"({len(active_campaigns)} active).\n\n"
            f"Critical Issues: {len(critical_alerts)} critical alerts "
            f"requiring immediate attention.\n"
            f"High Risk: {len(high_alerts)} high-severity incidents identified."
        )

        recommendations = [
            f"Address {len(critical_alerts)} critical alerts immediately",
            f"Investigate {len(active_campaigns)} active threat campaigns",
            "Review and update AI security policies",
            "Validate all security tool integrations",
        ]

        if len(critical_alerts) > 5:
            recommendations.insert(0, "SCHEDULE EMERGENCY INCIDENT RESPONSE REVIEW")

        from datetime import timedelta

        period_end = datetime.now(UTC).isoformat()
        period_start = (datetime.now(UTC) - timedelta(days=30)).isoformat()

        report = ThreatReport(
            id=f"exec-{uuid.uuid4().hex[:12]}",
            report_type="executive",
            title=f"Executive Threat Summary \u2014 {period_label or 'Current Period'}",
            summary=f"Executive summary of threat landscape: "
            f"{len(critical_alerts)} critical, "
            f"{len(high_alerts)} high alerts",
            period_start=period_start,
            period_end=period_end,
            generated_at=period_end,
            total_signals=signal_count,
            total_alerts=len(alerts),
            total_campaigns=campaign_count,
            top_sources=top_sources,
            severity_distribution=severity_dist,
            campaign_summaries=[
                {
                    "id": c.id,
                    "name": c.name,
                    "severity": c.severity.value,
                    "active": c.active,
                    "signal_count": len(c.signals),
                }
                for c in campaigns[:10]
            ],
            executive_summary=executive_summary,
            recommendations=recommendations,
        )

        if self.db:
            self.db.save_report(report)

        return report
