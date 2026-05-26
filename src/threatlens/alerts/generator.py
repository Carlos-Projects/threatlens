"""Alert generation engine — creates actionable alerts from correlated events."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from threatlens.database import Database
from threatlens.models import Alert, CorrelatedEvent, RawSignal, Severity

ALERT_RULES: list[dict[str, Any]] = [
    {
        "name": "critical-rce",
        "severity": Severity.CRITICAL,
        "categories": ["rce", "command_injection", "sql_injection"],
        "min_correlation_score": 50,
        "description": "Remote code execution or injection detected",
    },
    {
        "name": "multi-source-campaign",
        "severity": Severity.HIGH,
        "min_sources": 2,
        "min_signals": 3,
        "description": "Multi-source threat campaign detected",
    },
    {
        "name": "temporal-burst",
        "severity": Severity.MEDIUM,
        "min_burst_size": 5,
        "description": "Temporal burst of security signals",
    },
    {
        "name": "data-exfiltration",
        "severity": Severity.HIGH,
        "categories": ["exfiltration"],
        "min_correlation_score": 30,
        "description": "Potential data exfiltration detected",
    },
    {
        "name": "prompt-injection-wave",
        "severity": Severity.HIGH,
        "categories": ["injection", "jailbreak"],
        "min_signals": 3,
        "description": "Wave of prompt injection attempts",
    },
    {
        "name": "tool-poisoning",
        "severity": Severity.HIGH,
        "categories": ["tool_poisoning"],
        "min_correlation_score": 40,
        "description": "Tool poisoning attempt detected",
    },
    {
        "name": "critical-external",
        "severity": Severity.CRITICAL,
        "sources": ["external"],
        "min_signals": 1,
        "description": "Critical external threat intelligence",
    },
]


class AlertGenerator:
    def __init__(self, db: Database | None = None) -> None:
        self.db = db

    def generate(
        self,
        correlated_events: list[CorrelatedEvent],
        signals: list[RawSignal] | None = None,
    ) -> list[Alert]:
        alerts: list[Alert] = []
        seen_rules: set[str] = set()

        for event in correlated_events:
            for rule in ALERT_RULES:
                rule_key = f"{rule['name']}:{event.id}"
                if rule_key in seen_rules:
                    continue

                if not self._matches_rule(event, rule):
                    continue

                alert = Alert(
                    id=f"alert-{uuid.uuid4().hex[:12]}",
                    title=f"{rule['name']}: {event.title[:60]}",
                    description=rule.get("description", event.description),
                    severity=rule.get("severity", event.severity),
                    correlation_ids=[event.id],
                    signal_ids=[s.source_id for s in event.signals],
                    ttps=event.ttps,
                    enriched=event.enriched,
                    timestamp=datetime.now(UTC).isoformat(),
                )
                alerts.append(alert)
                seen_rules.add(rule_key)

        if signals:
            alert_rules_without_events = [
                r
                for r in ALERT_RULES
                if "categories" in r and r.get("min_correlation_score", 0) == 0
            ]
            for rule in alert_rules_without_events:
                matching = [s for s in signals if s.category.value in rule["categories"]]
                if len(matching) >= rule.get("min_signals", 3):
                    alert = Alert(
                        id=f"alert-{uuid.uuid4().hex[:12]}",
                        title=f"{rule['name']}: {len(matching)} signals",
                        description=rule.get("description", ""),
                        severity=rule.get("severity", Severity.MEDIUM),
                        correlation_ids=[],
                        signal_ids=[s.source_id for s in matching],
                        ttps=[],
                        enriched={},
                        timestamp=datetime.now(UTC).isoformat(),
                    )
                    alerts.append(alert)

        if self.db:
            for alert in alerts:
                self.db.save_alert(alert)

        return alerts

    def _matches_rule(self, event: CorrelatedEvent, rule: dict[str, Any]) -> bool:
        if rule.get("min_correlation_score", 0) > 0:
            if event.correlation_score < rule["min_correlation_score"]:
                return False

        if "categories" in rule:
            event_cats = {s.category.value for s in event.signals}
            if not event_cats.intersection(rule["categories"]):
                return False

        if "sources" in rule:
            event_sources = {s.source.value for s in event.signals}
            if not event_sources.intersection(rule["sources"]):
                return False

        if "min_sources" in rule:
            sources = {s.source for s in event.signals}
            if len(sources) < rule["min_sources"]:
                return False

        if "min_signals" in rule and len(event.signals) < rule["min_signals"]:
            return False

        return not ("severity" in rule and event.severity < rule["severity"])
