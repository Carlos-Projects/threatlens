"""Tests for alert generator."""

from __future__ import annotations

from mcp_taxonomy import AttackCategory, Confidence

from threatlens.alerts.generator import ALERT_RULES, AlertGenerator
from threatlens.models import (
    CorrelatedEvent,
    RawSignal,
    Severity,
    SignalSource,
)


def _make_signal(sid: str, category=AttackCategory.INJECTION, severity=Severity.HIGH) -> RawSignal:
    return RawSignal(
        source=SignalSource.MCPGUARD,
        source_id=sid,
        category=category,
        severity=severity,
        confidence=Confidence.HIGH,
        title=f"Signal {sid}",
        risk_score=severity.weight * 10,
    )


class TestAlertGenerator:
    def setup_method(self):
        self.generator = AlertGenerator()

    def test_empty_events_no_alerts(self):
        alerts = self.generator.generate([])
        assert alerts == []

    def test_generate_from_correlated_event(self):
        sig = _make_signal("s1", category=AttackCategory.RCE)
        event = CorrelatedEvent(
            id="corr-1",
            signals=[sig],
            correlation_type="same_category",
            correlation_score=80.0,
            title="RCE detected",
            description="RCE in MCP tool",
            ttps=[{"id": "AML.T0059"}],
            severity=Severity.CRITICAL,
        )
        alerts = self.generator.generate([event])
        assert len(alerts) >= 1

    def test_alert_id_unique(self):
        sig = _make_signal("s2", category=AttackCategory.RCE)
        event = CorrelatedEvent(
            id="corr-2",
            signals=[sig],
            correlation_type="same_category",
            correlation_score=90.0,
            title="RCE",
            description="",
            severity=Severity.CRITICAL,
        )
        alerts = self.generator.generate([event, event])
        ids = [a.id for a in alerts]
        assert len(ids) == len(set(ids))

    def test_alert_has_rules(self):
        assert len(ALERT_RULES) >= 7
        rule_names = [r["name"] for r in ALERT_RULES]
        assert "critical-rce" in rule_names
        assert "multi-source-campaign" in rule_names
        assert "prompt-injection-wave" in rule_names

    def test_severity_critical_alert(self):
        sig = _make_signal("s3", category=AttackCategory.RCE)
        event = CorrelatedEvent(
            id="corr-3",
            signals=[sig],
            correlation_type="same_category",
            correlation_score=95.0,
            title="Critical RCE",
            description="",
            severity=Severity.CRITICAL,
        )
        alerts = self.generator.generate([event])
        if alerts:
            assert alerts[0].severity == Severity.CRITICAL

    def test_generate_from_signals_only(self):
        signals = [_make_signal(f"s{i}", category=AttackCategory.INJECTION) for i in range(5)]
        alerts = self.generator.generate([], signals=signals)
        injection_alerts = [a for a in alerts if "prompt-injection" in a.title]
        assert len(injection_alerts) >= 1
        assert injection_alerts[0].severity == Severity.HIGH

    def test_multi_source_rule_not_enough_sources(self):
        sig = _make_signal("single", category=AttackCategory.INJECTION)
        event = CorrelatedEvent(
            id="corr-4",
            signals=[sig],
            correlation_type="same_category",
            correlation_score=30.0,
            title="Single source",
            description="",
            severity=Severity.MEDIUM,
        )
        alerts = self.generator.generate([event])
        multi = [a for a in alerts if "multi-source" in a.title]
        assert len(multi) == 0

    def test_signals_only_below_threshold(self):
        signals = [_make_signal("solo", category=AttackCategory.INJECTION)]
        alerts = self.generator.generate([], signals=signals)
        assert all("prompt-injection" not in a.title for a in alerts)
