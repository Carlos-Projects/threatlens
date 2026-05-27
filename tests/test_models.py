"""Tests for data models."""

from __future__ import annotations

from datetime import UTC, datetime

from mcp_taxonomy import AttackCategory, Confidence, DetectionMethod

from threatlens.models import (
    Alert,
    Campaign,
    CorrelatedEvent,
    RawSignal,
    Severity,
    SignalSource,
    ThreatReport,
)


class TestRawSignal:
    def test_minimal_construction(self):
        sig = RawSignal(
            source=SignalSource.MCPGUARD,
            source_id="test-001",
            category=AttackCategory.INJECTION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test signal",
        )
        assert sig.source == SignalSource.MCPGUARD
        assert sig.category == AttackCategory.INJECTION
        assert sig.severity == Severity.HIGH
        assert sig.risk_score == 0
        assert sig.blocked is None
        assert sig.tags == []

    def test_full_construction(self):
        sig = RawSignal(
            source=SignalSource.MCPWN,
            source_id="mcpwn-001",
            category=AttackCategory.RCE,
            severity=Severity.CRITICAL,
            confidence=Confidence.CERTAIN,
            title="RCE detected",
            description="Remote code execution attempt",
            recommendation="Block the source IP",
            detection_method=DetectionMethod.RCE_BLIND_TESTER,
            target="http://target/api",
            snippet="exec('malicious')",
            raw_data={"payload": "test"},
            timestamp="2025-01-01T00:00:00Z",
            blocked=True,
            risk_score=95,
            tags=["rce", "critical"],
        )
        assert sig.risk_score == 95
        assert sig.blocked is True
        assert "rce" in sig.tags
        assert sig.normalized_timestamp.year == 2025

    def test_normalized_timestamp(self):
        sig = RawSignal(
            source=SignalSource.PALISADE,
            source_id="p-001",
            category=AttackCategory.STEGO,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            title="Stego detected",
            timestamp="2025-06-01T12:00:00+00:00",
        )
        assert isinstance(sig.normalized_timestamp, datetime)
        assert sig.normalized_timestamp.hour == 12

    def test_default_timestamp(self):
        sig = RawSignal(
            source=SignalSource.AGENTGATE,
            source_id="ag-001",
            category=AttackCategory.CRAWL,
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            title="Crawl detected",
        )
        now = datetime.now(UTC)
        ts = datetime.fromisoformat(sig.timestamp)
        assert abs((now - ts).total_seconds()) < 5

    def test_uncategorized_category(self):
        sig = RawSignal(
            source=SignalSource.AGENTGATE,
            source_id="t-0",
            category=AttackCategory.CRAWL,
            severity=Severity.INFO,
            confidence=Confidence.NONE,
            title="test",
            risk_score=0,
        )
        assert sig.category == AttackCategory.CRAWL


class TestCorrelatedEvent:
    def test_risk_score_single_signal(self):
        sig = RawSignal(
            source=SignalSource.MCPGUARD,
            source_id="t-1",
            category=AttackCategory.INJECTION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="test",
            risk_score=50,
        )
        event = CorrelatedEvent(
            id="ev-1",
            signals=[sig],
            correlation_type="same_category",
            correlation_score=50.0,
            title="Test event",
            description="",
        )
        assert event.risk_score == 50

    def test_risk_score_multiple_signals(self):
        sigs = [
            RawSignal(
                source=SignalSource.MCPGUARD,
                source_id=f"t-{i}",
                category=AttackCategory.INJECTION,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="test",
                risk_score=30 + i * 10,
            )
            for i in range(3)
        ]
        event = CorrelatedEvent(
            id="ev-2",
            signals=sigs,
            correlation_type="same_category",
            correlation_score=60.0,
            title="Test",
            description="",
        )
        assert event.risk_score == 75  # max(50) * 1.5

    def test_risk_score_empty(self):
        event = CorrelatedEvent(
            id="ev-3",
            signals=[],
            correlation_type="none",
            correlation_score=0,
            title="empty",
            description="",
        )
        assert event.risk_score == 0

    def test_risk_score_single_with_zero(self):
        sig = RawSignal(
            source=SignalSource.AGENTGATE,
            source_id="t-0",
            category=AttackCategory.CRAWL,
            severity=Severity.INFO,
            confidence=Confidence.NONE,
            title="test",
            risk_score=0,
        )
        event = CorrelatedEvent(
            id="ev-4",
            signals=[sig],
            correlation_type="test",
            correlation_score=10.0,
            title="t",
            description="",
        )
        assert event.risk_score == 0


class TestAlert:
    def test_construction(self):
        alert = Alert(
            id="alert-001",
            title="Critical RCE Alert",
            description="RCE detected in MCP tool",
            severity=Severity.CRITICAL,
            correlation_ids=["corr-001"],
            signal_ids=["sig-001", "sig-002"],
            ttps=[{"id": "AML.T0059", "name": "RCE"}],
            enriched={"cve": "CVE-2025-0001"},
        )
        assert alert.severity == Severity.CRITICAL
        assert alert.acknowledged is False
        assert alert.notified is False
        assert alert.risk_score == 100  # Severity.CRITICAL.weight * 4

    def test_risk_score_info(self):
        alert = Alert(
            id="alert-002",
            title="Info",
            description="",
            severity=Severity.INFO,
            correlation_ids=[],
            signal_ids=[],
            ttps=[],
            enriched={},
        )
        assert alert.risk_score == 0

    def test_risk_score_high(self):
        alert = Alert(
            id="alert-003",
            title="High",
            description="",
            severity=Severity.HIGH,
            correlation_ids=[],
            signal_ids=[],
            ttps=[],
            enriched={},
        )
        assert alert.risk_score == 40


class TestThreatReport:
    def test_construction(self):
        report = ThreatReport(
            id="report-001",
            report_type="daily",
            title="Daily Report",
            summary="Summary text",
            period_start="2025-01-01",
            period_end="2025-01-02",
        )
        assert report.total_signals == 0
        assert report.total_alerts == 0
        assert report.recommendations == []

    def test_with_data(self):
        report = ThreatReport(
            id="report-002",
            report_type="executive",
            title="Executive",
            summary="Exec summary",
            period_start="2025-01-01",
            period_end="2025-01-31",
            total_signals=500,
            total_alerts=25,
            total_campaigns=5,
            top_ttps=[{"ttp_id": "AML.T0051", "count": 100}],
            top_sources={"mcpguard": 300, "mcpwn": 200},
            severity_distribution={"critical": 5, "high": 20},
            recommendations=["Fix critical issues"],
        )
        assert report.total_signals == 500
        assert len(report.recommendations) == 1


class TestCampaign:
    def test_construction(self):
        sig = RawSignal(
            source=SignalSource.MCPGUARD,
            source_id="t-1",
            category=AttackCategory.INJECTION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="test",
        )
        campaign = Campaign(
            id="camp-001",
            name="Test Campaign",
            description="A test campaign",
            severity=Severity.HIGH,
            signals=[sig],
            tags=["injection", "campaign"],
        )
        assert campaign.active is True
        assert len(campaign.signals) == 1
        assert campaign.events == []


class TestSignalSource:
    def test_values(self):
        assert SignalSource.MCPGUARD.value == "mcpguard"
        assert SignalSource.MCPWN.value == "mcpwn"
        assert SignalSource.PALISADE.value == "palisade"
        assert SignalSource.AGENTGATE.value == "agentgate"
        assert SignalSource.ABLITERATE.value == "abliterate"
        assert SignalSource.EXTERNAL.value == "external"
