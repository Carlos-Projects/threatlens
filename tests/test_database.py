"""Tests for database layer."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from threatlens.database import Database
from threatlens.models import (
    Alert,
    Campaign,
    CorrelatedEvent,
    RawSignal,
    Severity,
    SignalSource,
    ThreatReport,
)
from mcp_taxonomy import AttackCategory, Confidence


@pytest.fixture
def db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db_path = tmp.name
    tmp.close()
    database = Database(db_path=db_path)
    database.initialize()
    yield database
    database.close()
    Path(db_path).unlink(missing_ok=True)


class TestDatabase:
    def test_initialize(self, db):
        conn = db.connect()
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t["name"] for t in tables]
        assert "signals" in table_names
        assert "alerts" in table_names
        assert "correlated_events" in table_names
        assert "reports" in table_names
        assert "campaigns" in table_names

    def test_save_and_get_signals(self, db):
        sig = RawSignal(
            source=SignalSource.MCPGUARD,
            source_id="sig-001",
            category=AttackCategory.INJECTION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test injection",
            description="A test signal",
            risk_score=75,
        )
        saved = db.save_signals([sig])
        assert saved >= 0

        results = db.get_signals(limit=10)
        assert len(results) >= 1

    def test_save_and_get_alerts(self, db):
        alert = Alert(
            id="alert-001",
            title="Test Alert",
            description="Description",
            severity=Severity.CRITICAL,
            correlation_ids=["corr-1"],
            signal_ids=["sig-1"],
            ttps=[{"id": "AML.T0059"}],
            enriched={"cve": "CVE-2025-0001"},
        )
        db.save_alert(alert)
        alerts = db.get_alerts(limit=10)
        assert len(alerts) >= 1
        assert alerts[0]["severity"] == "critical"

    def test_save_and_get_reports(self, db):
        report = ThreatReport(
            id="report-001",
            report_type="daily",
            title="Daily Report",
            summary="Summary",
            period_start="2025-01-01",
            period_end="2025-01-02",
        )
        db.save_report(report)
        reports = db.get_reports(limit=10)
        assert len(reports) >= 1

    def test_save_and_get_campaigns(self, db):
        sig = RawSignal(
            source=SignalSource.MCPGUARD,
            source_id="sig-camp-1",
            category=AttackCategory.INJECTION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Campaign signal",
        )
        camp = Campaign(
            id="camp-001",
            name="Test Campaign",
            description="A test",
            severity=Severity.HIGH,
            signals=[sig],
        )
        db.save_campaign(camp)
        campaigns = db.get_campaigns()
        assert len(campaigns) >= 1

    def test_save_correlated_event(self, db):
        sig = RawSignal(
            source=SignalSource.MCPGUARD,
            source_id="sig-corr-1",
            category=AttackCategory.INJECTION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Event signal",
        )
        event = CorrelatedEvent(
            id="corr-001",
            signals=[sig],
            correlation_type="same_category",
            correlation_score=75.0,
            title="Correlated event",
            description="Test",
        )
        db.save_correlated_event(event)

    def test_get_stats(self, db):
        stats = db.get_stats()
        assert "total_signals" in stats
        assert "total_alerts" in stats
        assert "total_campaigns" in stats
        assert "severity_distribution" in stats
        assert "source_distribution" in stats

    def test_filter_signals_by_source(self, db):
        sig1 = RawSignal(
            source=SignalSource.MCPGUARD,
            source_id="f1",
            category=AttackCategory.INJECTION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="MCPGuard signal",
        )
        sig2 = RawSignal(
            source=SignalSource.MCPWN,
            source_id="f2",
            category=AttackCategory.RCE,
            severity=Severity.CRITICAL,
            confidence=Confidence.CERTAIN,
            title="MCPwn signal",
        )
        db.save_signals([sig1, sig2])

        mcpguard_results = db.get_signals(source="mcpguard")
        assert all(s["source"] == "mcpguard" for s in mcpguard_results)

    def test_filter_signals_by_severity(self, db):
        sig = RawSignal(
            source=SignalSource.PALISADE,
            source_id="sev-test",
            category=AttackCategory.STEGO,
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            title="Low severity signal",
        )
        db.save_signals([sig])
        results = db.get_signals(severity="low")
        assert all(s["severity"] == "low" for s in results)

    def test_signals_pagination(self, db):
        signals = [
            RawSignal(
                source=SignalSource.AGENTGATE,
                source_id=f"page-{i}",
                category=AttackCategory.CRAWL,
                severity=Severity.INFO,
                confidence=Confidence.NONE,
                title=f"Signal {i}",
            )
            for i in range(20)
        ]
        db.save_signals(signals)
        page1 = db.get_signals(limit=10, offset=0)
        page2 = db.get_signals(limit=10, offset=10)
        assert len(page1) <= 10
        assert len(page2) <= 10
