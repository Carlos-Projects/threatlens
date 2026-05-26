"""Tests for report generators."""

from __future__ import annotations

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
from threatlens.reports.executive import ExecutiveReportGenerator
from threatlens.reports.generator import ReportGenerator
from mcp_taxonomy import AttackCategory, Confidence


@pytest.fixture
def db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    database = Database(db_path=tmp.name)
    database.initialize()
    tmp.close()
    yield database
    database.close()
    Path(tmp.name).unlink(missing_ok=True)


def _sig(
    sid: str,
    category=AttackCategory.INJECTION,
    source=SignalSource.MCPGUARD,
    severity=Severity.HIGH,
) -> RawSignal:
    return RawSignal(
        source=source,
        source_id=sid,
        category=category,
        severity=severity,
        confidence=Confidence.HIGH,
        title=f"Sig {sid}",
    )


class TestReportGenerator:
    def test_generate_minimal(self):
        gen = ReportGenerator()
        report = gen.generate(
            report_type="daily",
            signals=[],
            correlated_events=[],
            alerts=[],
            campaigns=[],
        )
        assert report.report_type == "daily"
        assert report.total_signals == 0
        assert report.top_ttps == []

    def test_generate_with_data(self):
        gen = ReportGenerator()
        sigs = [_sig(f"s{i}") for i in range(10)]
        alerts = [
            Alert(
                id=f"a{i}",
                title="Alert",
                description="",
                severity=Severity.HIGH,
                correlation_ids=[],
                signal_ids=[],
                ttps=[],
                enriched={},
            )
            for i in range(3)
        ]
        camps = [
            Campaign(
                id=f"c{i}",
                name=f"Camp {i}",
                description="",
                severity=Severity.HIGH,
                signals=[_sig(f"cs{i}")],
            )
            for i in range(2)
        ]
        report = gen.generate(
            report_type="weekly",
            signals=sigs,
            correlated_events=[],
            alerts=alerts,
            campaigns=camps,
        )
        assert report.total_signals == 10
        assert len(report.recommendations) > 0

    def test_generate_saves_to_db(self, db):
        gen = ReportGenerator(db=db)
        report = gen.generate(
            report_type="monthly",
            signals=[],
            correlated_events=[],
            alerts=[],
            campaigns=[],
        )
        saved = db.get_reports(limit=10)
        assert any(r["id"] == report.id for r in saved)


class TestExecutiveReportGenerator:
    def test_generate_empty(self):
        gen = ExecutiveReportGenerator()
        report = gen.generate(signals=[], alerts=[], campaigns=[])
        assert report.report_type == "executive"
        assert report.total_signals == 0

    def test_generate_with_critical_alerts(self):
        gen = ExecutiveReportGenerator()
        alerts = [
            Alert(
                id="a1",
                title="Critical",
                description="",
                severity=Severity.CRITICAL,
                correlation_ids=[],
                signal_ids=[],
                ttps=[],
                enriched={},
            )
        ]
        report = gen.generate(
            signals=[_sig("s1")],
            alerts=alerts,
            campaigns=[],
        )
        assert report.total_alerts == 1
        assert len(report.recommendations) > 0

    def test_executive_summary(self):
        gen = ExecutiveReportGenerator()
        report = gen.generate(
            signals=[_sig(f"s{i}") for i in range(5)],
            alerts=[
                Alert(
                    id=f"a{i}",
                    title="High Alert",
                    description="",
                    severity=Severity.HIGH,
                    correlation_ids=[],
                    signal_ids=[],
                    ttps=[],
                    enriched={},
                )
                for i in range(2)
            ],
            campaigns=[
                Campaign(
                    id="c1",
                    name="Campaign 1",
                    description="",
                    severity=Severity.HIGH,
                    signals=[_sig("cs1")],
                )
            ],
            period_label="Q1 2025",
        )
        assert "Q1 2025" in report.executive_summary
