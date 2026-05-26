"""Tests for periodic report scheduler."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from threatlens.database import Database
from threatlens.reports.periodic import PeriodicReportScheduler
from threatlens.models import RawSignal, Severity, SignalSource
from mcp_taxonomy import AttackCategory, Confidence


@pytest.fixture
def db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    database = Database(db_path=tmp.name)
    database.initialize()
    database.save_signals(
        [
            RawSignal(
                source=SignalSource.MCPGUARD,
                source_id="per-sig-1",
                category=AttackCategory.INJECTION,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Periodic test signal",
                risk_score=70,
            ),
        ]
    )
    tmp.close()
    yield database
    database.close()
    Path(tmp.name).unlink(missing_ok=True)


class TestPeriodicReportScheduler:
    def test_init(self, db):
        scheduler = PeriodicReportScheduler(db)
        assert scheduler.db is db
        assert scheduler.generator is not None

    @pytest.mark.asyncio
    async def test_generate_daily(self, db):
        scheduler = PeriodicReportScheduler(db)
        with patch.object(scheduler.generator, "generate") as mock_gen:
            await scheduler._generate_daily()
            mock_gen.assert_called_once()

    def test_rows_to_signals(self, db):
        scheduler = PeriodicReportScheduler(db)
        rows = db.get_signals(limit=10)
        signals = scheduler._rows_to_signals(rows)
        assert len(signals) == 1
        assert signals[0].title == "Periodic test signal"

    @pytest.mark.asyncio
    async def test_generate_weekly(self, db):
        scheduler = PeriodicReportScheduler(db)
        with patch.object(scheduler.generator, "generate") as mock_gen:
            await scheduler._generate_weekly()
            mock_gen.assert_called_once()

    @pytest.mark.asyncio
    async def test_generate_monthly(self, db):
        scheduler = PeriodicReportScheduler(db)
        with patch.object(scheduler.generator, "generate") as mock_gen:
            await scheduler._generate_monthly()
            mock_gen.assert_called_once()
