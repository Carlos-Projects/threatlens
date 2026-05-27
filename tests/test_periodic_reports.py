"""Tests for periodic report scheduler."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

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

    def test_start_adds_daily_job(self, db):
        scheduler = PeriodicReportScheduler(
            db, {"reports": {"schedule": {"daily": True, "weekly": False, "monthly": False}}}
        )
        with (
            patch.object(scheduler.scheduler, "start"),
            patch.object(scheduler.scheduler, "add_job") as mock_add,
        ):
            scheduler.start()
            mock_add.assert_called_once_with(
                scheduler._generate_daily,
                "cron",
                hour=23,
                minute=0,
                id="daily_report",
                replace_existing=True,
            )

    def test_start_adds_weekly_job(self, db):
        scheduler = PeriodicReportScheduler(
            db, {"reports": {"schedule": {"daily": False, "weekly": True, "monthly": False}}}
        )
        with (
            patch.object(scheduler.scheduler, "start"),
            patch.object(scheduler.scheduler, "add_job") as mock_add,
        ):
            scheduler.start()
            mock_add.assert_called_once_with(
                scheduler._generate_weekly,
                "cron",
                day_of_week="sun",
                hour=23,
                minute=30,
                id="weekly_report",
                replace_existing=True,
            )

    def test_start_adds_monthly_job(self, db):
        scheduler = PeriodicReportScheduler(
            db, {"reports": {"schedule": {"daily": False, "weekly": False, "monthly": True}}}
        )
        with (
            patch.object(scheduler.scheduler, "start"),
            patch.object(scheduler.scheduler, "add_job") as mock_add,
        ):
            scheduler.start()
            mock_add.assert_called_once_with(
                scheduler._generate_monthly,
                "cron",
                day=1,
                hour=0,
                minute=0,
                id="monthly_report",
                replace_existing=True,
            )

    def test_start_all_enabled_adds_three_jobs(self, db):
        scheduler = PeriodicReportScheduler(
            db, {"reports": {"schedule": {"daily": True, "weekly": True, "monthly": True}}}
        )
        with (
            patch.object(scheduler.scheduler, "start"),
            patch.object(scheduler.scheduler, "add_job") as mock_add,
        ):
            scheduler.start()
            assert mock_add.call_count == 3

    def test_start_all_disabled_adds_no_jobs(self, db):
        scheduler = PeriodicReportScheduler(
            db, {"reports": {"schedule": {"daily": False, "weekly": False, "monthly": False}}}
        )
        with (
            patch.object(scheduler.scheduler, "start"),
            patch.object(scheduler.scheduler, "add_job") as mock_add,
        ):
            scheduler.start()
            mock_add.assert_not_called()

    def test_start_calls_scheduler_start(self, db):
        scheduler = PeriodicReportScheduler(db)
        with patch.object(scheduler.scheduler, "start") as mock_start:
            scheduler.start()
            mock_start.assert_called_once()

    def test_stop_shuts_down_scheduler(self, db):
        scheduler = PeriodicReportScheduler(db)
        with patch.object(scheduler.scheduler, "shutdown") as mock_shutdown:
            scheduler.stop()
            mock_shutdown.assert_called_once_with(wait=False)

    def test_start_default_schedule(self, db):
        scheduler = PeriodicReportScheduler(db)
        assert scheduler.config == {}

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
