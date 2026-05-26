"""Periodic report scheduler — generates reports on a schedule."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from threatlens.database import Database
from threatlens.models import AttackCategory, Confidence, RawSignal, Severity, SignalSource
from threatlens.reports.generator import ReportGenerator


class PeriodicReportScheduler:
    def __init__(self, db: Database, config: dict[str, Any] | None = None) -> None:
        self.db = db
        self.config = config or {}
        self.scheduler = AsyncIOScheduler()
        self.generator = ReportGenerator(db)

    def start(self) -> None:
        schedule = self.config.get("reports", {}).get("schedule", {})

        if schedule.get("daily", True):
            self.scheduler.add_job(
                self._generate_daily,
                "cron",
                hour=23,
                minute=0,
                id="daily_report",
                replace_existing=True,
            )

        if schedule.get("weekly", True):
            self.scheduler.add_job(
                self._generate_weekly,
                "cron",
                day_of_week="sun",
                hour=23,
                minute=30,
                id="weekly_report",
                replace_existing=True,
            )

        if schedule.get("monthly", True):
            self.scheduler.add_job(
                self._generate_monthly,
                "cron",
                day=1,
                hour=0,
                minute=0,
                id="monthly_report",
                replace_existing=True,
            )

        self.scheduler.start()

    def stop(self) -> None:
        self.scheduler.shutdown(wait=False)

    def _rows_to_signals(self, rows: list[dict[str, Any]]) -> list[RawSignal]:
        signals: list[RawSignal] = []
        for row in rows:
            signals.append(
                RawSignal(
                    source=SignalSource(row["source"]),
                    source_id=row["source_id"],
                    category=AttackCategory(row["category"]),
                    severity=Severity(row["severity"]),
                    confidence=Confidence(row["confidence"]),
                    title=row["title"],
                    description=row.get("description", ""),
                    recommendation=row.get("recommendation", ""),
                    detection_method=row.get("detection_method", ""),
                    target=row.get("target", ""),
                    snippet=row.get("snippet", ""),
                    timestamp=row.get("timestamp", ""),
                    risk_score=row.get("risk_score", 0),
                )
            )
        return signals

    async def _generate_daily(self) -> None:
        now = datetime.now(timezone.utc)
        start = (now - timedelta(days=1)).isoformat()
        end = now.isoformat()
        rows = self.db.get_signals(limit=1000)
        signals = self._rows_to_signals(rows)
        self.generator.generate(
            report_type="daily",
            signals=signals,
            correlated_events=[],
            alerts=[],
            campaigns=[],
            period_start=start,
            period_end=end,
        )

    async def _generate_weekly(self) -> None:
        now = datetime.now(timezone.utc)
        start = (now - timedelta(weeks=1)).isoformat()
        end = now.isoformat()
        rows = self.db.get_signals(limit=5000)
        signals = self._rows_to_signals(rows)
        self.generator.generate(
            report_type="weekly",
            signals=signals,
            correlated_events=[],
            alerts=[],
            campaigns=[],
            period_start=start,
            period_end=end,
        )

    async def _generate_monthly(self) -> None:
        now = datetime.now(timezone.utc)
        start = (now - timedelta(days=30)).isoformat()
        end = now.isoformat()
        rows = self.db.get_signals(limit=10000)
        signals = self._rows_to_signals(rows)
        self.generator.generate(
            report_type="monthly",
            signals=signals,
            correlated_events=[],
            alerts=[],
            campaigns=[],
            period_start=start,
            period_end=end,
        )
