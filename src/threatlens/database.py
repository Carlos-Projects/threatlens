"""SQLite database layer for ThreatLens."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from threatlens.models import (
    Alert,
    Campaign,
    CorrelatedEvent,
    RawSignal,
    ThreatReport,
)


class Database:
    def __init__(self, db_path: str = "~/.threatlens/threatlens.db") -> None:
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None

    def connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __del__(self) -> None:
        self.close()

    def initialize(self) -> None:
        conn = self.connect()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS signals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                source_id TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                recommendation TEXT DEFAULT '',
                detection_method TEXT DEFAULT '',
                target TEXT DEFAULT '',
                snippet TEXT DEFAULT '',
                raw_data TEXT DEFAULT '{}',
                timestamp TEXT NOT NULL,
                blocked INTEGER,
                risk_score INTEGER DEFAULT 0,
                tags TEXT DEFAULT '[]',
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS correlated_events (
                id TEXT PRIMARY KEY,
                correlation_type TEXT NOT NULL,
                correlation_score REAL DEFAULT 0.0,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                ttps TEXT DEFAULT '[]',
                campaign_id TEXT DEFAULT '',
                first_seen TEXT DEFAULT '',
                last_seen TEXT DEFAULT '',
                severity TEXT DEFAULT 'info',
                enriched TEXT DEFAULT '{}',
                signal_ids TEXT DEFAULT '[]',
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                severity TEXT NOT NULL,
                correlation_ids TEXT DEFAULT '[]',
                signal_ids TEXT DEFAULT '[]',
                ttps TEXT DEFAULT '[]',
                enriched TEXT DEFAULT '{}',
                timestamp TEXT NOT NULL,
                acknowledged INTEGER DEFAULT 0,
                notified INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                report_type TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT DEFAULT '',
                period_start TEXT DEFAULT '',
                period_end TEXT DEFAULT '',
                generated_at TEXT DEFAULT '',
                total_signals INTEGER DEFAULT 0,
                total_alerts INTEGER DEFAULT 0,
                total_campaigns INTEGER DEFAULT 0,
                top_ttps TEXT DEFAULT '[]',
                top_sources TEXT DEFAULT '{}',
                severity_distribution TEXT DEFAULT '{}',
                campaign_summaries TEXT DEFAULT '[]',
                executive_summary TEXT DEFAULT '',
                recommendations TEXT DEFAULT '[]',
                raw_data TEXT DEFAULT '{}',
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS campaigns (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                severity TEXT DEFAULT 'info',
                signal_ids TEXT DEFAULT '[]',
                event_ids TEXT DEFAULT '[]',
                ttps TEXT DEFAULT '[]',
                first_seen TEXT DEFAULT '',
                last_seen TEXT DEFAULT '',
                active INTEGER DEFAULT 1,
                tags TEXT DEFAULT '[]',
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_signals_source ON signals(source);
            CREATE INDEX IF NOT EXISTS idx_signals_severity ON signals(severity);
            CREATE INDEX IF NOT EXISTS idx_signals_timestamp ON signals(timestamp);
            CREATE INDEX IF NOT EXISTS idx_signals_category ON signals(category);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_corr_events_severity
                ON correlated_events(severity);
            CREATE INDEX IF NOT EXISTS idx_campaigns_active ON campaigns(active);
        """)
        conn.commit()

    def save_signals(self, signals: list[RawSignal]) -> int:
        conn = self.connect()
        count = 0
        max_snippet_len = 5000
        for sig in signals:
            try:
                conn.execute(
                    """INSERT OR IGNORE INTO signals
                    (source, source_id, category, severity, confidence, title,
                     description, recommendation, detection_method, target,
                     snippet, raw_data, timestamp, blocked, risk_score, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        sig.source.value,
                        sig.source_id,
                        sig.category.value,
                        sig.severity.value,
                        sig.confidence.value,
                        sig.title[:1000],
                        sig.description[:2000],
                        sig.recommendation[:1000],
                        str(sig.detection_method),
                        sig.target,
                        sig.snippet[:max_snippet_len] if sig.snippet else "",
                        json.dumps(sig.raw_data or {}),
                        sig.timestamp,
                        sig.blocked,
                        sig.risk_score,
                        json.dumps(sig.tags[:50]),
                    ),
                )
                count += conn.total_changes
                conn.commit()  # commit per signal to keep IDs
            except sqlite3.IntegrityError:
                continue
        return count

    def save_correlated_event(self, event: CorrelatedEvent) -> None:
        conn = self.connect()
        conn.execute(
            """INSERT OR REPLACE INTO correlated_events
            (id, correlation_type, correlation_score, title, description,
             ttps, campaign_id, first_seen, last_seen, severity,
             enriched, signal_ids)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.id,
                event.correlation_type,
                event.correlation_score,
                event.title,
                event.description,
                json.dumps(event.ttps),
                event.campaign_id,
                event.first_seen,
                event.last_seen,
                event.severity.value,
                json.dumps(event.enriched),
                json.dumps([s.source_id for s in event.signals]),
            ),
        )
        conn.commit()

    def save_alert(self, alert: Alert) -> None:
        conn = self.connect()
        conn.execute(
            """INSERT OR REPLACE INTO alerts
            (id, title, description, severity, correlation_ids, signal_ids,
             ttps, enriched, timestamp, acknowledged, notified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.id,
                alert.title,
                alert.description,
                alert.severity.value,
                json.dumps(alert.correlation_ids),
                json.dumps(alert.signal_ids),
                json.dumps(alert.ttps),
                json.dumps(alert.enriched),
                alert.timestamp,
                int(alert.acknowledged),
                int(alert.notified),
            ),
        )
        conn.commit()

    def save_report(self, report: ThreatReport) -> None:
        conn = self.connect()
        conn.execute(
            """INSERT OR REPLACE INTO reports
            (id, report_type, title, summary, period_start, period_end,
             generated_at, total_signals, total_alerts, total_campaigns,
             top_ttps, top_sources, severity_distribution, campaign_summaries,
             executive_summary, recommendations, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                report.id,
                report.report_type,
                report.title,
                report.summary,
                report.period_start,
                report.period_end,
                report.generated_at,
                report.total_signals,
                report.total_alerts,
                report.total_campaigns,
                json.dumps(report.top_ttps),
                json.dumps(report.top_sources),
                json.dumps(report.severity_distribution),
                json.dumps(report.campaign_summaries),
                report.executive_summary,
                json.dumps(report.recommendations),
                json.dumps(report.raw_data or {}),
            ),
        )
        conn.commit()

    def save_campaign(self, campaign: Campaign) -> None:
        conn = self.connect()
        conn.execute(
            """INSERT OR REPLACE INTO campaigns
            (id, name, description, severity, signal_ids, event_ids,
             ttps, first_seen, last_seen, active, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                campaign.id,
                campaign.name,
                campaign.description,
                campaign.severity.value,
                json.dumps([s.source_id for s in campaign.signals]),
                json.dumps([e.id for e in campaign.events]),
                json.dumps(campaign.ttps),
                campaign.first_seen,
                campaign.last_seen,
                int(campaign.active),
                json.dumps(campaign.tags),
            ),
        )
        conn.commit()

    def get_signals(
        self,
        source: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        conn = self.connect()
        query = "SELECT * FROM signals WHERE 1=1"
        params: list[Any] = []
        if source:
            query += " AND source = ?"
            params.append(source)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if category:
            query += " AND category = ?"
            params.append(category)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_alerts(
        self,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        conn = self.connect()
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_reports(self, report_type: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
        conn = self.connect()
        query = "SELECT * FROM reports WHERE 1=1"
        params: list[Any] = []
        if report_type:
            query += " AND report_type = ?"
            params.append(report_type)
        query += " ORDER BY generated_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_campaigns(self, active_only: bool = True) -> list[dict[str, Any]]:
        conn = self.connect()
        query = "SELECT * FROM campaigns WHERE 1=1"
        params: list[Any] = []
        if active_only:
            query += " AND active = 1"
        query += " ORDER BY last_seen DESC"
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> dict[str, Any]:
        conn = self.connect()
        total_signals = conn.execute("SELECT COUNT(*) FROM signals").fetchone()[0]
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        total_campaigns = conn.execute(
            "SELECT COUNT(*) FROM campaigns WHERE active = 1"
        ).fetchone()[0]

        severity_dist = conn.execute(
            """SELECT severity, COUNT(*) as count
               FROM signals GROUP BY severity ORDER BY count DESC"""
        ).fetchall()

        source_dist = conn.execute(
            """SELECT source, COUNT(*) as count
               FROM signals GROUP BY source ORDER BY count DESC"""
        ).fetchall()

        recent_signals = conn.execute(
            "SELECT timestamp FROM signals ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()

        return {
            "total_signals": total_signals,
            "total_alerts": total_alerts,
            "total_campaigns": total_campaigns,
            "severity_distribution": {r["severity"]: r["count"] for r in severity_dist},
            "source_distribution": {r["source"]: r["count"] for r in source_dist},
            "last_signal_at": recent_signals["timestamp"] if recent_signals else None,
        }
