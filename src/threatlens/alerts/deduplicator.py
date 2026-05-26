"""Alert deduplication — prevents duplicate alerts for the same signals."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from threatlens.models import Alert


class AlertDeduplicator:
    def __init__(self, window_minutes: int = 60) -> None:
        self.window_minutes = window_minutes
        self._seen: dict[str, datetime] = {}

    def is_duplicate(self, alert: Alert) -> bool:
        dedup_key = self._make_key(alert)
        now = datetime.now(UTC)

        if dedup_key in self._seen:
            age = now - self._seen[dedup_key]
            if age < timedelta(minutes=self.window_minutes):
                return True

        self._seen[dedup_key] = now
        return False

    def deduplicate(self, alerts: list[Alert]) -> list[Alert]:
        return [a for a in alerts if not self.is_duplicate(a)]

    def _make_key(self, alert: Alert) -> str:
        signal_ids = sorted(alert.signal_ids)
        correlation_ids = sorted(alert.correlation_ids)
        raw = f"{alert.title}|{','.join(signal_ids)}|{','.join(correlation_ids)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
