"""Tests for alert deduplication."""

from __future__ import annotations

from threatlens.alerts.deduplicator import AlertDeduplicator
from threatlens.models import Alert, Severity


class TestAlertDeduplicator:
    def setup_method(self):
        self.dedup = AlertDeduplicator(window_minutes=60)

    def _make_alert(self, aid: str, title: str = "Test Alert") -> Alert:
        return Alert(
            id=aid,
            title=title,
            description="",
            severity=Severity.HIGH,
            correlation_ids=[f"corr-{aid}"],
            signal_ids=[f"sig-{aid}"],
            ttps=[],
            enriched={},
        )

    def test_first_alert_not_duplicate(self):
        alert = self._make_alert("a1")
        assert self.dedup.is_duplicate(alert) is False

    def test_same_alert_is_duplicate(self):
        alert = self._make_alert("a2")
        self.dedup.is_duplicate(alert)
        assert self.dedup.is_duplicate(alert) is True

    def test_different_alerts_not_duplicate(self):
        a1 = self._make_alert("a3", title="Alert A")
        a2 = self._make_alert("a4", title="Alert B")
        self.dedup.is_duplicate(a1)
        assert self.dedup.is_duplicate(a2) is False

    def test_deduplicate_list(self):
        alerts = [self._make_alert(f"a{i}") for i in range(5)]
        self.dedup.is_duplicate(alerts[0])
        deduped = self.dedup.deduplicate(alerts)
        assert len(deduped) == 4  # first one is duplicate
