"""Tests for temporal analysis."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from threatlens.correlation.temporal_analyzer import TemporalAnalyzer
from threatlens.models import RawSignal, Severity, SignalSource
from mcp_taxonomy import AttackCategory, Confidence


def _make_signal(source_id: str, minutes_ago: float = 0) -> RawSignal:
    ts = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    return RawSignal(
        source=SignalSource.MCPGUARD,
        source_id=source_id,
        category=AttackCategory.INJECTION,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="test",
        timestamp=ts,
    )


class TestTemporalAnalyzer:
    def setup_method(self):
        self.analyzer = TemporalAnalyzer(window_minutes=60)

    def test_empty_signals(self):
        assert self.analyzer.find_bursts([], threshold=5) == []

    def test_no_burst_below_threshold(self):
        signals = [_make_signal(f"s{i}", minutes_ago=i * 30) for i in range(3)]
        bursts = self.analyzer.find_bursts(signals, threshold=5)
        assert bursts == []

    def test_burst_detection(self):
        signals = [_make_signal(f"s{i}", minutes_ago=i * 5) for i in range(10)]
        bursts = self.analyzer.find_bursts(signals, threshold=5)
        assert len(bursts) >= 1

    def test_temporal_clusters(self):
        signals = [_make_signal(f"s{i}", minutes_ago=i * 10) for i in range(20)]
        clusters = self.analyzer.find_temporal_clusters(signals, max_gap_minutes=30)
        assert len(clusters) >= 1

    def test_empty_clusters(self):
        assert self.analyzer.find_temporal_clusters([]) == []
