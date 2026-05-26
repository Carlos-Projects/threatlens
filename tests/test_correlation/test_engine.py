"""Tests for correlation engine."""

from __future__ import annotations

import pytest

from threatlens.correlation.engine import CorrelationEngine
from threatlens.models import RawSignal, Severity, SignalSource
from mcp_taxonomy import AttackCategory, Confidence


def _sig(
    sid: str,
    category=AttackCategory.INJECTION,
    source=SignalSource.MCPGUARD,
    target: str = "",
    severity=Severity.HIGH,
) -> RawSignal:
    return RawSignal(
        source=source,
        source_id=sid,
        category=category,
        severity=severity,
        confidence=Confidence.HIGH,
        title=f"Test {sid}",
        target=target,
    )


class TestCorrelationEngine:
    def setup_method(self):
        self.engine = CorrelationEngine()

    def test_empty_signals(self):
        events = self.engine.correlate([])
        assert events == []

    def test_single_signal_no_correlation(self):
        events = self.engine.correlate([_sig("s1")])
        assert len(events) == 0

    def test_correlate_by_category(self):
        signals = [
            _sig("s1", category=AttackCategory.INJECTION),
            _sig("s2", category=AttackCategory.INJECTION),
        ]
        events = self.engine.correlate(signals)
        assert any(e.correlation_type == "same_category" for e in events)

    def test_correlate_by_target(self):
        signals = [
            _sig("s1", source=SignalSource.MCPGUARD, target="/api/chat"),
            _sig("s2", source=SignalSource.MCPWN, target="/api/chat"),
        ]
        events = self.engine.correlate(signals)
        assert any(e.correlation_type == "same_target" for e in events)

    def test_correlate_by_ttp(self):
        signals = [
            _sig("s1", category=AttackCategory.INJECTION, source=SignalSource.MCPGUARD),
            _sig("s2", category=AttackCategory.INJECTION, source=SignalSource.MCPWN),
        ]
        events = self.engine.correlate(signals)
        assert any(e.correlation_type == "shared_ttp" for e in events)

    def test_unique_events_only(self):
        signals = [
            _sig("s1", category=AttackCategory.INJECTION),
            _sig("s2", category=AttackCategory.INJECTION),
            _sig("s3", category=AttackCategory.INJECTION),
        ]
        events = self.engine.correlate(signals)
        ids = [e.id for e in events]
        assert len(ids) == len(set(ids))

    def test_events_sorted_by_score(self):
        signals = [_sig(f"s{i}", category=AttackCategory.INJECTION) for i in range(10)]
        events = self.engine.correlate(signals)
        scores = [e.correlation_score for e in events]
        assert scores == sorted(scores, reverse=True)
