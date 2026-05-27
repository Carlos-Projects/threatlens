"""Tests for campaign detection."""

from __future__ import annotations

from mcp_taxonomy import AttackCategory, Confidence

from threatlens.correlation.campaign_detector import CampaignDetector
from threatlens.models import RawSignal, Severity, SignalSource


def _make_signal(
    source_id: str, category=AttackCategory.INJECTION, source=SignalSource.MCPGUARD
) -> RawSignal:
    return RawSignal(
        source=source,
        source_id=source_id,
        category=category,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="test",
    )


class TestCampaignDetector:
    def setup_method(self):
        self.detector = CampaignDetector()

    def test_empty_signals(self):
        campaigns = self.detector.detect([])
        assert campaigns == []

    def test_single_signal_no_campaign(self):
        sig = _make_signal("s1")
        campaigns = self.detector.detect([sig])
        assert len(campaigns) == 0

    def test_campaign_detection_multiple_signals(self):
        signals = [_make_signal(f"s{i}", category=AttackCategory.INJECTION) for i in range(5)]
        campaigns = self.detector.detect(signals)
        assert len(campaigns) >= 1

    def test_campaign_group_id_unique(self):
        sigs1 = [_make_signal(f"a{i}") for i in range(3)]
        sigs2 = [_make_signal(f"b{i}") for i in range(3)]
        camps1 = self.detector.detect(sigs1)
        camps2 = self.detector.detect(sigs2)
        if camps1 and camps2:
            assert camps1[0].id != camps2[0].id

    def test_campaign_mixed_sources(self):
        signals = [
            _make_signal("s1", source=SignalSource.MCPGUARD),
            _make_signal("s2", source=SignalSource.MCPWN, category=AttackCategory.INJECTION),
            _make_signal("s3", source=SignalSource.PALISADE, category=AttackCategory.INJECTION),
        ]
        campaigns = self.detector.detect(signals)
        if campaigns:
            assert len(campaigns[0].signals) >= 2
