"""Temporal analysis of threat signals — burst detection, time-based correlation."""

from __future__ import annotations

from collections import Counter
from datetime import timedelta
from typing import Any

from threatlens.models import RawSignal


class TemporalAnalyzer:
    def __init__(self, window_minutes: int = 60) -> None:
        self.window_minutes = window_minutes

    def find_bursts(self, signals: list[RawSignal], threshold: int = 5) -> list[dict[str, Any]]:
        if not signals:
            return []

        sorted_signals = sorted(signals, key=lambda s: s.normalized_timestamp)
        bursts: list[dict[str, Any]] = []

        window = timedelta(minutes=self.window_minutes)
        for i, sig in enumerate(sorted_signals):
            window_end = sig.normalized_timestamp + window
            group = [sig]

            for j in range(i + 1, len(sorted_signals)):
                if sorted_signals[j].normalized_timestamp <= window_end:
                    group.append(sorted_signals[j])
                else:
                    break

            if len(group) >= threshold:
                categories = Counter(s.category.value for s in group)
                sources = Counter(s.source.value for s in group)

                bursts.append(
                    {
                        "start_time": group[0].timestamp,
                        "end_time": group[-1].timestamp,
                        "signal_count": len(group),
                        "categories": dict(categories.most_common(5)),
                        "sources": dict(sources.most_common(5)),
                        "avg_risk_score": sum(s.risk_score for s in group) // len(group),
                        "signals": [s.source_id for s in group],
                    }
                )

        return bursts

    def find_temporal_clusters(
        self, signals: list[RawSignal], max_gap_minutes: int = 30
    ) -> list[list[RawSignal]]:
        if not signals:
            return []

        sorted_signals = sorted(signals, key=lambda s: s.normalized_timestamp)
        clusters: list[list[RawSignal]] = []
        current: list[RawSignal] = [sorted_signals[0]]
        max_gap = timedelta(minutes=max_gap_minutes)

        for sig in sorted_signals[1:]:
            gap = sig.normalized_timestamp - current[-1].normalized_timestamp
            if gap <= max_gap:
                current.append(sig)
            else:
                clusters.append(current)
                current = [sig]

        if current:
            clusters.append(current)

        return clusters
