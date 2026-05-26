"""Correlation engine — cross-source event correlation."""

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict

from threatlens.correlation.temporal_analyzer import TemporalAnalyzer
from threatlens.correlation.ttp_extractor import TTPExtractor
from threatlens.models import (
    CorrelatedEvent,
    RawSignal,
    Severity,
)


class CorrelationEngine:
    def __init__(self) -> None:
        self.ttp_extractor = TTPExtractor()
        self.temporal = TemporalAnalyzer()

    def correlate(self, signals: list[RawSignal]) -> list[CorrelatedEvent]:
        events: list[CorrelatedEvent] = []
        if not signals:
            return events

        events.extend(self._correlate_by_category(signals))
        events.extend(self._correlate_by_target(signals))
        events.extend(self._correlate_by_ttp(signals))
        events.extend(self._correlate_temporal(signals))

        seen_ids: set[str] = set()
        unique: list[CorrelatedEvent] = []
        for ev in events:
            if ev.id not in seen_ids:
                seen_ids.add(ev.id)
                unique.append(ev)

        unique.sort(key=lambda e: e.correlation_score, reverse=True)
        return unique

    def _correlate_by_category(self, signals: list[RawSignal]) -> list[CorrelatedEvent]:
        groups: defaultdict[str, list[RawSignal]] = defaultdict(list)
        for sig in signals:
            groups[f"{sig.category.value}:{sig.source.value}"].append(sig)

        events: list[CorrelatedEvent] = []
        for key, group in groups.items():
            if len(group) < 2:
                continue

            category, source = key.split(":", 1)
            ttps = self.ttp_extractor.extract_batch(group)
            unique_ttps = list({ttp["id"]: ttp for ttp in ttps}.values())
            max_sev = max((s.severity for s in group), default=Severity.INFO)
            timestamps = sorted(s.normalized_timestamp for s in group)

            event = CorrelatedEvent(
                id=f"corr-cat-{hashlib.md5(key.encode()).hexdigest()[:12]}",
                signals=group,
                correlation_type="same_category",
                correlation_score=min(100, len(group) * 15),
                title=f"Multiple {category} signals from {source}",
                description=f"Found {len(group)} signals of type {category} from {source}",
                ttps=unique_ttps,
                first_seen=timestamps[0].isoformat() if timestamps else "",
                last_seen=timestamps[-1].isoformat() if timestamps else "",
                severity=max_sev,
            )
            events.append(event)
        return events

    def _correlate_by_target(self, signals: list[RawSignal]) -> list[CorrelatedEvent]:
        groups: defaultdict[str, list[RawSignal]] = defaultdict(list)
        for sig in signals:
            if sig.target:
                groups[sig.target].append(sig)

        events: list[CorrelatedEvent] = []
        for target, group in groups.items():
            if len(group) < 2:
                continue

            sources = set(s.source for s in group)
            categories = set(s.category for s in group)
            if len(sources) < 2:
                continue

            ttps = self.ttp_extractor.extract_batch(group)
            unique_ttps = list({ttp["id"]: ttp for ttp in ttps}.values())
            max_sev = max((s.severity for s in group), default=Severity.INFO)
            timestamps = sorted(s.normalized_timestamp for s in group)

            event = CorrelatedEvent(
                id=f"corr-tgt-{hashlib.md5(target.encode()).hexdigest()[:12]}",
                signals=group,
                correlation_type="same_target",
                correlation_score=min(100, len(sources) * 20 + len(group) * 10),
                title=f"Multi-source targeting: {target[:60]}",
                description=f"Target {target} hit by {len(group)} signals "
                f"from {len(sources)} sources across "
                f"{len(categories)} categories",
                ttps=unique_ttps,
                first_seen=timestamps[0].isoformat() if timestamps else "",
                last_seen=timestamps[-1].isoformat() if timestamps else "",
                severity=max_sev,
            )
            events.append(event)
        return events

    def _correlate_by_ttp(self, signals: list[RawSignal]) -> list[CorrelatedEvent]:
        ttp_map: defaultdict[str, list[RawSignal]] = defaultdict(list)
        for sig in signals:
            ttps = self.ttp_extractor.extract(sig)
            for ttp in ttps:
                ttp_map[ttp["id"]].append(sig)

        events: list[CorrelatedEvent] = []
        for ttp_id, group in ttp_map.items():
            if len(group) < 2:
                continue

            sources = set(s.source for s in group)
            if len(sources) < 2:
                continue

            timestamps = sorted(s.normalized_timestamp for s in group)
            max_sev = max((s.severity for s in group), default=Severity.INFO)
            ttp_name = group[0].category.value

            event = CorrelatedEvent(
                id=f"corr-ttp-{ttp_id.lower().replace('.', '-')[:16]}",
                signals=group,
                correlation_type="shared_ttp",
                correlation_score=min(100, len(sources) * 25),
                title=f"Shared TTP {ttp_id} across {len(sources)} sources",
                description=f"TTP {ttp_id} detected by {len(sources)} tools",
                ttps=[{"id": ttp_id, "name": ttp_name}],
                first_seen=timestamps[0].isoformat() if timestamps else "",
                last_seen=timestamps[-1].isoformat() if timestamps else "",
                severity=max_sev,
            )
            events.append(event)
        return events

    def _correlate_temporal(self, signals: list[RawSignal]) -> list[CorrelatedEvent]:
        events: list[CorrelatedEvent] = []
        bursts = self.temporal.find_bursts(signals, threshold=3)
        for burst in bursts:
            burst_signals = [s for s in signals if s.source_id in burst["signals"]]
            if not burst_signals:
                continue

            sources = set(s.source for s in burst_signals)
            categories = set(s.category for s in burst_signals)
            max_sev = max((s.severity for s in burst_signals), default=Severity.INFO)
            ttps = self.ttp_extractor.extract_batch(burst_signals)
            unique_ttps = list({ttp["id"]: ttp for ttp in ttps}.values())

            event = CorrelatedEvent(
                id=f"corr-tmp-{uuid.uuid4().hex[:12]}",
                signals=burst_signals,
                correlation_type="temporal_burst",
                correlation_score=min(100, burst["signal_count"] * 10),
                title=f"Temporal burst: {burst['signal_count']} signals in {len(sources)} sources",
                description=f"Detected burst of {burst['signal_count']} signals "
                f"across {len(categories)} categories",
                ttps=unique_ttps,
                first_seen=burst["start_time"],
                last_seen=burst["end_time"],
                severity=max_sev,
            )
            events.append(event)
        return events
