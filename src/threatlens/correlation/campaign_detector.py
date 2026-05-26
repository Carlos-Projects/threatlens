"""Campaign detection — identifies related threat campaigns across signals."""

from __future__ import annotations

import hashlib
from collections import defaultdict

from threatlens.correlation.temporal_analyzer import TemporalAnalyzer
from threatlens.correlation.ttp_extractor import TTPExtractor
from threatlens.models import Campaign, CorrelatedEvent, RawSignal, Severity


class CampaignDetector:
    def __init__(self) -> None:
        self.ttp_extractor = TTPExtractor()
        self.temporal = TemporalAnalyzer()

    def detect(
        self,
        signals: list[RawSignal],
        correlated_events: list[CorrelatedEvent] | None = None,
    ) -> list[Campaign]:
        campaigns: list[Campaign] = []
        if not signals:
            return campaigns

        ttp_to_signals: dict[str, list[RawSignal]] = defaultdict(list)
        for sig in signals:
            ttps = self.ttp_extractor.extract(sig)
            for ttp in ttps:
                ttp_to_signals[ttp["id"]].append(sig)

        clusters = self.temporal.find_temporal_clusters(signals)

        candidate_groups: list[list[RawSignal]] = []
        for _, ttp_signals in ttp_to_signals.items():
            if len(ttp_signals) >= 3:
                candidate_groups.append(ttp_signals)

        for cluster in clusters:
            if len(cluster) >= 3:
                candidate_groups.append(cluster)

        seen_ids: set[str] = set()
        for group in candidate_groups:
            group_id = self._group_id(group)
            if group_id in seen_ids:
                continue
            seen_ids.add(group_id)

            all_ttps = self.ttp_extractor.extract_batch(group)
            unique_ttps = list({ttp["id"]: ttp for ttp in all_ttps}.values())
            categories = set(s.category for s in group)
            sources = set(s.source for s in group)

            max_sev = max((s.severity for s in group), default=Severity.INFO)
            timestamps = sorted(s.normalized_timestamp for s in group)

            campaign = Campaign(
                id=group_id,
                name=f"Campaign: {', '.join(c.value for c in categories)[:80]}",
                description=f"Detected {len(group)} signals across "
                f"{len(sources)} sources with "
                f"{len(unique_ttps)} unique TTPs",
                severity=max_sev,
                signals=group,
                ttps=unique_ttps,
                tags=list({f"source:{s.value}" for s in sources}),
                first_seen=timestamps[0].isoformat() if timestamps else "",
                last_seen=timestamps[-1].isoformat() if timestamps else "",
            )
            campaigns.append(campaign)

        campaigns.sort(key=lambda c: c.severity.weight, reverse=True)
        return campaigns

    def _group_id(self, group: list[RawSignal]) -> str:
        ids = sorted(s.source_id for s in group)
        h = hashlib.sha256("".join(ids).encode()).hexdigest()[:16]
        return f"camp-{h}"
