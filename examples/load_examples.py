#!/usr/bin/env python3
"""Load example data into ThreatLens database for demo/testing."""

from __future__ import annotations

import json
from pathlib import Path

from threatlens.aggregator import Aggregator
from threatlens.database import Database
from threatlens.models import RawSignal, Severity, SignalSource, Alert
from mcp_taxonomy import AttackCategory, Confidence


def load_examples(db: Database, examples_dir: str = "examples") -> int:
    examples = Path(examples_dir).expanduser()
    count = 0

    mcpguard_file = examples / "mcpguard_events.json"
    if mcpguard_file.exists():
        events = json.loads(mcpguard_file.read_text())
        from mcp_taxonomy import mcpguard_event_to_taxonomy

        for ev in events:
            tax = mcpguard_event_to_taxonomy(ev)
            sig = RawSignal(
                source=SignalSource.MCPGUARD,
                source_id=f"demo-mcpguard-{tax.title[:20]}",
                category=tax.attack_category,
                severity=tax.severity,
                confidence=tax.confidence,
                title=tax.title,
                description=tax.description,
                recommendation=tax.recommendation,
                detection_method=str(tax.detection_method),
                target=tax.target,
                snippet=tax.snippet,
                raw_data=ev,
                timestamp=tax.timestamp,
                blocked=tax.blocked,
                risk_score=tax.risk_score,
            )
            db.save_signals([sig])
            count += 1

    mcpwn_file = examples / "mcpwn_findings.json"
    if mcpwn_file.exists():
        findings = json.loads(mcpwn_file.read_text())
        from mcp_taxonomy import mcpwn_finding_to_taxonomy

        for f in findings:
            tax = mcpwn_finding_to_taxonomy(f)
            sig = RawSignal(
                source=SignalSource.MCPWN,
                source_id=f"demo-mcpwn-{f.get('title', '')[:20]}",
                category=tax.attack_category,
                severity=tax.severity,
                confidence=tax.confidence,
                title=tax.title,
                description=tax.description,
                recommendation=tax.recommendation,
                detection_method=str(tax.detection_method),
                target=tax.target,
                snippet=tax.snippet,
                raw_data=f,
                timestamp=tax.timestamp,
                risk_score=tax.risk_score,
            )
            db.save_signals([sig])
            count += 1

    palisade_file = examples / "palisade_scans.json"
    if palisade_file.exists():
        scans = json.loads(palisade_file.read_text())
        from mcp_taxonomy import palisade_finding_to_taxonomy

        for scan in scans:
            for finding in scan.get("findings", []):
                tax = palisade_finding_to_taxonomy(finding)
                sig = RawSignal(
                    source=SignalSource.PALISADE,
                    source_id=f"demo-palisade-{finding.get('title', '')[:20]}",
                    category=tax.attack_category,
                    severity=tax.severity,
                    confidence=tax.confidence,
                    title=tax.title,
                    description=tax.description,
                    recommendation=tax.recommendation,
                    detection_method=str(tax.detection_method),
                    target=scan.get("url", ""),
                    snippet=tax.snippet,
                    raw_data=finding,
                    timestamp=tax.timestamp,
                    risk_score=tax.risk_score,
                )
                db.save_signals([sig])
                count += 1

    abliterate_file = examples / "abliterate_scans.json"
    if abliterate_file.exists():
        scans = json.loads(abliterate_file.read_text())
        from threatlens.sources.abliterate import _abliterate_to_taxonomy

        for scan in scans:
            tax = _abliterate_to_taxonomy(scan)
            sig = RawSignal(
                source=SignalSource.ABLITERATE,
                source_id=f"demo-abliterate-{scan.get('title', '')[:20]}",
                category=tax.attack_category,
                severity=tax.severity,
                confidence=tax.confidence,
                title=tax.title,
                description=tax.description,
                recommendation=tax.recommendation,
                detection_method=str(tax.detection_method),
                target=tax.target,
                snippet=tax.snippet,
                raw_data=scan,
                timestamp=tax.timestamp,
                risk_score=tax.risk_score,
                tags=["model-scan", "abliteration"],
            )
            db.save_signals([sig])
            count += 1

    return count


def create_demo_alerts(db: Database) -> int:
    from threatlens.correlation import CorrelationEngine
    from threatlens.alerts.generator import AlertGenerator

    signals_data = db.get_signals(limit=500)
    import json as _json

    signals = []
    if signals_data:
        for row in signals_data:
            signals.append(
                RawSignal(
                    source=SignalSource(row["source"]),
                    source_id=row["source_id"],
                    category=AttackCategory(row["category"]),
                    severity=Severity(row["severity"]),
                    confidence=Confidence(row["confidence"]),
                    title=row["title"],
                    description=row.get("description", ""),
                )
            )
            if len(signals) >= 100:
                break

    if not signals:
        return 0

    engine = CorrelationEngine()
    events = engine.correlate(signals)
    gen = AlertGenerator(db)
    alerts = gen.generate(events, signals)
    return len(alerts)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Load example data into ThreatLens")
    parser.add_argument("--db", default="~/.threatlens/threatlens.db", help="Database path")
    parser.add_argument("--examples", default="examples", help="Examples directory")
    args = parser.parse_args()

    db = Database(db_path=args.db)
    db.initialize()

    count = load_examples(db, args.examples)
    print(f"Loaded {count} signals from example data")

    alert_count = create_demo_alerts(db)
    print(f"Generated {alert_count} demo alerts")

    print("Done. Run 'threatlens serve' to view the dashboard.")
