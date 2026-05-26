"""ThreatLens CLI — Typer-based command-line interface."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer
import yaml
from rich.console import Console
from rich.table import Table

from threatlens import __version__
from threatlens.aggregator import Aggregator
from threatlens.correlation import (
    CampaignDetector,
    CorrelationEngine,
    TTPExtractor,
)
from threatlens.database import Database
from threatlens.models import RawSignal
from threatlens.reports import (
    ExecutiveReportGenerator,
    ReportGenerator,
)

app = typer.Typer(
    name="threatlens",
    help="Threat intelligence aggregation and correlation engine for AI/MCP security",
    no_args_is_help=True,
)
console = Console()

CONFIG_PATH = Path("~/.threatlens/config.yaml").expanduser()


def _load_config() -> dict[str, Any]:
    if CONFIG_PATH.exists():
        return yaml.safe_load(CONFIG_PATH.read_text()) or {}
    return {}


def _init_db(config: dict[str, Any]) -> Database:
    db_path = config.get("database", {}).get("path", "~/.threatlens/threatlens.db")
    db = Database(db_path=db_path)
    db.initialize()
    return db


@app.callback()
def main() -> None: ...


@app.command()
def init() -> None:
    """Initialize ThreatLens database and configuration."""
    config_dir = CONFIG_PATH.parent
    config_dir.mkdir(parents=True, exist_ok=True)

    if not CONFIG_PATH.exists():
        default_config = {
            "database": {"path": "~/.threatlens/threatlens.db"},
            "sources": {
                "mcpguard": {"enabled": True, "url": "http://localhost:8081"},
                "mcpwn": {"enabled": True, "results_dir": "~/.mcpwn/results"},
                "palisade": {"enabled": True, "url": "http://localhost:8082"},
                "agentgate": {"enabled": True, "log_path": "/var/log/agentgate/access.log"},
                "abliterate": {"enabled": True, "scan_dir": "~/.reverse-abliterate/scans"},
                "external": {"enabled": True, "nvd_api_key": ""},
            },
            "enrichment": {
                "cve": {"enabled": True, "nvd_api_key": ""},
                "atlas": {"enabled": True},
                "advisories": {"enabled": True},
            },
            "alerts": {
                "rules": [
                    {
                        "name": "critical-rce",
                        "severity": "critical",
                        "correlation_min": 2,
                        "notify": ["email", "telegram"],
                    }
                ],
                "notifiers": {
                    "telegram": {"bot_token": "", "chat_id": ""},
                    "webhook": {"url": ""},
                },
            },
            "reports": {
                "schedule": {"daily": True, "weekly": True, "monthly": True},
            },
        }
        CONFIG_PATH.write_text(yaml.dump(default_config, default_flow_style=False))
        console.print("[green]Created default configuration at ~/.threatlens/config.yaml[/green]")

    db = _init_db(_load_config())
    console.print(f"[green]Database initialized at {db.db_path}[/green]")
    console.print("[bold]ThreatLens is ready. Run 'threatlens aggregate' to start.[/bold]")


@app.command()
def aggregate(
    limit: int = typer.Option(100, help="Max signals per source"),
) -> None:
    """Aggregate signals from all configured sources."""
    config = _load_config()
    db = _init_db(config)
    aggregator = Aggregator(db, config)

    async def _run() -> list[RawSignal]:
        return await aggregator.aggregate_all(limit=limit)

    signals = asyncio.run(_run())

    table = Table(title="Aggregation Results")
    table.add_column("Source", style="cyan")
    table.add_column("Signals", style="magenta")

    source_counts: dict[str, int] = {}
    for s in signals:
        source_counts[s.source.value] = source_counts.get(s.source.value, 0) + 1

    for src, count in source_counts.items():
        table.add_row(src, str(count))

    console.print(table)


@app.command()
def correlate() -> None:
    """Run correlation engine on aggregated signals."""
    config = _load_config()
    db = _init_db(config)

    signals_data = db.get_signals(limit=1000)

    from threatlens.models import AttackCategory, Confidence, Severity, SignalSource

    signals: list[RawSignal] = []
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
                recommendation=row.get("recommendation", ""),
                detection_method=row.get("detection_method", ""),
                target=row.get("target", ""),
                snippet=row.get("snippet", ""),
                raw_data=json.loads(row.get("raw_data", "{}")),
                timestamp=row.get("timestamp", ""),
                blocked=bool(row.get("blocked")) if row.get("blocked") is not None else None,
                risk_score=row.get("risk_score", 0),
                tags=json.loads(row.get("tags", "[]")),
            )
        )

    engine = CorrelationEngine()
    correlated = engine.correlate(signals)

    detector = CampaignDetector()
    campaigns = detector.detect(signals, correlated)

    ttp_extractor = TTPExtractor()
    all_ttps = ttp_extractor.extract_batch(signals)

    for event in correlated:
        db.save_correlated_event(event)

    for campaign in campaigns:
        db.save_campaign(campaign)

    from threatlens.alerts.generator import AlertGenerator
    from threatlens.alerts.deduplicator import AlertDeduplicator

    alert_gen = AlertGenerator(db)
    alert_dedup = AlertDeduplicator()
    raw_alerts = alert_gen.generate(correlated, signals)
    alerts = alert_dedup.deduplicate(raw_alerts)

    table = Table(title="Correlation Results")
    table.add_column("Type", style="cyan")
    table.add_column("Count", style="magenta")
    table.add_row("Correlated Events", str(len(correlated)))
    table.add_row("Alerts Generated", str(len(alerts)))
    table.add_row("Campaigns Detected", str(len(campaigns)))
    table.add_row("Unique TTPs", str(len(set(t["id"] for t in all_ttps))))
    console.print(table)

    if alerts:
        console.print("\n[bold red]Alerts:[/bold red]")
        for a in alerts[:5]:
            console.print(f"  [red]{a.severity.value.upper()}[/red] {a.title[:80]}")
    if campaigns:
        console.print("\n[bold yellow]Campaigns:[/bold yellow]")
        for c in campaigns[:5]:
            console.print(f"  [red]{c.name}[/red] — {len(c.signals)} signals, {len(c.ttps)} TTPs")


@app.command()
def report(
    report_type: str = typer.Option("daily", help="Report type: daily, weekly, monthly, executive"),
    output: str | None = typer.Option(None, help="Output file path"),
) -> None:
    """Generate threat intelligence reports."""
    config = _load_config()
    db = _init_db(config)

    signals_data = db.get_signals(limit=5000)

    from threatlens.models import (
        AttackCategory,
        Confidence,
        Severity,
        SignalSource,
    )

    signals: list[RawSignal] = []
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
                recommendation=row.get("recommendation", ""),
                detection_method=row.get("detection_method", ""),
                target=row.get("target", ""),
                snippet=row.get("snippet", ""),
                raw_data=json.loads(row.get("raw_data", "{}")),
                timestamp=row.get("timestamp", ""),
                blocked=bool(row.get("blocked")) if row.get("blocked") is not None else None,
                risk_score=row.get("risk_score", 0),
                tags=json.loads(row.get("tags", "[]")),
            )
        )

    if report_type == "executive":
        report_obj = ExecutiveReportGenerator(db).generate(
            signals, [], [], period_label="Current Period"
        )
    else:
        report_obj = ReportGenerator(db).generate(
            report_type=report_type,
            signals=signals,
            correlated_events=[],
            alerts=[],
            campaigns=[],
        )

    if output:
        output_path = Path(output).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report_dict = {
            "id": report_obj.id,
            "type": report_obj.report_type,
            "title": report_obj.title,
            "summary": report_obj.summary,
            "period_start": report_obj.period_start,
            "period_end": report_obj.period_end,
            "total_signals": report_obj.total_signals,
            "total_alerts": report_obj.total_alerts,
            "total_campaigns": report_obj.total_campaigns,
            "top_ttps": report_obj.top_ttps,
            "top_sources": report_obj.top_sources,
            "severity_distribution": report_obj.severity_distribution,
            "executive_summary": report_obj.executive_summary,
            "recommendations": report_obj.recommendations,
        }
        output_path.write_text(json.dumps(report_dict, indent=2))
        console.print(f"[green]Report saved to {output_path}[/green]")
    else:
        console.print(f"[bold]Report:[/bold] {report_obj.title}")
        console.print(f"  Summary: {report_obj.summary}")
        console.print(f"  Signals: {report_obj.total_signals}")
        console.print(f"  Alerts: {report_obj.total_alerts}")
        console.print(f"  Campaigns: {report_obj.total_campaigns}")
        if report_obj.recommendations:
            console.print("\n[bold yellow]Recommendations:[/bold yellow]")
            for r in report_obj.recommendations:
                console.print(f"  - {r}")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Host to bind to"),
    port: int = typer.Option(8080, help="Port to bind to"),
) -> None:
    """Start the ThreatLens web dashboard."""
    import uvicorn

    config = _load_config()
    db = _init_db(config)

    from threatlens.web.server import create_app

    app_instance = create_app(db=db, config=config)
    console.print(f"[green]ThreatLens dashboard starting at http://{host}:{port}[/green]")
    uvicorn.run(app_instance, host=host, port=port, log_level="info")


@app.command()
def feed(
    format: str = typer.Option("json", help="Output format: json"),
    source: str | None = typer.Option(None, help="Filter by source"),
    severity: str | None = typer.Option(None, help="Filter by severity"),
    limit: int = typer.Option(100, help="Max signals to export"),
    output: str | None = typer.Option(None, help="Output file path"),
) -> None:
    """Export threat feed in STIX-compatible format."""
    config = _load_config()
    db = _init_db(config)

    signals = db.get_signals(source=source, severity=severity, limit=limit)

    feed_data = {
        "feed_version": "1.0",
        "provider": "ThreatLens",
        "generated_at": datetime.now(UTC).isoformat(),
        "total_signals": len(signals),
        "signals": signals,
    }

    if output:
        output_path = Path(output).expanduser()
        output_path.write_text(json.dumps(feed_data, indent=2))
        console.print(f"[green]Threat feed saved to {output_path}[/green]")
    else:
        console.print(json.dumps(feed_data, indent=2))


@app.command()
def enrich() -> None:
    """Enrich signals with external threat intelligence."""
    config = _load_config()
    db = _init_db(config)

    enrichment_config = config.get("enrichment", {})
    signals = db.get_signals(limit=100)

    from threatlens.enrichment.cve_lookup import CVELookup

    if enrichment_config.get("cve", {}).get("enabled", True):
        api_key = enrichment_config.get("cve", {}).get("nvd_api_key", "")
        cve_lookup = CVELookup(api_key=api_key)
        # Find CVE references in signals
        cve_ids = set()
        for s in signals:
            desc = s.get("description", "") + " " + s.get("snippet", "")
            import re

            found = re.findall(r"CVE-\d{4}-\d{4,7}", desc)
            cve_ids.update(found)

        if cve_ids:
            console.print(f"Found {len(cve_ids)} CVE references in signals")
            for cve_id in list(cve_ids)[:10]:
                result = asyncio.run(cve_lookup.lookup(cve_id))
                if result:
                    console.print(
                        f"  [cyan]{cve_id}[/cyan]: CVSS {result.get('base_score', 'N/A')}"
                    )

    console.print("[green]Enrichment complete[/green]")


@app.command()
def status() -> None:
    """Show ThreatLens system status."""
    config = _load_config()
    db = _init_db(config)

    stats = db.get_stats()
    config_path = CONFIG_PATH

    table = Table(title="ThreatLens Status")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    table.add_row("Version", __version__)
    table.add_row("Config", str(config_path) if config_path.exists() else "Not found")
    table.add_row("Database", str(db.db_path))
    table.add_row("Total Signals", str(stats.get("total_signals", 0)))
    table.add_row("Total Alerts", str(stats.get("total_alerts", 0)))
    table.add_row("Active Campaigns", str(stats.get("total_campaigns", 0)))
    table.add_row("Last Signal", str(stats.get("last_signal_at", "N/A")))

    console.print(table)
