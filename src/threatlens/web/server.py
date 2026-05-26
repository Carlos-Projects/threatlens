"""FastAPI web server with HTMX dashboard."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader

from threatlens.database import Database

SEVERITY_COLORS = {
    "critical": "red-600",
    "high": "orange-500",
    "medium": "yellow-500",
    "low": "blue-400",
    "info": "gray-400",
}


def _severity_color(sev: str) -> str:
    return SEVERITY_COLORS.get(sev, "gray-400")


def _env() -> Environment:
    templates = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(templates)))
    env.globals["sev_color"] = _severity_color
    return env


def _render(template_name: str, **kwargs: Any) -> str:
    return _env().get_template(template_name).render(**kwargs)


def create_app(db: Database | None = None, config: dict[str, Any] | None = None) -> FastAPI:
    app = FastAPI(title="ThreatLens", version="0.1.0")
    _db = db or Database()

    @app.get("/api/v1/health")
    async def health():
        return {"status": "ok", "version": "0.1.0"}

    @app.get("/api/v1/stats")
    async def stats():
        return _db.get_stats()

    @app.get("/api/v1/signals")
    async def list_signals(
        source: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ):
        return _db.get_signals(
            source=source,
            severity=severity,
            category=category,
            limit=limit,
            offset=offset,
        )

    @app.get("/api/v1/alerts")
    async def list_alerts(severity: str | None = None, limit: int = 100, offset: int = 0):
        return _db.get_alerts(severity=severity, limit=limit, offset=offset)

    @app.get("/api/v1/campaigns")
    async def list_campaigns(active_only: bool = True):
        return _db.get_campaigns(active_only=active_only)

    @app.get("/api/v1/reports")
    async def list_reports(report_type: str | None = None, limit: int = 10):
        return _db.get_reports(report_type=report_type, limit=limit)

    @app.get("/api/v1/feed")
    async def threat_feed(
        source: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ):
        signals = _db.get_signals(source=source, severity=severity, limit=limit)
        return {"feed_version": "1.0", "provider": "ThreatLens", "signals": signals}

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        stats_data = _db.get_stats()
        alerts = _db.get_alerts(limit=20)
        campaigns = _db.get_campaigns()

        sev_dist = stats_data.get("severity_distribution", {})
        src_dist = stats_data.get("source_distribution", {})

        return _render(
            "index.html",
            stats=stats_data,
            alerts=alerts,
            campaigns=campaigns,
            severity_bars=[(k, v) for k, v in sev_dist.items()],
            source_bars=[(k, v) for k, v in src_dist.items()],
        )

    @app.get("/signals", response_class=HTMLResponse)
    async def signals_page(
        request: Request,
        source: str | None = None,
        severity: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ):
        signals = _db.get_signals(source=source, severity=severity, limit=limit, offset=offset)
        return _render("signals_table.html", signals=signals)

    @app.get("/alerts", response_class=HTMLResponse)
    async def alerts_page(request: Request):
        alerts = _db.get_alerts(limit=50)
        return _render("alerts_cards.html", alerts=alerts)

    return app
