"""Tests for the FastAPI web server."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from httpx import AsyncClient, ASGITransport

from threatlens.database import Database
from threatlens.web.server import create_app, _severity_color, _render

from mcp_taxonomy import AttackCategory, Confidence


@pytest.fixture
def db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    database = Database(db_path=tmp.name)
    database.initialize()

    from threatlens.models import RawSignal, Severity, SignalSource, Alert

    database.save_signals(
        [
            RawSignal(
                source=SignalSource.MCPGUARD,
                source_id="ws-sig-1",
                category=AttackCategory.INJECTION,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Web test signal",
            ),
            RawSignal(
                source=SignalSource.MCPWN,
                source_id="ws-sig-2",
                category=AttackCategory.RCE,
                severity=Severity.CRITICAL,
                confidence=Confidence.CERTAIN,
                title="RCE from web",
            ),
        ]
    )
    database.save_alert(
        Alert(
            id="ws-alert-1",
            title="Web Alert",
            description="Test",
            severity=Severity.CRITICAL,
            correlation_ids=[],
            signal_ids=[],
            ttps=[],
            enriched={},
        )
    )
    tmp.close()
    yield database
    database.close()
    Path(tmp.name).unlink(missing_ok=True)


@pytest.fixture
def client(db):
    app = create_app(db=db)
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


class TestWebServer:
    @pytest.mark.asyncio
    async def test_health_endpoint(self, client):
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_stats_endpoint(self, client):
        response = await client.get("/api/v1/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_signals" in data
        assert data["total_signals"] >= 2

    @pytest.mark.asyncio
    async def test_signals_endpoint(self, client):
        response = await client.get("/api/v1/signals")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 2

    @pytest.mark.asyncio
    async def test_signals_filtered(self, client):
        response = await client.get("/api/v1/signals?source=mcpguard")
        assert response.status_code == 200
        data = response.json()
        assert all(s["source"] == "mcpguard" for s in data)

    @pytest.mark.asyncio
    async def test_alerts_endpoint(self, client):
        response = await client.get("/api/v1/alerts")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1

    @pytest.mark.asyncio
    async def test_campaigns_endpoint(self, client):
        response = await client.get("/api/v1/campaigns")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_reports_endpoint(self, client):
        response = await client.get("/api/v1/reports")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_feed_endpoint(self, client):
        response = await client.get("/api/v1/feed")
        assert response.status_code == 200
        data = response.json()
        assert data["feed_version"] == "1.0"

    @pytest.mark.asyncio
    async def test_dashboard_html(self, client):
        response = await client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_signals_html(self, client):
        response = await client.get("/signals")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_alerts_html(self, client):
        response = await client.get("/alerts")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")


class TestServerUtils:
    def test_severity_color_mapping(self):
        assert _severity_color("critical") == "red-600"
        assert _severity_color("high") == "orange-500"
        assert _severity_color("unknown") == "gray-400"

    def test_render_template_not_found(self):
        with pytest.raises(Exception):
            _render("nonexistent.html")


class TestCreateApp:
    def test_create_without_db(self):
        app = create_app()
        assert app.title == "ThreatLens"
