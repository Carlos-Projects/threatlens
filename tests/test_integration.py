"""Integration test — end-to-end flow with FastAPI TestClient."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from mcp_taxonomy import AttackCategory, Confidence

from threatlens.database import Database
from threatlens.models import Alert, RawSignal, Severity, SignalSource
from threatlens.web.server import create_app


@pytest.fixture
def db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    database = Database(db_path=tmp.name)
    database.initialize()
    database.save_signals(
        [
            RawSignal(
                source=SignalSource.MCPGUARD,
                source_id="int-sig-1",
                category=AttackCategory.INJECTION,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Integration test signal",
                target="/api/chat",
                risk_score=75,
            ),
            RawSignal(
                source=SignalSource.MCPWN,
                source_id="int-sig-2",
                category=AttackCategory.RCE,
                severity=Severity.CRITICAL,
                confidence=Confidence.CERTAIN,
                title="RCE detected",
                target="/api/execute",
                risk_score=95,
            ),
        ]
    )
    database.save_alert(
        Alert(
            id="int-alert-1",
            title="Critical RCE Alert",
            description="RCE via MCPwn",
            severity=Severity.CRITICAL,
            correlation_ids=[],
            signal_ids=["int-sig-2"],
            ttps=[{"id": "AML.T0059", "name": "RCE"}],
            enriched={},
        )
    )
    from threatlens.models import Campaign

    database.save_campaign(
        Campaign(
            id="int-camp-1",
            name="Test Campaign",
            description="Integration test",
            severity=Severity.HIGH,
            signals=[],
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


class TestIntegration:
    @pytest.mark.asyncio
    async def test_full_dashboard_loads(self, client):
        resp = await client.get("/")
        assert resp.status_code == 200
        html = resp.text
        assert "ThreatLens" in html
        assert "Integration test signal" not in html  # not in dashboard
        assert "Critical RCE Alert" in html

    @pytest.mark.asyncio
    async def test_signals_page_shows_data(self, client):
        resp = await client.get("/signals")
        assert resp.status_code == 200
        assert "Integration test signal" in resp.text

    @pytest.mark.asyncio
    async def test_signals_filtered_by_source(self, client):
        resp = await client.get("/signals?source=mcpwn")
        assert resp.status_code == 200
        assert "RCE detected" in resp.text
        assert "Integration test signal" not in resp.text

    @pytest.mark.asyncio
    async def test_signals_filtered_by_severity(self, client):
        resp = await client.get("/signals?severity=critical")
        assert resp.status_code == 200
        assert "RCE detected" in resp.text
        assert "Integration test signal" not in resp.text

    @pytest.mark.asyncio
    async def test_signals_pagination_offset(self, client):
        resp = await client.get("/signals?limit=1&offset=0")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_alerts_page_shows_alerts(self, client):
        resp = await client.get("/alerts")
        assert resp.status_code == 200
        assert "Critical RCE Alert" in resp.text

    @pytest.mark.asyncio
    async def test_alerts_filtered_by_severity(self, client):
        resp = await client.get("/alerts?severity=critical")
        assert resp.status_code == 200
        assert "Critical RCE Alert" in resp.text

    @pytest.mark.asyncio
    async def test_alerts_pagination(self, client):
        resp = await client.get("/alerts?limit=1&offset=0")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_api_signals_endpoint(self, client):
        resp = await client.get("/api/v1/signals")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 2

    @pytest.mark.asyncio
    async def test_api_alerts_endpoint(self, client):
        resp = await client.get("/api/v1/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1

    @pytest.mark.asyncio
    async def test_api_campaigns_endpoint(self, client):
        resp = await client.get("/api/v1/campaigns")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1

    @pytest.mark.asyncio
    async def test_api_stats(self, client):
        resp = await client.get("/api/v1/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_signals"] >= 2
        assert data["total_alerts"] >= 1
        assert data["total_campaigns"] >= 1

    @pytest.mark.asyncio
    async def test_feed_endpoint(self, client):
        resp = await client.get("/api/v1/feed")
        assert resp.status_code == 200
        data = resp.json()
        assert data["feed_version"] == "1.0"
        assert len(data["signals"]) >= 2

    @pytest.mark.asyncio
    async def test_health_endpoint(self, client):
        resp = await client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
