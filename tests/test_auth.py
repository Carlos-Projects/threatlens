"""Tests for API key auth middleware and security headers."""

from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport

from fastapi import FastAPI
from threatlens.web.auth import APIKeyMiddleware
from threatlens.web.server import create_app


@pytest.fixture
def app_with_auth():
    app = FastAPI()
    app.add_middleware(APIKeyMiddleware, api_key="test-key-123")

    @app.get("/api/v1/test")
    async def api_test():
        return {"status": "ok"}

    @app.get("/")
    async def root():
        return "Hello"

    return app


@pytest.fixture
def app_no_auth():
    app = FastAPI()
    app.add_middleware(APIKeyMiddleware, api_key="")

    @app.get("/api/v1/test")
    async def api_test():
        return {"status": "ok"}

    return app


class TestAPIKeyMiddleware:
    @pytest.mark.asyncio
    async def test_no_auth_passes_through(self, app_no_auth):
        transport = ASGITransport(app=app_no_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/test")
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_missing_key_rejected(self, app_with_auth):
        transport = ASGITransport(app=app_with_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/test")
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_key_accepted(self, app_with_auth):
        transport = ASGITransport(app=app_with_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/test",
                headers={"Authorization": "Bearer test-key-123"},
            )
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_wrong_key_rejected(self, app_with_auth):
        transport = ASGITransport(app=app_with_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/test",
                headers={"Authorization": "Bearer wrong-key"},
            )
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_static_files_bypass_auth(self, app_with_auth):
        transport = ASGITransport(app=app_with_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/static/style.css")
            assert resp.status_code in (200, 404)

    @pytest.mark.asyncio
    async def test_web_page_gets_login_form(self, app_with_auth):
        transport = ASGITransport(app=app_with_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/")
            assert resp.status_code == 401
            assert "Unauthorized" in resp.text

    @pytest.mark.asyncio
    async def test_web_page_with_valid_cookie(self, app_with_auth):
        transport = ASGITransport(app=app_with_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/", cookies={"token": "test-key-123"})
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_web_page_with_x_api_key_header(self, app_with_auth):
        transport = ASGITransport(app=app_with_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/", headers={"X-API-Key": "test-key-123"})
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_login_success_redirects(self, app_with_auth):
        transport = ASGITransport(app=app_with_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/auth", data={"key": "test-key-123"})
            assert resp.status_code == 302
            assert resp.headers.get("location") == "/"

    @pytest.mark.asyncio
    async def test_login_failure(self, app_with_auth):
        transport = ASGITransport(app=app_with_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/auth", data={"key": "wrong-key"})
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_rate_limiting(self, app_with_auth):
        transport = ASGITransport(app=app_with_auth)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            for _ in range(10):
                await client.post("/auth", data={"key": "wrong"})
            resp = await client.post("/auth", data={"key": "wrong"})
            assert resp.status_code == 429


class TestSecurityHeaders:
    @pytest.mark.asyncio
    async def test_security_headers_via_create_app(self):
        app = create_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/health")
            assert resp.headers.get("content-security-policy") is not None
            assert resp.headers.get("x-content-type-options") == "nosniff"
            assert resp.headers.get("x-frame-options") == "DENY"
            assert resp.headers.get("x-xss-protection") is not None
            assert resp.headers.get("referrer-policy") is not None
