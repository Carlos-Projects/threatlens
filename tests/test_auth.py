"""Tests for API key auth middleware."""

from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport

from fastapi import FastAPI
from threatlens.web.auth import APIKeyMiddleware


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
