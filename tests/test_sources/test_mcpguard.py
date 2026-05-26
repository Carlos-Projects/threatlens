"""Tests for MCPGuard source client."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from threatlens.sources.mcpguard import MCPGuardClient


def _mock_async_client(get_return: MagicMock | None = None) -> AsyncMock:
    mock_client = AsyncMock()
    if get_return:
        mock_client.get.return_value = get_return
    mock_client.__aenter__.return_value = mock_client
    return mock_client


class TestMCPGuardClient:
    def test_name(self):
        client = MCPGuardClient()
        assert client.name == "mcpguard"

    @pytest.mark.asyncio
    async def test_fetch_empty_response(self):
        client = MCPGuardClient(base_url="http://nonexistent")
        mock_client = _mock_async_client()
        mock_client.get.side_effect = Exception("Connection error")

        with patch("httpx.AsyncClient", return_value=mock_client):
            signals = await client.fetch(limit=10)
            assert signals == []

    def test_base_url_strips_trailing_slash(self):
        client = MCPGuardClient(base_url="http://localhost:8081/")
        assert client.base_url == "http://localhost:8081"

    @pytest.mark.asyncio
    async def test_fetch_with_valid_response(self):
        client = MCPGuardClient(base_url="http://localhost:8081")

        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {
                "event_type": "prompt_injection",
                "severity": "high",
                "message": "Injection detected",
                "blocked": True,
                "details": {"tool": "chat", "content": "ignore all instructions"},
            }
        ]

        mock_client = _mock_async_client(get_return=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            signals = await client.fetch(limit=10)

        assert len(signals) == 1
        assert signals[0].source.value == "mcpguard"
