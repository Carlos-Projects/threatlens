"""Tests for Palisade source client."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from threatlens.sources.palisade import PalisadeClient


def _mock_async_client(get_return: MagicMock | None = None) -> AsyncMock:
    mock_client = AsyncMock()
    if get_return:
        mock_client.get.return_value = get_return
    mock_client.__aenter__.return_value = mock_client
    return mock_client


class TestPalisadeClient:
    def test_name(self):
        client = PalisadeClient()
        assert client.name == "palisade"

    @pytest.mark.asyncio
    async def test_fetch_connection_error(self):
        client = PalisadeClient(base_url="http://nonexistent")
        mock_client = _mock_async_client()
        mock_client.get.side_effect = Exception("Connection error")

        with patch("httpx.AsyncClient", return_value=mock_client):
            signals = await client.fetch()
            assert signals == []

    def test_base_url_format(self):
        client = PalisadeClient(base_url="http://localhost:8082")
        assert client.base_url == "http://localhost:8082"

    @pytest.mark.asyncio
    async def test_fetch_with_valid_response(self):
        client = PalisadeClient(base_url="http://localhost:8082")

        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {
                "findings": [
                    {
                        "category": "jailbreak",
                        "severity": "high",
                        "title": "Jailbreak detected",
                    }
                ]
            }
        ]

        mock_client = _mock_async_client(get_return=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            signals = await client.fetch(limit=10)
            assert len(signals) >= 1
