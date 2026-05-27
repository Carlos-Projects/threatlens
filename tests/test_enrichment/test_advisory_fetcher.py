"""Tests for advisory fetcher."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from threatlens.enrichment.advisory_fetcher import AdvisoryFetcher


def _mock_async_client(
    get_return: MagicMock | None = None, post_return: MagicMock | None = None
) -> AsyncMock:
    mock_client = AsyncMock()
    if get_return:
        mock_client.get.return_value = get_return
    if post_return:
        mock_client.post.return_value = post_return
    mock_client.__aenter__.return_value = mock_client
    return mock_client


class TestAdvisoryFetcher:
    def setup_method(self):
        self.fetcher = AdvisoryFetcher()

    @pytest.mark.asyncio
    async def test_fetch_recent_network_error(self):
        mock_client = _mock_async_client()
        mock_client.get.side_effect = Exception("Network error")

        with patch("httpx.AsyncClient", return_value=mock_client):
            advisories = await self.fetcher.fetch_recent(days=1, limit=10)
            assert advisories == []

    @pytest.mark.asyncio
    async def test_query_osv_network_error(self):
        mock_client = _mock_async_client()
        mock_client.post.side_effect = Exception("Network error")

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await self.fetcher.query_osv("flask")
            assert result == []

    @pytest.mark.asyncio
    async def test_fetch_recent_with_results(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2025-0001",
                        "published": "2025-01-01T00:00:00",
                        "descriptions": [{"lang": "en", "value": "Test"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.0, "baseSeverity": "CRITICAL"}}
                            ]
                        },
                    }
                }
            ]
        }

        mock_client = _mock_async_client(get_return=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            advisories = await self.fetcher.fetch_recent(days=7, limit=10)
            assert len(advisories) == 1
            assert advisories[0]["id"] == "CVE-2025-0001"

    def test_get_description_empty(self):
        desc = self.fetcher._get_description({})
        assert desc == ""

    def test_get_severity_empty(self):
        sev = self.fetcher._get_severity({})
        assert sev == "UNKNOWN"

    @pytest.mark.asyncio
    async def test_query_osv_success(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-xxxx",
                    "summary": "Test vuln",
                    "aliases": ["CVE-2025-0001"],
                    "severity": [],
                }
            ]
        }
        mock_client = _mock_async_client(post_return=mock_resp)
        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await self.fetcher.query_osv("flask")
            assert len(result) == 1
            assert result[0]["id"] == "GHSA-xxxx"
