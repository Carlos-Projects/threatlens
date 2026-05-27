"""Tests for CVE lookup."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from threatlens.enrichment.cve_lookup import CVELookup


def _mock_async_client(get_return: MagicMock | None = None) -> AsyncMock:
    mock_client = AsyncMock()
    if get_return:
        mock_client.get.return_value = get_return
    mock_client.__aenter__.return_value = mock_client
    return mock_client


class TestCVELookup:
    def test_init(self):
        lookup = CVELookup(api_key="test-key")
        assert lookup.api_key == "test-key"

    @pytest.mark.asyncio
    async def test_lookup_with_api_key(self):
        lookup = CVELookup(api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulnerabilities": []}
        mock_client = _mock_async_client(get_return=mock_resp)
        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await lookup.lookup("CVE-2025-9999")
            assert result is None

    @pytest.mark.asyncio
    async def test_lookup_network_error(self):
        lookup = CVELookup()
        mock_client = _mock_async_client()
        mock_client.get.side_effect = Exception("Network error")

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await lookup.lookup("CVE-2025-0001")
            assert result is None

    @pytest.mark.asyncio
    async def test_lookup_success(self):
        lookup = CVELookup()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2025-0001",
                        "descriptions": [{"lang": "en", "value": "Test vuln"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.0, "baseSeverity": "CRITICAL"}}
                            ]
                        },
                        "published": "2025-01-01T00:00:00",
                        "lastModified": "2025-01-02T00:00:00",
                        "references": [],
                        "weaknesses": [],
                    }
                }
            ]
        }

        mock_client = _mock_async_client(get_return=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await lookup.lookup("CVE-2025-0001")
            assert result is not None
            assert result["id"] == "CVE-2025-0001"

    def test_parse_cve(self):
        lookup = CVELookup()
        cve = {
            "id": "CVE-2025-0001",
            "descriptions": [{"lang": "en", "value": "Test vuln"}],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.0, "baseSeverity": "CRITICAL"}}]
            },
            "published": "2025-01-01T00:00:00",
            "lastModified": "2025-01-02T00:00:00",
            "references": [{"url": "https://example.com", "source": "test"}],
            "weaknesses": [{"source": "test", "description": [{"value": "CWE-79"}]}],
        }
        parsed = lookup._parse_cve(cve)
        assert parsed["id"] == "CVE-2025-0001"
        assert parsed["base_score"] == 9.0
        assert parsed["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_bulk_lookup(self):
        lookup = CVELookup()
        with patch.object(lookup, "lookup", new=AsyncMock(return_value={"id": "test"})):
            results = await lookup.bulk_lookup(["CVE-2025-0001", "CVE-2025-0002"])
            assert len(results) == 2
