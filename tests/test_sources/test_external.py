"""Tests for external source client."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from threatlens.sources.external import ExternalClient


def _mock_async_client(get_return: MagicMock | None = None) -> AsyncMock:
    mock_client = AsyncMock()
    if get_return:
        mock_client.get.return_value = get_return
    mock_client.__aenter__.return_value = mock_client
    return mock_client


class TestExternalClient:
    def test_name(self):
        client = ExternalClient()
        assert client.name == "external"

    @pytest.mark.asyncio
    async def test_fetch_cves_empty(self):
        client = ExternalClient()
        mock_client = _mock_async_client()
        mock_client.get.side_effect = Exception("API error")

        with patch("httpx.AsyncClient", return_value=mock_client):
            signals = await client.fetch_cves(keywords=["test"])
            assert signals == []

    @pytest.mark.asyncio
    async def test_fetch_external_empty_on_error(self):
        client = ExternalClient()
        mock_client = _mock_async_client()
        mock_client.get.side_effect = Exception("Connection error")

        with patch("httpx.AsyncClient", return_value=mock_client):
            signals = await client.fetch()
            assert signals == []

    @pytest.mark.asyncio
    async def test_fetch_cves_with_results(self):
        client = ExternalClient()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2025-0001",
                        "descriptions": [{"lang": "en", "value": "Test vuln"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
                            ]
                        },
                    }
                }
            ]
        }

        mock_client = _mock_async_client(get_return=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            signals = await client.fetch_cves(keywords=["test"])
            assert len(signals) == 1
            assert signals[0].source_id == "CVE-2025-0001"

    @pytest.mark.asyncio
    async def test_fetch_cves_with_api_key(self):
        client = ExternalClient(nvd_api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"vulnerabilities": []}
        mock_client = _mock_async_client(get_return=mock_resp)
        with patch("httpx.AsyncClient", return_value=mock_client):
            signals = await client.fetch_cves(keywords=["test"])
            assert signals == []

    def test_cve_to_signal_severity_mapping(self):
        from threatlens.sources.external import _cve_to_signal

        cve = {
            "id": "CVE-2025-1234",
            "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.5, "baseSeverity": "CRITICAL"}}]
            },
        }
        signal = _cve_to_signal(cve)
        assert signal.source_id == "CVE-2025-1234"
        assert signal.severity.value == "critical"
        assert signal.risk_score == 95
        assert "cve" in signal.tags
