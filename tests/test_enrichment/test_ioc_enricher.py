"""Tests for IOC enricher — includes enrich_ip tests."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from threatlens.enrichment.ioc_enricher import IOCEnricher


class TestIOCEnricher:
    def setup_method(self):
        self.enricher = IOCEnricher()

    def test_extract_ipv4(self):
        iocs = self.enricher.extract_iocs("Connection from 192.168.1.1")
        assert "ipv4" in iocs

    def test_extract_domain(self):
        iocs = self.enricher.extract_iocs("malicious.example.com")
        assert "domain" in iocs

    def test_extract_url(self):
        iocs = self.enricher.extract_iocs("POST https://evil.com/payload")
        assert "url" in iocs

    def test_extract_cve(self):
        iocs = self.enricher.extract_iocs("CVE-2025-1234")
        assert "cve" in iocs

    def test_extract_hash(self):
        sha256 = "a" * 64
        iocs = self.enricher.extract_iocs(f"hash {sha256}")
        assert "hash_sha256" in iocs

    def test_extract_email(self):
        iocs = self.enricher.extract_iocs("contact attacker@evil.com")
        assert "email" in iocs

    def test_extract_mixed(self):
        text = "Attack from 10.0.0.1 using CVE-2025-5678 at bad.example.com"
        iocs = self.enricher.extract_iocs(text)
        assert len(iocs) >= 2

    def test_empty_text_returns_empty(self):
        assert self.enricher.extract_iocs("") == {}

    def test_invalid_ip_excluded(self):
        iocs = self.enricher.extract_iocs("999.999.999.999")
        assert "ipv4" not in iocs

    def test_is_valid_ip(self):
        assert self.enricher._is_valid_ip("192.168.1.1") is True
        assert self.enricher._is_valid_ip("256.1.1.1") is False
        assert self.enricher._is_valid_ip("not.an.ip") is False

    @pytest.mark.asyncio
    async def test_enrich_ip_network_error(self):
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            mock_client.__aenter__.return_value = mock_client
            mock_client.get.side_effect = Exception("API error")
            result = await self.enricher.enrich_ip("8.8.8.8")
            assert result["ip"] == "8.8.8.8"
            assert "error" in result

    @pytest.mark.asyncio
    async def test_enrich_ip_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 85,
                "countryCode": "US",
                "isp": "Google LLC",
                "domain": "google.com",
                "totalReports": 42,
                "lastReportedAt": "2025-01-01T00:00:00Z",
            }
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            mock_client.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp
            result = await self.enricher.enrich_ip("8.8.8.8")
            assert result["ip"] == "8.8.8.8"
            assert result["abuse_confidence_score"] == 85
            assert result["isp"] == "Google LLC"
