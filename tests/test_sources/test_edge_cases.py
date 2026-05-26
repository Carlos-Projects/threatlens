"""Edge case tests for source clients."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from threatlens.models import RawSignal, SignalSource
from threatlens.sources.abliterate import AbliterateClient, _abliterate_to_taxonomy
from threatlens.sources.agentgate import AgentGateClient
from threatlens.sources.base import SourceClient
from threatlens.sources.external import ExternalClient, _cve_to_signal
from threatlens.sources.mcpguard import MCPGuardClient
from threatlens.sources.mcpwn import MCPwnClient
from threatlens.sources.palisade import PalisadeClient


def _mock_async_client(get_return: MagicMock | None = None) -> AsyncMock:
    mock_client = AsyncMock()
    if get_return:
        mock_client.get.return_value = get_return
    mock_client.__aenter__.return_value = mock_client
    return mock_client


class TestSourceClientBase:
    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            SourceClient()  # type: ignore


class TestMCPGuardEdgeCases:
    @pytest.mark.asyncio
    async def test_fetch_empty_event_list(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = []

        client = MCPGuardClient()
        with patch("httpx.AsyncClient", return_value=_mock_async_client(get_return=mock_resp)):
            signals = await client.fetch()
            assert signals == []

    @pytest.mark.asyncio
    async def test_fetch_partial_event_data(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"event_type": "unknown_type", "severity": "info", "message": "test"}
        ]

        client = MCPGuardClient()
        with patch("httpx.AsyncClient", return_value=_mock_async_client(get_return=mock_resp)):
            signals = await client.fetch()
            assert len(signals) == 1


class TestMCPwnEdgeCases:
    @pytest.mark.asyncio
    async def test_empty_json_file(self):
        tmp = tempfile.mkdtemp()
        Path(tmp, "empty.json").write_text("[]")
        client = MCPwnClient(results_dir=tmp)
        signals = await client.fetch()
        assert signals == []

    @pytest.mark.asyncio
    async def test_malformed_json_file(self):
        tmp = tempfile.mkdtemp()
        Path(tmp, "bad.json").write_text("{invalid")
        client = MCPwnClient(results_dir=tmp)
        signals = await client.fetch()
        assert signals == []


class TestPalisadeEdgeCases:
    @pytest.mark.asyncio
    async def test_no_findings_key(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{"url": "http://test", "no_findings": True}]

        client = PalisadeClient()
        with patch("httpx.AsyncClient", return_value=_mock_async_client(get_return=mock_resp)):
            signals = await client.fetch()
            assert len(signals) == 1
            assert signals[0].target == "http://test"


class TestExternalEdgeCases:
    def test_cve_missing_fields(self):
        signal = _cve_to_signal({"id": "CVE-2025-TEST"})
        assert signal.source_id == "CVE-2025-TEST"
        assert signal.severity.value == "medium"
        assert signal.description == ""

    def test_cve_high_severity(self):
        cve = {
            "id": "CVE-2025-0001",
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 8.5, "baseSeverity": "HIGH"}}]
            },
        }
        signal = _cve_to_signal(cve)
        assert signal.severity.value == "high"
        assert 80 <= signal.risk_score <= 85

    def test_cve_no_english_description(self):
        cve = {
            "id": "CVE-2025-0001",
            "descriptions": [{"lang": "fr", "value": "Description française"}],
        }
        signal = _cve_to_signal(cve)
        assert signal.description == ""

    def test_cve_rce_weakness_maps_to_rce(self):
        from threatlens.sources.external import _cve_to_signal, _infer_category_from_cwe

        cve = {
            "id": "CVE-2025-RCE",
            "weaknesses": [{"description": [{"value": "CWE-94"}]}],
            "descriptions": [{"lang": "en", "value": "Remote code execution vulnerability"}],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
            },
        }
        inferred = _infer_category_from_cwe(cve)
        assert inferred is not None and inferred.value == "rce"
        signal = _cve_to_signal(cve)
        assert signal.category.value == "rce"

    def test_cve_ssrf_keyword_maps_to_ssrf(self):
        from threatlens.sources.external import _infer_category_from_text

        cat = _infer_category_from_text("Server-Side Request Forgery in webhook endpoint")
        assert cat is not None and cat.value == "ssrf"

    def test_cve_sqli_keyword_maps_to_sqli(self):
        from threatlens.sources.external import _infer_category_from_text

        cat = _infer_category_from_text("SQL Injection vulnerability in input parser")
        assert cat is not None and cat.value == "sql_injection"

    def test_cve_empty_text_returns_none(self):
        from threatlens.sources.external import _infer_category_from_text

        assert _infer_category_from_text("") is None

    def test_cve_unrecognized_text_fallback(self):
        from threatlens.sources.external import _cve_to_signal

        signal = _cve_to_signal(
            {"id": "CVE-2025-UNK", "descriptions": [{"lang": "en", "value": "Something unknown"}]}
        )
        assert signal.category.value == "malware"
        assert signal.severity.value == "medium"


class TestAbliterateEdgeCases:
    def test_abliterate_empty_scan(self):
        scan = {"title": "Empty scan", "risk_score": 0}
        tax = _abliterate_to_taxonomy(scan)
        assert tax.attack_category.value == "misconfiguration"

    def test_abliterate_high_risk_scan(self):
        scan = {
            "title": "Dangerous scan",
            "anomalies": ["abliteration_detected"],
            "safety_violations": ["refusal_override"],
            "risk_score": 90,
        }
        tax = _abliterate_to_taxonomy(scan)
        assert tax.attack_category.value == "tool_poisoning"
        assert tax.risk_score >= 60
