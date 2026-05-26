"""Tests for Reverse-Abliterate source client."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from threatlens.sources.abliterate import AbliterateClient


class TestAbliterateClient:
    def test_name(self):
        client = AbliterateClient()
        assert client.name == "abliterate"

    @pytest.mark.asyncio
    async def test_fetch_no_directory(self):
        client = AbliterateClient(scan_dir="/tmp/nonexistent_abl_dir")
        signals = await client.fetch()
        assert signals == []

    @pytest.mark.asyncio
    async def test_fetch_with_scans(self):
        tmp = tempfile.mkdtemp()
        scan = {
            "title": "Model Safety Scan",
            "description": "Scan of llama-3-70b",
            "anomalies": ["abliteration_detected"],
            "risk_score": 75,
            "model_path": "/models/llama-3-70b",
            "safety_violations": ["refusal_override"],
        }
        scan_file = Path(tmp) / "scan_001.json"
        scan_file.write_text(json.dumps(scan))

        client = AbliterateClient(scan_dir=tmp)
        signals = await client.fetch()

        assert len(signals) == 1
        assert signals[0].source.value == "abliterate"
        assert "model-scan" in signals[0].tags
        assert signals[0].risk_score >= 60

    @pytest.mark.asyncio
    async def test_fetch_with_clean_scan(self):
        tmp = tempfile.mkdtemp()
        scan = {
            "title": "Clean Model Scan",
            "model_path": "/models/safe-model",
            "risk_score": 10,
        }
        Path(tmp, "clean_scan.json").write_text(json.dumps(scan))

        client = AbliterateClient(scan_dir=tmp)
        signals = await client.fetch()
        assert len(signals) == 1
        assert signals[0].category.value == "misconfiguration"
