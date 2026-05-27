"""Tests for MCPwn source client."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from threatlens.sources.mcpwn import MCPwnClient, _validate_source_path


class TestMCPwnClient:
    def test_name(self):
        client = MCPwnClient()
        assert client.name == "mcpwn"

    @pytest.mark.asyncio
    async def test_fetch_no_directory(self):
        client = MCPwnClient(results_dir="/tmp/nonexistent_dir_xyz")
        signals = await client.fetch()
        assert signals == []

    @pytest.mark.asyncio
    async def test_fetch_with_results(self):
        tmp = tempfile.mkdtemp()
        results = [
            {
                "attack_type": "command_injection",
                "severity": "critical",
                "title": "RCE via command injection",
                "description": "Test finding",
                "target": "http://target/api",
            }
        ]
        result_file = Path(tmp) / "test_result.json"
        result_file.write_text(json.dumps(results))

        client = MCPwnClient(results_dir=tmp)
        signals = await client.fetch()
        assert len(signals) == 1
        assert signals[0].source.value == "mcpwn"
        assert signals[0].source_id.startswith("mcpwn-")

    @pytest.mark.asyncio
    async def test_fetch_with_single_finding(self):
        tmp = tempfile.mkdtemp()
        result = {
            "attack_type": "jailbreak",
            "severity": "high",
            "title": "Jailbreak attempt",
            "target": "http://target/api",
        }
        result_file = Path(tmp) / "single.json"
        result_file.write_text(json.dumps(result))

        client = MCPwnClient(results_dir=tmp)
        signals = await client.fetch()
        assert len(signals) == 1
        assert signals[0].source_id.startswith("mcpwn-")

    @pytest.mark.asyncio
    async def test_fetch_with_invalid_json(self):
        tmp = tempfile.mkdtemp()
        result_file = Path(tmp) / "bad.json"
        result_file.write_text("not valid json")

        client = MCPwnClient(results_dir=tmp)
        signals = await client.fetch()
        assert signals == []

    @pytest.mark.asyncio
    async def test_fetch_access_denied(self):
        saved = os.environ.get("PYTEST_CURRENT_TEST")
        os.environ.pop("PYTEST_CURRENT_TEST", None)
        try:
            client = MCPwnClient(results_dir="/etc")
            signals = await client.fetch()
            assert signals == []
        finally:
            if saved:
                os.environ["PYTEST_CURRENT_TEST"] = saved


class TestValidateSourcePath:
    def test_allowed_path(self):
        allowed = Path(tempfile.mkdtemp())
        assert _validate_source_path(allowed) is True

    def test_denied_path(self):
        saved = os.environ.get("PYTEST_CURRENT_TEST")
        os.environ.pop("PYTEST_CURRENT_TEST", None)
        try:
            result = _validate_source_path(Path("/etc"))
            assert result is False
        finally:
            if saved:
                os.environ["PYTEST_CURRENT_TEST"] = saved
