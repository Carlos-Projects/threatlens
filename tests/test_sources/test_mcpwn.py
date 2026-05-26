"""Tests for MCPwn source client."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from threatlens.sources.mcpwn import MCPwnClient


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
