"""Tests for AgentGate source client."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from threatlens.sources.agentgate import AgentGateClient


class TestAgentGateClient:
    def test_name(self):
        client = AgentGateClient()
        assert client.name == "agentgate"

    @pytest.mark.asyncio
    async def test_fetch_no_log_file(self):
        client = AgentGateClient(log_path="/tmp/nonexistent_agentgate.log")
        signals = await client.fetch()
        assert signals == []

    @pytest.mark.asyncio
    async def test_fetch_with_log_entries(self):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
        entries = [
            {
                "signal_type": "known_ai_user_agent",
                "weight": 5,
                "action": "block",
                "path": "/api/chat",
                "user_agent": "GPTBot/1.0",
                "score": 80,
            },
            {
                "signal_type": "high_request_rate",
                "weight": 3,
                "action": "challenge",
                "path": "/api/tools",
                "user_agent": "curl/7.0",
                "score": 45,
            },
        ]
        for entry in entries:
            tmp.write(json.dumps(entry) + "\n")
        tmp.close()

        client = AgentGateClient(log_path=tmp.name)
        signals = await client.fetch()

        assert len(signals) == 2
        assert signals[0].source.value == "agentgate"
        assert signals[1].source.value == "agentgate"

        Path(tmp.name).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_fetch_invalid_json_lines(self):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
        tmp.write("not valid json\n")
        tmp.write('{"valid": "json"}\n')
        tmp.close()

        client = AgentGateClient(log_path=tmp.name)
        signals = await client.fetch()

        assert len(signals) == 1
        Path(tmp.name).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_fetch_with_empty_lines(self):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
        tmp.write(
            '{"signal_type": "known_ai_user_agent", "weight": 1, "action": "log", "path": "/test", "score": 10}\n'
        )
        tmp.write("\n")
        tmp.write(
            '{"signal_type": "high_request_rate", "weight": 2, "action": "block", "path": "/api", "score": 50}\n'
        )
        tmp.close()
        client = AgentGateClient(log_path=tmp.name)
        signals = await client.fetch()
        assert len(signals) == 2
        Path(tmp.name).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_fetch_access_denied(self):
        import os

        saved = os.environ.get("PYTEST_CURRENT_TEST")
        os.environ.pop("PYTEST_CURRENT_TEST", None)
        try:
            client = AgentGateClient(log_path="/etc/passwd")
            signals = await client.fetch()
            assert signals == []
        finally:
            if saved:
                os.environ["PYTEST_CURRENT_TEST"] = saved
