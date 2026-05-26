"""Tests for the aggregation engine."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from threatlens.aggregator import Aggregator
from threatlens.database import Database
from threatlens.models import RawSignal, Severity, SignalSource
from mcp_taxonomy import AttackCategory, Confidence


@pytest.fixture
def db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    database = Database(db_path=tmp.name)
    database.initialize()
    tmp.close()
    yield database
    database.close()
    Path(tmp.name).unlink(missing_ok=True)


def _mock_signal(source: SignalSource, sid: str) -> RawSignal:
    return RawSignal(
        source=source,
        source_id=sid,
        category=AttackCategory.INJECTION,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title=f"Signal from {source.value}",
    )


class TestAggregator:
    def test_init_with_defaults(self, db):
        agg = Aggregator(db)
        assert agg.db is db
        assert len(agg.clients) > 0

    def test_init_with_config_disabling_all(self, db):
        config = {
            "sources": {
                "mcpguard": {"enabled": False},
                "mcpwn": {"enabled": False},
                "palisade": {"enabled": False},
                "agentgate": {"enabled": False},
                "abliterate": {"enabled": False},
                "external": {"enabled": False},
            }
        }
        agg = Aggregator(db, config)
        assert len(agg.clients) == 0

    @pytest.mark.asyncio
    async def test_aggregate_all_no_clients(self, db):
        config = {
            "sources": {
                src: {"enabled": False}
                for src in ["mcpguard", "mcpwn", "palisade", "agentgate", "abliterate", "external"]
            }
        }
        agg = Aggregator(db, config)
        signals = await agg.aggregate_all()
        assert signals == []

    @pytest.mark.asyncio
    async def test_aggregate_all_empty_clients(self, db):
        with patch.object(Aggregator, "_init_clients") as mock_init:
            agg = Aggregator(db)
            agg.clients = {}
            signals = await agg.aggregate_all()
            assert signals == []

    @pytest.mark.asyncio
    async def test_aggregate_all_multiple_sources(self, db):
        agg = Aggregator(db)

        mcpguard_mock = AsyncMock()
        mcpguard_mock.name = "mcpguard"
        mcpguard_mock.fetch.return_value = [_mock_signal(SignalSource.MCPGUARD, "a1")]

        mcpwn_mock = AsyncMock()
        mcpwn_mock.name = "mcpwn"
        mcpwn_mock.fetch.return_value = [
            _mock_signal(SignalSource.MCPWN, "b1"),
            _mock_signal(SignalSource.MCPWN, "b2"),
        ]

        agg.clients = {
            SignalSource.MCPGUARD: mcpguard_mock,
            SignalSource.MCPWN: mcpwn_mock,
        }

        signals = await agg.aggregate_all()
        assert len(signals) == 3

    @pytest.mark.asyncio
    async def test_aggregate_all_one_source_fails(self, db):
        agg = Aggregator(db)

        good_mock = AsyncMock()
        good_mock.name = "good"
        good_mock.fetch.return_value = [_mock_signal(SignalSource.MCPGUARD, "g1")]

        bad_mock = AsyncMock()
        bad_mock.name = "bad"
        bad_mock.fetch.side_effect = Exception("Connection refused")

        agg.clients = {
            SignalSource.MCPGUARD: good_mock,
            SignalSource.MCPWN: bad_mock,
        }

        signals = await agg.aggregate_all()
        assert len(signals) == 1

    @pytest.mark.asyncio
    async def test_aggregate_all_saves_to_db(self, db):
        agg = Aggregator(db)

        mock_client = AsyncMock()
        mock_client.name = "test"
        mock_client.fetch.return_value = [_mock_signal(SignalSource.MCPGUARD, "saved1")]

        agg.clients = {SignalSource.MCPGUARD: mock_client}

        signals = await agg.aggregate_all()
        assert len(signals) == 1
        results = db.get_signals(limit=10)
        assert any(r["source_id"] == "saved1" for r in results)
