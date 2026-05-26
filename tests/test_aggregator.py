"""Tests for the aggregation engine."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

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
