"""Tests for CLI commands."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from threatlens.cli import app

runner = CliRunner()


def test_version():
    from threatlens import __version__

    assert __version__ == "0.1.0"


class TestCLI:
    def test_help_shows_commands(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "aggregate" in result.output
        assert "correlate" in result.output
        assert "report" in result.output
        assert "serve" in result.output
        assert "feed" in result.output
        assert "init" in result.output

    def test_init_creates_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp) / ".threatlens"
            config_path = config_dir / "config.yaml"

            with patch("threatlens.cli.CONFIG_PATH", config_path):
                result = runner.invoke(app, ["init"])

            assert result.exit_code == 0
            assert config_path.exists()
            content = config_path.read_text()
            assert "mcpguard" in content
            assert "database" in content

    def test_status_without_init(self):
        with patch("threatlens.cli.CONFIG_PATH", Path("/tmp/nonexistent_config.yaml")):
            result = runner.invoke(app, ["status"])
            assert result.exit_code == 0
            assert "Config" in result.output or "Status" in result.output

    def test_feed_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            config = {"database": {"path": str(db_path)}}
            with patch("threatlens.cli._load_config", return_value=config):
                result = runner.invoke(app, ["feed", "--limit", "5"])
            assert result.exit_code == 0
            assert (
                "feed_version" in result.output
                or "signals" in result.output
                or "ThreatLens" in result.output
            )

    def test_aggregate_no_config(self):
        with patch("threatlens.cli.CONFIG_PATH", Path("/tmp/nonexistent_config.yaml")):
            result = runner.invoke(app, ["aggregate", "--limit", "5"])
            assert result.exit_code == 0

    def test_correlate_no_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            config = {"database": {"path": str(db_path)}}
            with patch("threatlens.cli._load_config", return_value=config):
                result = runner.invoke(app, ["correlate"])
            assert result.exit_code == 0
