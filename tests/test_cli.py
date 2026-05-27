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

    def test_report_daily_with_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            config = {"database": {"path": str(db_path)}}
            from threatlens.database import Database

            db = Database(db_path=str(db_path))
            db.initialize()
            from threatlens.models import RawSignal, Severity, SignalSource
            from mcp_taxonomy import AttackCategory, Confidence

            db.save_signals(
                [
                    RawSignal(
                        source=SignalSource.MCPGUARD,
                        source_id="rep-sig-1",
                        category=AttackCategory.INJECTION,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        title="Report test signal",
                    ),
                ]
            )
            db.close()
            with patch("threatlens.cli._load_config", return_value=config):
                result = runner.invoke(app, ["report", "--report-type", "daily"])
            assert result.exit_code == 0
            assert "Signals:" in result.output or "Report:" in result.output

    def test_report_daily_no_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            config = {"database": {"path": str(db_path)}}
            with patch("threatlens.cli._load_config", return_value=config):
                result = runner.invoke(app, ["report", "--report-type", "daily"])
            assert result.exit_code == 0

    def test_report_executive_no_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            config = {"database": {"path": str(db_path)}}
            with patch("threatlens.cli._load_config", return_value=config):
                result = runner.invoke(app, ["report", "--report-type", "executive"])
            assert result.exit_code == 0

    def test_report_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            output_path = Path(tmp) / "report.json"
            config = {"database": {"path": str(db_path)}}
            with patch("threatlens.cli._load_config", return_value=config):
                result = runner.invoke(
                    app,
                    [
                        "report",
                        "--report-type",
                        "weekly",
                        "--output",
                        str(output_path),
                    ],
                )
            assert result.exit_code == 0
            assert output_path.exists()

    def test_feed_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            output_path = Path(tmp) / "feed.json"
            config = {"database": {"path": str(db_path)}}
            with patch("threatlens.cli._load_config", return_value=config):
                result = runner.invoke(
                    app,
                    [
                        "feed",
                        "--limit",
                        "5",
                        "--output",
                        str(output_path),
                    ],
                )
            assert result.exit_code == 0
            assert output_path.exists()

    def test_enrich_no_cves(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            config = {"database": {"path": str(db_path)}}
            with patch("threatlens.cli._load_config", return_value=config):
                result = runner.invoke(app, ["enrich"])
            assert result.exit_code == 0

    def test_enrich_with_cve_references(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            config = {
                "database": {"path": str(db_path)},
                "enrichment": {"cve": {"enabled": True, "nvd_api_key": ""}},
            }
            from threatlens.database import Database

            db = Database(db_path=str(db_path))
            db.initialize()
            from threatlens.models import RawSignal, Severity, SignalSource
            from mcp_taxonomy import AttackCategory, Confidence

            db.save_signals(
                [
                    RawSignal(
                        source=SignalSource.MCPGUARD,
                        source_id="cve-sig-1",
                        category=AttackCategory.INJECTION,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        title="Signal with CVE-2024-0001",
                        description="Reference to CVE-2024-0001 found in logs",
                    ),
                ]
            )
            db.close()
            with patch("threatlens.cli._load_config", return_value=config):
                result = runner.invoke(app, ["enrich"])
            assert result.exit_code == 0

    def test_serve_mocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            config = {"database": {"path": str(db_path)}}
            with (
                patch("threatlens.cli._load_config", return_value=config),
                patch("uvicorn.run") as mock_uvicorn,
            ):
                result = runner.invoke(app, ["serve", "--host", "0.0.0.0", "--port", "9090"])
            assert result.exit_code == 0
            mock_uvicorn.assert_called_once()
            args = mock_uvicorn.call_args[1]
            assert args["host"] == "0.0.0.0"
            assert args["port"] == 9090

    def test_correlate_with_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            config = {"database": {"path": str(db_path)}}
            from threatlens.database import Database

            db = Database(db_path=str(db_path))
            db.initialize()
            from threatlens.models import RawSignal, Severity, SignalSource
            from mcp_taxonomy import AttackCategory, Confidence

            db.save_signals(
                [
                    RawSignal(
                        source=SignalSource.MCPGUARD,
                        source_id="corr-sig-1",
                        category=AttackCategory.INJECTION,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        title="First injection signal",
                    ),
                    RawSignal(
                        source=SignalSource.MCPWN,
                        source_id="corr-sig-2",
                        category=AttackCategory.INJECTION,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        title="Second injection signal",
                    ),
                ]
            )
            db.close()
            with patch("threatlens.cli._load_config", return_value=config):
                result = runner.invoke(app, ["correlate"])
            assert result.exit_code == 0
            assert "Correlated Events" in result.output
            assert "Alerts Generated" in result.output
            assert "Campaigns Detected" in result.output
            assert "Unique TTPs" in result.output

    def test_correlate_with_alerts_and_campaigns(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            config = {"database": {"path": str(db_path)}}
            from threatlens.database import Database

            db = Database(db_path=str(db_path))
            db.initialize()
            from threatlens.models import RawSignal, Severity, SignalSource
            from mcp_taxonomy import AttackCategory, Confidence

            signals = [
                RawSignal(
                    source=SignalSource.MCPGUARD,
                    source_id=f"camp-sig-{i}",
                    category=AttackCategory.RCE,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CERTAIN,
                    title=f"RCE signal {i}",
                )
                for i in range(5)
            ]
            db.save_signals(signals)
            db.close()
            with patch("threatlens.cli._load_config", return_value=config):
                result = runner.invoke(app, ["correlate"])
            assert result.exit_code == 0
            assert "Alerts:" in result.output or "Campaigns:" in result.output
