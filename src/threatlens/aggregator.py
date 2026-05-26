"""Core aggregation engine — fetches signals from all configured sources."""

from __future__ import annotations

from typing import Any

from threatlens.database import Database
from threatlens.models import RawSignal, SignalSource
from threatlens.sources import (
    AbliterateClient,
    AgentGateClient,
    ExternalClient,
    MCPGuardClient,
    MCPwnClient,
    PalisadeClient,
    SourceClient,
)


class Aggregator:
    def __init__(self, db: Database, config: dict[str, Any] | None = None) -> None:
        self.db = db
        self.config = config or {}
        self._init_clients()

    def _init_clients(self) -> None:
        sources = self.config.get("sources", {})
        self.clients: dict[SignalSource, SourceClient] = {}

        mcpguard_cfg = sources.get("mcpguard", {})
        if mcpguard_cfg.get("enabled", True):
            self.clients[SignalSource.MCPGUARD] = MCPGuardClient(
                base_url=mcpguard_cfg.get("url", "http://localhost:8081")
            )

        mcpwn_cfg = sources.get("mcpwn", {})
        if mcpwn_cfg.get("enabled", True):
            self.clients[SignalSource.MCPWN] = MCPwnClient(
                results_dir=mcpwn_cfg.get("results_dir", "~/.mcpwn/results")
            )

        palisade_cfg = sources.get("palisade", {})
        if palisade_cfg.get("enabled", True):
            self.clients[SignalSource.PALISADE] = PalisadeClient(
                base_url=palisade_cfg.get("url", "http://localhost:8082")
            )

        agentgate_cfg = sources.get("agentgate", {})
        if agentgate_cfg.get("enabled", True):
            self.clients[SignalSource.AGENTGATE] = AgentGateClient(
                log_path=agentgate_cfg.get("log_path", "/var/log/agentgate/access.log")
            )

        abliterate_cfg = sources.get("abliterate", {})
        if abliterate_cfg.get("enabled", True):
            self.clients[SignalSource.ABLITERATE] = AbliterateClient(
                scan_dir=abliterate_cfg.get("scan_dir", "~/.reverse-abliterate/scans")
            )

        external_cfg = sources.get("external", {})
        if external_cfg.get("enabled", True):
            self.clients[SignalSource.EXTERNAL] = ExternalClient(
                nvd_api_key=external_cfg.get("nvd_api_key", "")
            )

    async def aggregate_all(self, **kwargs: Any) -> list[RawSignal]:
        all_signals: list[RawSignal] = []
        import asyncio

        async def fetch_source(client: SourceClient) -> list[RawSignal]:
            try:
                return await client.fetch(**kwargs)
            except Exception as e:
                print(f"[{client.name}] fetch error: {e}")
                return []

        tasks = [fetch_source(c) for c in self.clients.values()]
        results = await asyncio.gather(*tasks)
        for signals in results:
            all_signals.extend(signals)

        if all_signals:
            saved = self.db.save_signals(all_signals)
            print(f"Aggregated {saved} new signals from {len(self.clients)} sources")
        else:
            print("No new signals found")

        return all_signals
