# Current State

Status: active
Last updated: 2026-05-29

## Current Goal

Install the shared Codex/OpenCode harness and connect ThreatLens to the security-signal correlation role in the ecosystem.

## Known Good Commands

- setup: `pip install -e ".[dev,web]"`
- test: `python -m pytest tests/ -v`
- lint: `ruff check src/`
- typecheck: `mypy src/`
- build: `hatch build`

## Open Risks

- Avoid treating correlated signals as verified incidents without source evidence.
- Preserve provenance from MCPGuard, AgentGate, MCPwn, Palisade, and external threat feeds.
- Do not commit local caches, API keys, or generated dashboards.

## Next Step

- Add harness audit-event ingestion contract and verify it against MCPGuard/AgentGate sample events.
