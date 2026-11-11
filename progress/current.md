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

## Recent Changes

- 2026-11-11: Cursor-based pagination for the signals (threats) API, issue #6.
  `GET /api/v1/signals` accepts an optional `cursor` param (`cursor=0` = first
  page) and then returns `{"signals": [...], "next_cursor": <id|null>}`;
  keyset pagination in `Database.get_signals` (stable `id DESC` ordering).
  Without `cursor`, the existing limit/offset list response is unchanged.
  Verified: 3 new tests in `tests/test_web_server.py`
  (`TestSignalsCursorPagination`) pass; full suite 264 passed with 1
  pre-existing, network-dependent failure
  (`test_cli.py::TestCLI::test_enrich_with_cve_references`, fails on clean
  master too).
