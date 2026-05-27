# Changelog

## 0.2.0 (2026-05-26)

### Added
- Authentication middleware (API key, cookie, header) with rate limiting
- HTTPS redirect middleware with configurable `force_https`
- Environment variable cache for config loading
- Web dashboard pages: signals list with filters, alerts list, pagination UI
- Integration test suite with end-to-end FastAPI flows
- Campaign detection engine
- Temporal burst analysis
- Executive report generator (management summaries)
- Alert deduplication and notifier system (Telegram, webhook)
- STIX-compatible threat feed export (`threatlens feed`)
- Enrichment commands in CLI (`threatlens enrich`)
- Issue templates (bug report, feature request) and PR template
- SECURITY.md with disclosure policy
- pre-commit config for code quality
- `threatlens status` command showing system metrics
- `docs/` folder with basic documentation
- Makefile for common development tasks

### Changed
- Coverage: 91% → 100% (261 tests, 0 uncovered statements)
- Security: fixed all 12 findings from security audit (HMAC timing, path traversal, audit logging)
- CI: pip-audit changed from non-blocking to blocking
- Docker healthcheck now follows redirects (`curl -fL`)
- CLI: `report` command supports `--output` for file export
- CLI: `feed` command supports `--output`, `--source`, `--severity` filters
- CLI: `serve` command supports custom `--host`/`--port`
- Dependency bumps: fastapi~=0.136.3, httpx~=0.28.1, pydantic~=2.13.4, jinja2~=3.1.6, pyyaml~=6.0.3
- README badges updated (Python 3.11|3.12|3.13, coverage 100%)
- Database: `__del__` added to prevent resource warnings

### Fixed
- Placeholder TTP ID `AML.TXXXX` replaced with proper constant `AML.T0000`
- CONTRIBUTING.md broken reference to `.opencode/` removed
- CVE severity mapping to threat categories
- Category inference from CWE and text descriptions
- Alert pipeline integration in `correlate` command

## 0.1.0 (2026-05-26)

Initial release of ThreatLens — threat intelligence aggregation and correlation engine for AI/MCP security.

### Added
- CLI with commands: `init`, `aggregate`, `correlate`, `report`, `serve`, `feed`, `enrich`, `status`
- Aggregation engine with 6 source clients: MCPGuard, MCPwn, Palisade Scanner, AgentGate, Reverse-Abliterate, External (NVD)
- Correlation engine: cross-source event correlation, TTP extraction (MITRE ATLAS), campaign detection, temporal burst analysis
- Enrichment modules: CVE lookup (NVD), MITRE ATLAS mapping, advisory fetching, IOC extraction and enrichment
- Alert system: rule-based generation (7 rules), deduplication, Telegram and webhook notifications
- Report system: daily/weekly/monthly periodic reports, executive summaries
- Web dashboard: FastAPI + HTMX + DaisyUI dark theme, REST API
- SQLite database with 5 tables and indexes
- 180+ tests with 91% coverage
- CI/CD: GitHub Actions (lint, test, typecheck on 3.11/3.12/3.13), PyPI publishing
- Dockerfile + docker-compose.yml for containerized deployment
- Cryptographic utilities: API key generation, HMAC signing, IP anonymization
- Integration with mcp-taxonomy for canonical classification
