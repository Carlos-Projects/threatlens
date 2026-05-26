# Changelog

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
