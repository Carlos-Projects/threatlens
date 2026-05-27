# ThreatLens

[![Python](https://img.shields.io/badge/python-3.11%20|%203.12%20|%203.13-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/Carlos-Projects/threatlens/actions/workflows/ci.yml/badge.svg)](https://github.com/Carlos-Projects/threatlens/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/threatlens-ai.svg)](https://pypi.org/project/threatlens-ai/)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen.svg)](https://github.com/Carlos-Projects/threatlens)

**ThreatLens** is a threat intelligence aggregation and correlation engine for the **AI/MCP security ecosystem**. It ingests security signals from multiple tools, correlates them across time and attack vectors, enriches with external threat intelligence, and produces actionable alerts and threat reports.

## Ecosystem Integration

| Source | Tool | Signals |
|--------|------|---------|
| MCPGuard | [mcpguard](https://github.com/Carlos-Projects/mcpguard) | Prompt injection, jailbreak, tool poisoning, stegano, anomalies |
| MCPwn | [mcpwn](https://github.com/Carlos-Projects/mcpwn) | Injection tests, fuzzing, SSRF, SQLi, RCE, A2A scanner |
| Palisade Scanner | [palisade-scanner](https://github.com/Carlos-Projects/palisade-scanner) | Hidden text, stego, encoding, exfiltration, instruction classifier |
| AgentGate | [agentgate](https://github.com/Carlos-Projects/agentgate) | AI user agents, request anomalies, honeypot, policy violations |
| Reverse-Abliterate | [reverse-abliterate](https://github.com/Carlos-Projects/reverse-abliterate) | Model safety scans, abliteration detection, weight manifests |
| External | CVEs, MITRE ATLAS, NVD | CVE databases, ATLAS techniques, security advisories |

## Features

- **Signal Aggregation** — Unified ingestion from 5+ security tools
- **TTP Extraction** — Evidence-grounded TTP extraction (arXiv:2605.25836)
- **Threat Correlation** — Cross-source event correlation to identify campaigns
- **External Enrichment** — CVE lookup, MITRE ATLAS mapping, IOC enrichment
- **Alert Generation** — Configurable rules, deduplication, notifications
- **Threat Reports** — Periodic (daily/weekly/monthly) and executive summaries
- **Threat Feed API** — RESTful API for consuming enriched threat intelligence
- **Web Dashboard** — HTMX-powered dashboard with real-time updates
- **MCP Taxonomy** — Canonical classification via [mcp-taxonomy](https://github.com/Carlos-Projects/mcp-taxonomy)

## Installation

```bash
pip install threatlens-ai
```

### From source

```bash
git clone https://github.com/Carlos-Projects/threatlens
cd threatlens
pip install -e ".[dev,web]"
```

## Quick Start

```bash
# Initialize database and config
threatlens init

# Ingest signals from all configured sources
threatlens aggregate

# Run correlation engine
threatlens correlate

# Generate threat report
threatlens report --type daily

# Start the web dashboard
threatlens serve --port 8080

# Consume threat feed
threatlens feed --format json
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `threatlens init` | Initialize database and configuration |
| `threatlens aggregate` | Aggregate signals from all sources |
| `threatlens correlate` | Run correlation engine |
| `threatlens report` | Generate threat reports |
| `threatlens serve` | Start web dashboard |
| `threatlens feed` | Export threat feed |
| `threatlens enrich` | Enrich signals with external sources |
| `threatlens status` | Show system status |

## Architecture

```
┌─────────────┐  ┌──────────┐  ┌────────────────┐
│   MCPGuard   │  │  MCPwn   │  │ Palisade Scan   │
├─────────────┤  ├──────────┤  ├────────────────┤
│  Events API │  │ Findings │  │ Scan Results    │
└──────┬──────┘  └────┬─────┘  └───────┬────────┘
       │              │                │
       ▼              ▼                ▼
┌──────────────────────────────────────────────┐
│               ThreatLens Engine              │
│                                              │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  │
│  │ Aggregate │─▶│ Correlate │─▶│ Enrich   │  │
│  └──────────┘  └───────────┘  └────┬─────┘  │
│                                    │        │
│  ┌──────────┐  ┌───────────┐       │        │
│  │  Alerts  │◀─│  Reports  │◀──────┘        │
│  └──────────┘  └───────────┘                │
└──────────────────────────────────────────────┘
       │              │                │
       ▼              ▼                ▼
┌─────────────┐  ┌──────────┐  ┌────────────────┐
│  Dashboard   │  │ Threat   │  │ Notifications  │
│  (FastAPI)   │  │ Feed API │  │ (Email,TG,WH)  │
└─────────────┘  └──────────┘  └────────────────┘
```

## Configuration

```yaml
# ~/.threatlens/config.yaml
database:
  path: ~/.threatlens/threatlens.db

sources:
  mcpguard:
    enabled: true
    url: http://localhost:8081
  mcpwn:
    enabled: true
    results_dir: ~/.mcpwn/results
  palisade:
    enabled: true
    url: http://localhost:8082
  agentgate:
    enabled: true
    log_path: /var/log/agentgate/access.log
  abliterate:
    enabled: true
    scan_dir: ~/.reverse-abliterate/scans

enrichment:
  cve:
    enabled: true
    nvd_api_key: ""
  atlas:
    enabled: true
  advisories:
    enabled: true

alerts:
  rules:
    - name: critical-rce
      severity: critical
      correlation_min: 2
      notify: [email, telegram]
  notifiers:
    email:
      smtp_host: smtp.gmail.com
      smtp_port: 587
    telegram:
      bot_token: ""
      chat_id: ""

reports:
  schedule:
    daily: true
    weekly: true
    monthly: true
```

## API

Start the server:

```bash
threatlens serve --host 0.0.0.0 --port 8080
```

### REST API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/signals` | List signals (paginated) |
| GET | `/api/v1/signals/{id}` | Get signal details |
| GET | `/api/v1/alerts` | List alerts (paginated) |
| GET | `/api/v1/alerts/{id}` | Get alert details |
| GET | `/api/v1/campaigns` | List detected campaigns |
| GET | `/api/v1/reports` | List generated reports |
| GET | `/api/v1/reports/{id}` | Download report |
| GET | `/api/v1/feed` | Threat feed (STIX/JSON) |
| GET | `/api/v1/stats` | Aggregated statistics |
| POST | `/api/v1/ingest` | Ingest external signals |

## Development

```bash
# Lint
ruff check src/

# Type check
mypy src/

# Test with coverage
python -m pytest tests/ -v --cov=threatlens

# Run all checks
ruff check src/ && python -m pytest tests/ -v --cov=threatlens
```

## Academic References

- **TTPrint** — Evidence-Grounded TTP Extraction via Diverge-then-Converge Verification ([arXiv:2605.25836](https://arxiv.org/abs/2605.25836))
- **CALIBURN** — Regime-Sensitivity Study of Operationally Calibrated Streaming Intrusion Detection ([arXiv:2605.24696](https://arxiv.org/abs/2605.24696))
- **KYA** — Framework-Agnostic Trust Layer for Autonomous Systems ([arXiv:2605.25376](https://arxiv.org/abs/2605.25376))

## License

MIT
