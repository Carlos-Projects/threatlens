# ThreatLens Documentation

## Overview

ThreatLens is a threat intelligence aggregation and correlation engine for the AI/MCP security ecosystem.

## Architecture

- **Sources**: MCPGuard, MCPwn, Palisade, AgentGate, Reverse-Abliterate, External (NVD/OSV)
- **Correlation**: Category, target, TTP, and temporal burst correlation
- **Enrichment**: CVE lookup, MITRE ATLAS mapping, advisory fetch
- **Alerts**: Rule-based alert generation with deduplication
- **Reports**: Daily, weekly, monthly, and executive threat reports
- **Web Dashboard**: FastAPI-based UI with auth, HTTPS, rate limiting

## CLI Reference

| Command | Description |
|---------|-------------|
| `threatlens init` | Initialize database and config |
| `threatlens aggregate` | Fetch signals from all sources |
| `threatlens correlate` | Run correlation engine |
| `threatlens report` | Generate threat reports |
| `threatlens serve` | Start web dashboard |
| `threatlens feed` | Export STIX-compatible feed |
| `threatlens enrich` | Enrich signals with external intel |
| `threatlens status` | Show system status |

## Development

See [CONTRIBUTING.md](../CONTRIBUTING.md).
