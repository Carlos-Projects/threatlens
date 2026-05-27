---
layout: default
title: Home
nav_order: 1
---

# ThreatLens

Threat intelligence aggregation and correlation engine for the AI/MCP security ecosystem.

---

## Quick Start

```bash
pip install threatlens-ai
threatlens init
threatlens aggregate
threatlens serve
```

## Features

- **Multi-source ingestion** — MCPGuard, MCPwn, Palisade, AgentGate, Reverse-Abliterate, External (NVD)
- **Cross-source correlation** — category, target, TTP, and temporal burst correlation
- **MITRE ATLAS mapping** — automatic TTP extraction from attack categories
- **Alert generation** — rule-based with deduplication and multi-channel notifications
- **Reporting** — daily, weekly, monthly, and executive summaries
- **Web dashboard** — FastAPI + HTMX with dark theme
- **100% test coverage** — 261 tests across all modules

## Installation

```bash
pip install threatlens-ai
```

Or with development dependencies:

```bash
pip install "threatlens-ai[dev,web]"
```

## Configuration

Configuration is stored at `~/.threatlens/config.yaml` and created automatically on first run:

```bash
threatlens init
```

## Quick Demo

```bash
# Start the web dashboard
threatlens serve

# In another terminal, check system status
threatlens status
```
