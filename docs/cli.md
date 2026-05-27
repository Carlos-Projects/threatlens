---
layout: default
title: CLI Reference
nav_order: 2
---

# CLI Reference

| Command | Description |
|---------|-------------|
| `threatlens init` | Initialize database and default configuration |
| `threatlens aggregate` | Fetch and aggregate signals from all configured sources |
| `threatlens correlate` | Run the correlation engine on aggregated signals |
| `threatlens report` | Generate threat reports (daily, weekly, monthly, executive) |
| `threatlens serve` | Start the web dashboard |
| `threatlens feed` | Export threat feed in STIX-compatible format |
| `threatlens enrich` | Enrich signals with external threat intelligence |
| `threatlens status` | Show system status and statistics |

## Options

### `threatlens aggregate`

| Flag | Default | Description |
|------|---------|-------------|
| `--limit` | `100` | Max signals per source |

### `threatlens report`

| Flag | Default | Description |
|------|---------|-------------|
| `--report-type` | `daily` | Type: daily, weekly, monthly, executive |
| `--output` | `None` | File path to save report as JSON |

### `threatlens serve`

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `127.0.0.1` | Bind address |
| `--port` | `8080` | Port number |

### `threatlens feed`

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `json` | Output format |
| `--source` | `None` | Filter by source |
| `--severity` | `None` | Filter by severity |
| `--limit` | `100` | Max signals to export |
| `--output` | `None` | File path to save feed as JSON |
