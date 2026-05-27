---
layout: default
title: Development
nav_order: 5
---

# Development

## Setup

```bash
git clone https://github.com/Carlos-Projects/threatlens
cd threatlens
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,web]"
```

## Commands

```bash
# Lint
ruff check src/

# Type check
mypy src/

# Test with coverage
python -m pytest tests/ --cov=threatlens --cov-report=term

# Run all checks
make check
```

## Architecture Guidelines

- Type hints required for all code
- Docstrings on all public functions and classes
- Follow existing patterns in `src/threatlens/`
- Tests required for new features
- Coverage must stay at 100%

## Project Structure

```
threatlens/
├── alerts/          — Alert generation, deduplication, notification
├── correlation/     — Cross-source correlation, TTP extraction, campaigns
├── enrichment/      — CVE lookup, ATLAS mapping, advisory fetch
├── reports/         — Report generation (periodic, executive)
├── sources/         — Source clients (MCPGuard, MCPwn, Palisade, etc.)
├── utils/           — Crypto utilities
├── web/             — FastAPI server, auth middleware
├── cli.py           — Typer CLI entry point
├── database.py      — SQLite database layer
└── models.py        — Data models and enums
```
