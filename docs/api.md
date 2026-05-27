---
layout: default
title: API
nav_order: 3
---

# REST API

All API endpoints are prefixed with `/api/v1/`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/signals` | List signals (paginated) |
| GET | `/signals/{id}` | Get signal details |
| GET | `/alerts` | List alerts (paginated) |
| GET | `/alerts/{id}` | Get alert details |
| GET | `/campaigns` | List detected campaigns |
| GET | `/reports` | List generated reports |
| GET | `/reports/{id}` | Download report |
| GET | `/feed` | Threat feed (STIX/JSON) |
| GET | `/stats` | Aggregated statistics |
| POST | `/ingest` | Ingest external signals |

## Authentication

If configured, API requests require either:

- `Authorization: Bearer <api-key>` header
- `X-API-Key: <api-key>` header
- `token=<api-key>` cookie (for browser access)

## Dashboard Pages

| Path | Description |
|------|-------------|
| `/` | Dashboard overview |
| `/signals` | Browse signals with filters |
| `/alerts` | View and manage alerts |
