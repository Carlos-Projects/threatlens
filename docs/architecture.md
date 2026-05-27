---
layout: default
title: Architecture
nav_order: 4
---

# Architecture

## Data Flow

```
Sources ──► Aggregation ──► Correlation ──► Enrichment ──► Alerts ──► Reports
   │            │               │               │              │            │
   ▼            ▼               ▼               ▼              ▼            ▼
 MCPGuard    Batch fetch    Category       CVE lookup      Rules        Daily
 MCPwn       Dedup          Target         ATLAS map       Dedup        Weekly
 Palisade    DB store       TTP            Advisory fetch  Notify       Monthly
 AgentGate                  Temporal                                        Executive
 Abliterate                 Campaigns
 External
```

## Source Clients

Each source implements the `SourceClient` interface:

```
SourceClient
├── MCPGuardClient    — API polling
├── MCPwnClient       — File reading (~/.mcpwn/results)
├── PalisadeClient    — API polling
├── AgentGateClient   — Log file parsing
├── AbliterateClient  — Scan directory reading
└── ExternalClient    — NVD API for CVEs
```

## Database Schema

- **signals** — Raw threat signals with source, category, severity, confidence
- **correlated_events** — Cross-source correlation results
- **alerts** — Generated alerts with severity and notification status
- **campaigns** — Detected threat campaigns
- **reports** — Generated threat reports
