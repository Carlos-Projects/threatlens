"""
ThreatLens — Threat intelligence aggregation and correlation engine for AI/MCP security.

Aggregates security signals from MCPGuard, mcpwn, palisade-scanner, agentgate,
and reverse-abliterate; correlates across time and attack vectors; enriches with
external threat intelligence (CVEs, MITRE ATLAS, advisories); and produces
actionable alerts and threat reports.
"""

from threatlens._version import __version__

__all__ = ["__version__"]
