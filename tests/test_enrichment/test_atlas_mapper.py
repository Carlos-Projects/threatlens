"""Tests for MITRE ATLAS mapper."""

from __future__ import annotations

import pytest

from threatlens.enrichment.atlas_mapper import AtlasMapper, ATLAS_TECHNIQUES
from mcp_taxonomy import AttackCategory


class TestAtlasMapper:
    def setup_method(self):
        self.mapper = AtlasMapper()

    def test_map_injection(self):
        techniques = self.mapper.map_category(AttackCategory.INJECTION)
        assert len(techniques) == 2
        assert techniques[0]["id"] == "AML.T0051"

    def test_map_rce(self):
        techniques = self.mapper.map_category(AttackCategory.RCE)
        assert any(t["id"] == "AML.T0059" for t in techniques)

    def test_map_unknown_category(self):
        techniques = self.mapper.map_category(AttackCategory.HOMOGLYPH)
        assert techniques == []

    def test_get_technique_exists(self):
        tech = self.mapper.get_technique("AML.T0051")
        assert tech is not None
        assert tech["name"] == "LLM Prompt Injection"

    def test_get_technique_not_found(self):
        tech = self.mapper.get_technique("AML.T9999")
        assert tech is None

    def test_search(self):
        results = self.mapper.search("injection")
        assert len(results) >= 1
        assert any("injection" in r["name"].lower() for r in results)

    def test_search_empty_query(self):
        results = self.mapper.search("")
        assert len(results) == len(ATLAS_TECHNIQUES)

    def test_atlas_techniques_have_all_fields(self):
        for tid, tech in ATLAS_TECHNIQUES.items():
            assert "name" in tech
            assert "tactics" in tech
            assert "description" in tech
            assert "mitigations" in tech
