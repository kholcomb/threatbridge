"""Tests for AttackData STIX loading, data source indexing, and technique lookup."""

import json
import pytest
from pathlib import Path


# ---------------------------------------------------------------------------
# Minimal STIX bundle builder
# ---------------------------------------------------------------------------

def _make_bundle(*objects) -> dict:
    return {"type": "bundle", "objects": list(objects)}


def _tactic(stix_id: str, shortname: str, name: str, tactic_id: str) -> dict:
    return {
        "type": "x-mitre-tactic",
        "id": stix_id,
        "name": name,
        "x_mitre_shortname": shortname,
        "external_references": [{"source_name": "mitre-attack", "external_id": tactic_id}],
    }


def _technique(stix_id: str, tech_id: str, name: str, phases: list[str],
               data_sources_flat: list[str] | None = None) -> dict:
    obj = {
        "type": "attack-pattern",
        "id": stix_id,
        "name": name,
        "description": f"Description of {name}",
        "x_mitre_platforms": ["Linux", "Windows"],
        "x_mitre_data_sources": data_sources_flat or [],
        "x_mitre_detection": "",
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": p} for p in phases
        ],
        "external_references": [{"source_name": "mitre-attack", "external_id": tech_id}],
    }
    return obj


def _data_source(stix_id: str, name: str) -> dict:
    return {"type": "x-mitre-data-source", "id": stix_id, "name": name}


def _data_component(stix_id: str, name: str, source_ref: str) -> dict:
    return {
        "type": "x-mitre-data-component",
        "id": stix_id,
        "name": name,
        "x_mitre_data_source_ref": source_ref,
    }


def _detects(stix_id: str, component_ref: str, technique_ref: str,
             revoked: bool = False) -> dict:
    obj = {
        "type": "relationship",
        "id": stix_id,
        "relationship_type": "detects",
        "source_ref": component_ref,
        "target_ref": technique_ref,
    }
    if revoked:
        obj["revoked"] = True
    return obj


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TACTIC_STIX_ID   = "x-mitre-tactic--ta0001"
TECH_STIX_ID     = "attack-pattern--t1190"
TECH_STIX_ID_2   = "attack-pattern--t1059"
DS_STIX_ID       = "x-mitre-data-source--net"
COMP_STIX_ID     = "x-mitre-data-component--net-content"
COMP_STIX_ID_2   = "x-mitre-data-component--net-flow"
REL_STIX_ID      = "relationship--rel1"
REL_STIX_ID_2    = "relationship--rel2"


@pytest.fixture
def tmp_bundle_path(tmp_path):
    """Write a bundle to disk and return its path."""
    def _write(bundle: dict) -> Path:
        p = tmp_path / "enterprise-attack.json"
        p.write_text(json.dumps(bundle))
        return p
    return _write


# ---------------------------------------------------------------------------
# _build_data_source_index
# ---------------------------------------------------------------------------

class TestBuildDataSourceIndex:
    def _make_attack_data(self, bundle: dict, tmp_bundle_path):
        from cve_intel.fetchers.attack_data import AttackData
        path = tmp_bundle_path(bundle)
        return AttackData(path)

    def test_relationship_sources_populate_technique(self, tmp_bundle_path):
        """A technique with no flat list gets data sources from detects relationships."""
        bundle = _make_bundle(
            _tactic(TACTIC_STIX_ID, "initial-access", "Initial Access", "TA0001"),
            _technique(TECH_STIX_ID, "T1190", "Exploit Public-Facing Application",
                       ["initial-access"], data_sources_flat=[]),
            _data_source(DS_STIX_ID, "Network Traffic"),
            _data_component(COMP_STIX_ID, "Network Traffic Content", DS_STIX_ID),
            _detects(REL_STIX_ID, COMP_STIX_ID, TECH_STIX_ID),
        )
        ad = self._make_attack_data(bundle, tmp_bundle_path)
        tech = ad.get_technique("T1190")
        assert tech is not None
        assert "Network Traffic: Network Traffic Content" in tech.data_sources

    def test_old_flat_list_preserved_and_merged(self, tmp_bundle_path):
        """Old-format flat list entries are kept; new relationship entries are appended."""
        bundle = _make_bundle(
            _tactic(TACTIC_STIX_ID, "initial-access", "Initial Access", "TA0001"),
            _technique(TECH_STIX_ID, "T1190", "Exploit Public-Facing Application",
                       ["initial-access"],
                       data_sources_flat=["Application Log: Application Log Content"]),
            _data_source(DS_STIX_ID, "Network Traffic"),
            _data_component(COMP_STIX_ID, "Network Traffic Content", DS_STIX_ID),
            _detects(REL_STIX_ID, COMP_STIX_ID, TECH_STIX_ID),
        )
        ad = self._make_attack_data(bundle, tmp_bundle_path)
        tech = ad.get_technique("T1190")
        assert "Application Log: Application Log Content" in tech.data_sources
        assert "Network Traffic: Network Traffic Content" in tech.data_sources

    def test_revoked_relationship_is_skipped(self, tmp_bundle_path):
        """A revoked detects relationship must not contribute data sources."""
        bundle = _make_bundle(
            _tactic(TACTIC_STIX_ID, "initial-access", "Initial Access", "TA0001"),
            _technique(TECH_STIX_ID, "T1190", "Exploit Public-Facing Application",
                       ["initial-access"], data_sources_flat=[]),
            _data_source(DS_STIX_ID, "Network Traffic"),
            _data_component(COMP_STIX_ID, "Network Traffic Content", DS_STIX_ID),
            _detects(REL_STIX_ID, COMP_STIX_ID, TECH_STIX_ID, revoked=True),
        )
        ad = self._make_attack_data(bundle, tmp_bundle_path)
        tech = ad.get_technique("T1190")
        assert tech.data_sources == []

    def test_orphaned_component_uses_component_name_only(self, tmp_bundle_path):
        """A data component with no matching parent source uses just the component name."""
        bundle = _make_bundle(
            _tactic(TACTIC_STIX_ID, "initial-access", "Initial Access", "TA0001"),
            _technique(TECH_STIX_ID, "T1190", "Exploit Public-Facing Application",
                       ["initial-access"], data_sources_flat=[]),
            # No x-mitre-data-source object — orphaned component
            _data_component(COMP_STIX_ID, "Network Traffic Content", "x-mitre-data-source--missing"),
            _detects(REL_STIX_ID, COMP_STIX_ID, TECH_STIX_ID),
        )
        ad = self._make_attack_data(bundle, tmp_bundle_path)
        tech = ad.get_technique("T1190")
        assert "Network Traffic Content" in tech.data_sources

    def test_multiple_components_all_populated(self, tmp_bundle_path):
        """Multiple detects relationships populate all component labels."""
        bundle = _make_bundle(
            _tactic(TACTIC_STIX_ID, "initial-access", "Initial Access", "TA0001"),
            _technique(TECH_STIX_ID, "T1190", "Exploit Public-Facing Application",
                       ["initial-access"], data_sources_flat=[]),
            _data_source(DS_STIX_ID, "Network Traffic"),
            _data_component(COMP_STIX_ID,   "Network Traffic Content", DS_STIX_ID),
            _data_component(COMP_STIX_ID_2, "Network Traffic Flow",    DS_STIX_ID),
            _detects(REL_STIX_ID,   COMP_STIX_ID,   TECH_STIX_ID),
            _detects(REL_STIX_ID_2, COMP_STIX_ID_2, TECH_STIX_ID),
        )
        ad = self._make_attack_data(bundle, tmp_bundle_path)
        tech = ad.get_technique("T1190")
        assert "Network Traffic: Network Traffic Content" in tech.data_sources
        assert "Network Traffic: Network Traffic Flow" in tech.data_sources

    def test_no_cross_contamination_between_techniques(self, tmp_bundle_path):
        """Data sources for one technique must not appear on another."""
        bundle = _make_bundle(
            _tactic(TACTIC_STIX_ID, "initial-access", "Initial Access", "TA0001"),
            _technique(TECH_STIX_ID,   "T1190", "Exploit Public-Facing Application", ["initial-access"]),
            _technique(TECH_STIX_ID_2, "T1059", "Command and Scripting Interpreter",  ["initial-access"]),
            _data_source(DS_STIX_ID, "Network Traffic"),
            _data_component(COMP_STIX_ID, "Network Traffic Content", DS_STIX_ID),
            _detects(REL_STIX_ID, COMP_STIX_ID, TECH_STIX_ID),  # only T1190
        )
        ad = self._make_attack_data(bundle, tmp_bundle_path)
        t1190 = ad.get_technique("T1190")
        t1059 = ad.get_technique("T1059")
        assert "Network Traffic: Network Traffic Content" in t1190.data_sources
        assert "Network Traffic: Network Traffic Content" not in t1059.data_sources

    def test_deduplication_between_flat_and_graph(self, tmp_bundle_path):
        """A source present in both flat list and graph appears only once."""
        bundle = _make_bundle(
            _tactic(TACTIC_STIX_ID, "initial-access", "Initial Access", "TA0001"),
            _technique(TECH_STIX_ID, "T1190", "Exploit Public-Facing Application",
                       ["initial-access"],
                       data_sources_flat=["Network Traffic: Network Traffic Content"]),
            _data_source(DS_STIX_ID, "Network Traffic"),
            _data_component(COMP_STIX_ID, "Network Traffic Content", DS_STIX_ID),
            _detects(REL_STIX_ID, COMP_STIX_ID, TECH_STIX_ID),
        )
        ad = self._make_attack_data(bundle, tmp_bundle_path)
        tech = ad.get_technique("T1190")
        assert tech.data_sources.count("Network Traffic: Network Traffic Content") == 1
