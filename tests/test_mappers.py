"""Tests for CWE and CVSS mappers."""

import pytest

from cve_intel.mappers.cwe_to_attack import map_cwe_to_attack
from cve_intel.mappers.cvss_to_attack import map_cvss_to_attack
from cve_intel.models.cve import CVSSData, CVSSSeverity


def test_cwe_787_maps_to_t1203_and_t1068(mock_attack_data):
    mapping = map_cwe_to_attack("CVE-2024-21762", ["CWE-787"], mock_attack_data)
    ids = mapping.technique_ids
    assert "T1203" in ids
    assert "T1068" in ids


def test_unknown_cwe_produces_empty_mapping(mock_attack_data):
    mapping = map_cwe_to_attack("CVE-2024-0001", ["CWE-9999"], mock_attack_data)
    assert mapping.techniques == []


def test_cwe_mapping_method_is_static(mock_attack_data):
    mapping = map_cwe_to_attack("CVE-2024-0001", ["CWE-787"], mock_attack_data)
    assert mapping.mapping_method == "cwe_static"


def test_cvss_network_low_hints_t1190(mock_attack_data):
    cvss = CVSSData(
        version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=9.8,
        base_severity=CVSSSeverity.CRITICAL,
        attack_vector="NETWORK",
        attack_complexity="LOW",
    )
    hints = map_cvss_to_attack("CVE-2024-0001", cvss, mock_attack_data, existing_ids=set())
    ids = [t.technique_id for t in hints]
    assert "T1190" in ids


def test_cvss_hint_skips_existing_ids(mock_attack_data):
    cvss = CVSSData(
        version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=9.8,
        base_severity=CVSSSeverity.CRITICAL,
        attack_vector="NETWORK",
        attack_complexity="LOW",
    )
    hints = map_cvss_to_attack("CVE-2024-0001", cvss, mock_attack_data, existing_ids={"T1190"})
    ids = [t.technique_id for t in hints]
    assert "T1190" not in ids


def test_cvss_hint_confidence_is_low(mock_attack_data):
    cvss = CVSSData(
        version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=9.8,
        base_severity=CVSSSeverity.CRITICAL,
        attack_vector="NETWORK",
        attack_complexity="LOW",
    )
    hints = map_cvss_to_attack("CVE-2024-0001", cvss, mock_attack_data, existing_ids=set())
    for t in hints:
        assert t.confidence <= 0.5
